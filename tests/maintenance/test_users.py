import jwt
import pytest
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from include.database.models.identity import User, UserStatus
from include.database.session import Base
from include.domains.identity.auth.flows import create_authentication_context
from include.domains.identity.auth.types import AuthPurpose
from include.domains.identity.tokens import Token, TokenPurpose
from maintenance.operations import users

pytestmark = pytest.mark.component


@pytest.fixture
def user_sessions(monkeypatch, sqlite_engine_factory, tmp_path):
    engine = sqlite_engine_factory(tmp_path / "users.db")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(users, "enter_server_root", lambda: None)
    monkeypatch.setattr(users, "load_database_models", lambda: None)
    monkeypatch.setattr(users, "Session", sessions)
    return sessions


def test_rotate_secrets_invalidates_every_token_purpose_for_all_users(user_sessions):
    previous = {}
    with user_sessions.begin() as session:
        for username, secret, status in (
            ("independent", "old-independent-secret" * 2, UserStatus.ACTIVE),
            ("passwordless", None, UserStatus.ACTIVE),
            ("inactive", "old-inactive-secret" * 2, UserStatus.DISABLED),
        ):
            user = User(username=username, status=status, secret_key=secret)
            session.add(user)
            session.flush()
            context = create_authentication_context(
                session, user, AuthPurpose.LOGIN, "password"
            )
            signing_key = user.secret_key
            tokens = []
            for purpose in (
                TokenPurpose.AUTH,
                TokenPurpose.POST_AUTH,
                TokenPurpose.GENERAL,
                TokenPurpose.GENERAL | TokenPurpose.ESCALATION,
            ):
                token = Token.new(
                    user.id,
                    300,
                    signing_key,
                    purpose,
                    auth_context=context
                    if purpose in (TokenPurpose.AUTH, TokenPurpose.POST_AUTH)
                    else None,
                )
                assert Token.from_raw(token.raw, signing_key).purpose == purpose
                tokens.append(token.raw)
            previous[user.id] = (signing_key, status, tokens)

    assert users.rotate_secrets() == len(previous)

    with user_sessions() as session:
        rotated = session.scalars(select(User)).all()
        assert {user.id for user in rotated} == set(previous)
        assert len({user.secret_key for user in rotated}) == len(previous)
        for user in rotated:
            old_secret, status, tokens = previous[user.id]
            assert user.secret_key != old_secret
            assert len(bytes.fromhex(user.secret_key)) == 32
            assert user.status == status
            for raw in tokens:
                with pytest.raises(jwt.InvalidSignatureError):
                    Token.from_raw(raw, user.secret_key)
            new_token = Token.new(user.id, 300, user.secret_key)
            assert Token.from_raw(new_token.raw, user.secret_key).sub == user.id


def test_rotate_secrets_rolls_back_all_users_on_database_failure(user_sessions):
    with user_sessions.begin() as session:
        session.add_all(
            User(username=name, secret_key=f"old-{name}") for name in ("alice", "bob")
        )
        session.connection().exec_driver_sql(
            "CREATE TRIGGER reject_secret_rotation BEFORE UPDATE OF secret_key ON users "
            "WHEN NEW.username = 'bob' "
            "BEGIN SELECT RAISE(ABORT, 'rotation blocked'); END"
        )

    with pytest.raises(IntegrityError):
        users.rotate_secrets()

    with user_sessions() as session:
        assert dict(session.execute(select(User.username, User.secret_key)).all()) == {
            "alice": "old-alice",
            "bob": "old-bob",
        }


def test_rotate_secrets_with_no_users(user_sessions):
    assert users.rotate_secrets() == 0
