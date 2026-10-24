import secrets

import jwt
import pytest
from sqlalchemy import null, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from include.config.settings import global_config
from include.database.models.identity import User
from include.database.session import Base
from include.domains.identity.auth.flows import (
    create_authentication_context,
    validate_authentication_context,
)
from include.domains.identity.auth.types import (
    AuthPurpose,
    InvalidAuthenticationAttempt,
)
from include.domains.identity.commands import users
from include.domains.identity.tokens import Token, TokenPurpose

pytestmark = pytest.mark.component


@pytest.fixture
def secret_sessions(sqlite_engine_factory):
    engine = sqlite_engine_factory()
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


@pytest.mark.parametrize("value", [None, ""])
@pytest.mark.parametrize("operation", ["insert", "update"])
def test_database_rejects_missing_user_secret(secret_sessions, value, operation):
    with secret_sessions.begin() as session:
        user = User(username="alice")
        session.add(user)
        session.flush()
        user_id = user.id

    missing = null() if value is None else value
    statement = (
        User.__table__.insert().values(username="invalid", secret_key=missing)
        if operation == "insert"
        else update(User).where(User.id == user_id).values(secret_key=missing)
    )
    with pytest.raises(IntegrityError), secret_sessions.begin() as session:
        session.execute(statement)

    with secret_sessions() as session:
        assert len(bytes.fromhex(session.get(User, user_id).secret_key)) == 32


@pytest.mark.parametrize("password", [None, "Password123!"])
def test_create_user_persists_independent_secret(
    secret_sessions, monkeypatch, password
):
    monkeypatch.setattr(users, "Session", secret_sessions)
    first_id = users.create_user(username="first", password=password)
    second_id = users.create_user(username="second", password=password)
    with secret_sessions() as session:
        keys = [
            session.get(User, user_id).secret_key for user_id in (first_id, second_id)
        ]
        assert len(set(keys)) == 2
        assert all(len(bytes.fromhex(key)) == 32 for key in keys)


@pytest.mark.parametrize(
    "purpose",
    [
        TokenPurpose.AUTH,
        TokenPurpose.POST_AUTH,
        TokenPurpose.GENERAL,
        TokenPurpose.GENERAL_WITH_ESCALATION,
    ],
)
def test_global_rotation_preserves_user_tokens_and_authentication(
    secret_sessions, monkeypatch, purpose
):
    with secret_sessions() as session:
        first, second = User(username="first"), User(username="second")
        session.add_all([first, second])
        session.flush()
        context = create_authentication_context(
            session, first, AuthPurpose.LOGIN, "password"
        )
        token = Token.new(
            first.id,
            300,
            first.secret_key,
            purpose,
            auth_context=context
            if purpose in (TokenPurpose.AUTH, TokenPurpose.POST_AUTH)
            else None,
        )
        other_token = second.renew_token()
        monkeypatch.setitem(
            global_config["server"], "secret_key", secrets.token_hex(32)
        )

        assert first.is_token_valid(token, purpose)
        validate_authentication_context(session, first, context, (AuthPurpose.LOGIN,))
        assert first.is_token_valid(first.create_token_after_authentication())
        assert first.is_token_valid(first.renew_token())

        first.secret_key = secrets.token_hex(32)
        session.flush()
        assert not first.is_token_valid(token, purpose)
        with pytest.raises(jwt.InvalidSignatureError):
            Token.from_raw(token.raw, first.secret_key)
        with pytest.raises(InvalidAuthenticationAttempt):
            validate_authentication_context(
                session, first, context, (AuthPurpose.LOGIN,)
            )
        assert second.is_token_valid(other_token)
