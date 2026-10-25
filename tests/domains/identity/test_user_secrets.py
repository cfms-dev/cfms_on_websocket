import secrets
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import jwt
import pytest
from sqlalchemy import null, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from include.config.settings import global_config
from include.database.models.auth import UserPasswordCredential
from include.database.models.identity import User, UserPermission, UserStatus
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
from include.domains.identity.commands.credentials import set_password
from include.domains.identity.handlers import users as user_handlers
from include.domains.identity.tokens import Token, TokenPurpose

pytestmark = pytest.mark.component


@pytest.fixture
def secret_sessions(sqlite_engine_factory, tmp_path):
    engine = sqlite_engine_factory(tmp_path / "secrets.db")
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


@pytest.fixture
def password_account(secret_sessions):
    with secret_sessions.begin() as session:
        user = User(
            username="alice",
            rights=[
                UserPermission(
                    permission="configure_auth_methods", granted=True, start_time=0
                )
            ],
        )
        session.add(user)
        session.flush()
        set_password(session, user, "OriginalPassword123!")
        user_id = user.id
        token = Token.new(user_id, 300, user.secret_key, TokenPurpose.ESCALATION)
        assert user.is_token_valid(token, TokenPurpose.ESCALATION)
    return user_id, token


@pytest.mark.parametrize("change", ["rotate_key", "disable_account"])
@pytest.mark.parametrize(
    ("new_password", "expected_code"),
    [("UpdatedPassword456!", 401), ("OriginalPassword123!", 400)],
)
def test_password_change_rejects_changed_account_after_request_entry(
    secret_sessions, password_account, monkeypatch, change, new_password, expected_code
):
    user_id, token = password_account

    with secret_sessions.begin() as session:
        user = session.get(User, user_id)
        if change == "rotate_key":
            user.secret_key = secrets.token_hex(32)
        else:
            user.status = UserStatus.DISABLED
        assert not user.is_token_valid(token, TokenPurpose.ESCALATION)
        expected_secret = user.secret_key
        expected_status = user.status

    monkeypatch.setattr(user_handlers, "Session", secret_sessions)
    responses = []
    handler = SimpleNamespace(
        user_id=user_id,
        token=token,
        conclude_request=lambda **response: responses.append(response),
    )
    password_handler = user_handlers.RequestSetPasswdHandler()
    result = password_handler.handle(
        handler,
        password_handler.request_model.model_validate({"new_passwd": new_password}),
    )

    assert responses[0]["code"] == expected_code
    assert responses[0]["data"] == {}
    assert result.code == expected_code
    assert result.user_id == user_id
    assert result.target == str(user_id)
    with secret_sessions() as session:
        credential = session.get(UserPasswordCredential, user_id)
        assert credential.verify("OriginalPassword123!")
        assert not credential.verify("UpdatedPassword456!")
        user = session.get(User, user_id)
        assert user.secret_key == expected_secret
        assert user.status == expected_status


@pytest.mark.parametrize("explicit_target", [False, True])
def test_concurrent_self_password_changes_have_one_winner(
    secret_sessions, password_account, monkeypatch, explicit_target
):
    user_id, token = password_account
    monkeypatch.setattr(user_handlers, "Session", secret_sessions)
    ready = Barrier(2)

    def change_password(password):
        responses = []
        handler = SimpleNamespace(
            user_id=user_id,
            token=token,
            conclude_request=lambda **response: responses.append(response),
        )
        password_handler = user_handlers.RequestSetPasswdHandler()
        data = {"new_passwd": password}
        if explicit_target:
            data["user_id"] = str(user_id)
        request = password_handler.request_model.model_validate(data)
        ready.wait(timeout=5)
        result = password_handler.handle(handler, request)
        with secret_sessions() as session:
            signing_key = session.get(User, user_id).secret_key
        return password, result, responses[0], signing_key

    with ThreadPoolExecutor(max_workers=2) as workers:
        futures = [
            workers.submit(change_password, password)
            for password in ("FirstPassword456!", "SecondPassword789!")
        ]
        results = [future.result(timeout=10) for future in futures]

    assert sorted(result.code for _, result, _, _ in results) == [200, 401]
    for _, result, response, _ in results:
        assert response["code"] == result.code
        assert response["data"] == {}
        assert result.user_id == user_id
        assert result.target == str(user_id)
    winner = next(item for item in results if item[1].code == 200)
    loser = next(item for item in results if item[1].code == 401)
    with secret_sessions() as session:
        credential = session.get(UserPasswordCredential, user_id)
        assert credential.verify(winner[0])
        assert not credential.verify(loser[0])
        user = session.get(User, user_id)
        assert user.secret_key == winner[3] == loser[3]
        assert user.secret_key != token._secret
        assert not user.is_token_valid(token, TokenPurpose.ESCALATION)


@pytest.mark.parametrize("refresh", [False, True])
def test_password_update_rejects_version_committed_by_another_session(
    secret_sessions, password_account, refresh
):
    user_id, token = password_account
    with secret_sessions() as first, secret_sessions() as second:
        winner = first.get(User, user_id)
        loser = second.get(User, user_id)
        set_password(
            first, winner, "FirstPassword456!", expected_signing_key=token._secret
        )
        first.commit()
        winning_secret = winner.secret_key
        if refresh:
            second.refresh(loser)
        with pytest.raises(InvalidAuthenticationAttempt):
            set_password(
                second, loser, "SecondPassword789!", expected_signing_key=token._secret
            )
        second.rollback()

    with secret_sessions() as session:
        credential = session.get(UserPasswordCredential, user_id)
        assert credential.verify("FirstPassword456!")
        assert not credential.verify("SecondPassword789!")
        assert session.get(User, user_id).secret_key == winning_secret


def test_conditional_password_update_rolls_back_without_consuming_version(
    secret_sessions, password_account
):
    user_id, token = password_account
    with secret_sessions() as session:
        original_hash = session.get(UserPasswordCredential, user_id).pass_hash

    with secret_sessions() as session:
        user = session.get(User, user_id)
        set_password(
            session, user, "UpdatedPassword456!", expected_signing_key=token._secret
        )
        session.flush()
        session.add(User(username="alice"))
        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()

    with secret_sessions.begin() as session:
        credential = session.get(UserPasswordCredential, user_id)
        user = session.get(User, user_id)
        assert credential.pass_hash == original_hash
        assert user.secret_key == token._secret
        assert user.is_token_valid(token, TokenPurpose.ESCALATION)
        set_password(
            session, user, "RetryPassword789!", expected_signing_key=token._secret
        )

    with secret_sessions() as session:
        assert session.get(UserPasswordCredential, user_id).verify("RetryPassword789!")
        assert session.get(User, user_id).secret_key != token._secret


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
