import time
import uuid
from types import SimpleNamespace

import jwt
import pytest
from sqlalchemy.orm import sessionmaker

import include.database.models  # noqa: F401
from include.database.models.identity import User
from include.database.session import Base
from include.domains.identity.tokens import Token

pytestmark = pytest.mark.component


@pytest.fixture
def identity_session(sqlite_engine_factory):
    engine = sqlite_engine_factory()
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine)() as session:
        yield session


def test_token_round_trip_serializes_uuid_and_hides_secret():
    user_id = uuid.uuid4()
    token = Token.new(user_id, 300, "s" * 64)
    payload = jwt.decode(token.raw, "s" * 64, algorithms=["HS256"])

    assert payload["sub"] == str(user_id)
    assert "username" not in payload
    assert "_secret" not in payload
    assert "s" * 64 not in repr(token)
    restored = Token.from_raw(token.raw, "s" * 64)
    assert restored.sub == user_id
    assert restored.raw == token.raw


def test_same_username_replacement_rejects_old_token_with_same_secret(identity_session):
    session = identity_session
    old = User(username="reused", secret_key="s" * 64)
    session.add(old)
    session.commit()
    old_id = old.id
    token = old.renew_token()
    assert old.is_token_valid(token)
    session.delete(old)
    session.commit()
    replacement = User(username="reused", secret_key="s" * 64)
    session.add(replacement)
    session.commit()

    assert replacement.id != old_id
    assert not replacement.is_token_valid(token)
    with pytest.raises(jwt.InvalidTokenError):
        replacement.renew_token(token)
    assert replacement.is_token_valid(replacement.renew_token())


def test_rename_preserves_token_identity(identity_session):
    user = User(username="before", secret_key="s" * 64)
    identity_session.add(user)
    identity_session.commit()
    token = user.renew_token()
    user.username = "after"
    identity_session.commit()

    assert user.is_token_valid(token)


def test_management_id_survives_database_username_change(identity_session, monkeypatch):
    from include.database.models.identity import UserPermission
    from include.domains.identity.handlers import users

    actor = User(
        username="admin",
        rights=[
            UserPermission(
                permission="super_rename_user",
                granted=True,
                start_time=0,
            )
        ],
    )
    target = User(username="before")
    identity_session.add_all([actor, target])
    identity_session.commit()
    user_id = target.id
    target.username = "after"
    identity_session.commit()
    monkeypatch.setattr(users, "Session", sessionmaker(bind=identity_session.bind))
    responses = []
    handler = SimpleNamespace(
        user_id=actor.id,
        data={"user_id": str(user_id), "nickname": "Changed"},
        conclude_request=lambda **response: responses.append(response),
    )

    result = users.RequestRenameUserHandler().handle(
        handler,
        users.RequestRenameUserHandler.request_model.model_validate(handler.data),
    )

    assert responses[0]["code"] == 200
    identity_session.refresh(target)
    assert target.id == user_id
    assert target.username == "after"
    assert target.nickname == "Changed"
    assert result.target == str(user_id)
    assert result.user_id == actor.id
    assert result.data == {"target_username": "after"}


@pytest.mark.parametrize(
    "claims", [{"username": "alice"}, {"sub": "alice"}, {"sub": None}]
)
def test_legacy_or_invalid_subject_is_rejected(identity_session, claims):
    user = User(username="alice", secret_key="s" * 64)
    identity_session.add(user)
    identity_session.commit()
    raw = jwt.encode(
        {
            **claims,
            "purpose": 2,
            "exp": time.time() + 300,
            "iat": time.time(),
            "nbf": time.time(),
        },
        "s" * 64,
        algorithm="HS256",
    )

    assert not user.is_token_valid(raw)
    with pytest.raises(jwt.InvalidTokenError):
        Token.from_raw(raw, "s" * 64)


def test_refresh_audits_username_target_and_uuid_actor(identity_session, monkeypatch):
    from include.domains.identity.handlers import auth

    user = User(username="alice")
    identity_session.add(user)
    identity_session.commit()
    factory = sessionmaker(bind=identity_session.bind)
    monkeypatch.setattr(auth, "Session", factory)
    responses = []
    handler = SimpleNamespace(
        user_id=user.id,
        token=user.renew_token(),
        conclude_request=lambda **response: responses.append(response),
    )

    result = auth.RequestRefreshTokenHandler().handle(
        handler, auth.RequestRefreshTokenHandler.request_model()
    )

    assert result.target == "alice"
    assert result.user_id == user.id
    assert responses[0]["code"] == 200
    assert Token.from_raw(responses[0]["data"]["token"], user.secret_key).sub == user.id


def test_http_rejects_deleted_account_token_after_username_reuse(
    identity_session, monkeypatch
):
    from fastapi import HTTPException

    from include.extensions.http_api import security

    session = identity_session
    old = User(username="reused", secret_key="s" * 64)
    session.add(old)
    session.commit()
    old_token = old.renew_token()
    session.delete(old)
    session.commit()
    replacement = User(username="reused", secret_key="s" * 64)
    session.add(replacement)
    session.commit()
    monkeypatch.setattr(security, "Session", sessionmaker(bind=session.bind))

    with pytest.raises(HTTPException) as rejected:
        security._principal_from_token(old_token.raw)
    assert rejected.value.status_code == 401
    assert (
        security._principal_from_token(replacement.renew_token().raw).user_id
        == replacement.id
    )


def test_public_key_challenge_cannot_transfer_to_replacement_account(
    identity_session,
):
    from include.domains.identity.auth.providers import publickey

    session = identity_session
    user = User(username="reused")
    session.add(user)
    session.commit()
    provider = publickey.PublicKeyAuthProvider()
    context = {
        "attempt_id": "attempt",
        "stage": "login",
        "stream_id": 1,
        "interaction_id": "interaction",
        "fingerprint": (b"f" * 32).hex(),
    }
    provider.create_challenge(session, user, context=context)
    session.delete(user)
    session.commit()
    replacement = User(username="reused")
    session.add(replacement)
    session.commit()

    result = provider.verify(
        session,
        replacement,
        {
            "fingerprint": (b"f" * 32).hex(),
            "signature": "AA==",
        },
        context,
    )

    assert not result.success
    assert result.error_code == 401
    assert "publickey_challenge" not in context


@pytest.mark.parametrize("subject", [None, "alice", [], {}, 42])
def test_router_rejects_invalid_subject_as_authentication_error(
    identity_session, monkeypatch, subject
):
    import orjson

    from include.transport import router

    request = orjson.dumps(
        {
            "action": "refresh_token",
            "data": {},
            "token": jwt.encode({"sub": subject}, "s" * 64, algorithm="HS256"),
        }
    )
    responses = []
    stream = SimpleNamespace(
        connection=SimpleNamespace(
            _ws=SimpleNamespace(
                remote_address=("192.0.2.1", 1), request=SimpleNamespace(headers={})
            )
        ),
        recv=lambda: SimpleNamespace(data=request),
        send=lambda data, **kwargs: responses.append(orjson.loads(data)),
    )
    monkeypatch.setattr(
        router.LoginGuard,
        "evaluate_subnet_access",
        lambda _ip: SimpleNamespace(allowed=True),
    )
    monkeypatch.setattr(router, "Session", sessionmaker(bind=identity_session.bind))

    router.handle_request(stream)

    assert len(responses) == 1
    assert responses[0]["code"] == 401
    assert responses[0]["data"] == {}


@pytest.mark.parametrize("envelope_username", [None, "bob"])
def test_router_derives_identity_only_from_token(
    identity_session, monkeypatch, envelope_username
):
    import orjson

    from include.domains.identity.handlers import auth
    from include.domains.security.guards import replay
    from include.providers.caching.memory import MemoryCachingProvider
    from include.transport import router

    user = User(username="alice", secret_key="s" * 64)
    identity_session.add(user)
    identity_session.commit()
    request = {
        "action": "refresh_token",
        "data": {},
        "token": user.renew_token().raw,
        "nonce": uuid.uuid4().hex,
        "timestamp": time.time(),
    }
    if envelope_username is not None:
        request["username"] = envelope_username
    responses = []
    audit = []
    stream = SimpleNamespace(
        connection=SimpleNamespace(
            _ws=SimpleNamespace(
                remote_address=("192.0.2.1", 1), request=SimpleNamespace(headers={})
            )
        ),
        recv=lambda: SimpleNamespace(data=orjson.dumps(request)),
        send=lambda data, **kwargs: responses.append(orjson.loads(data)),
    )
    sessions = sessionmaker(bind=identity_session.bind)
    monkeypatch.setattr(router, "Session", sessions)
    monkeypatch.setattr(auth, "Session", sessions)
    cache = MemoryCachingProvider()
    monkeypatch.setattr(
        replay, "ProviderManager", lambda: SimpleNamespace(caching=cache)
    )
    monkeypatch.setattr(
        router.LoginGuard,
        "evaluate_subnet_access",
        lambda _ip: SimpleNamespace(allowed=True),
    )
    monkeypatch.setattr(
        router,
        "check_request_rate",
        lambda *args, **kwargs: SimpleNamespace(allowed=True),
    )
    monkeypatch.setattr(
        router.lockdown_state_manager,
        "get_state",
        lambda: SimpleNamespace(enabled=False),
    )
    monkeypatch.setattr(
        router,
        "pm",
        SimpleNamespace(
            hook=SimpleNamespace(
                ext_before_request=lambda **kwargs: None,
                ext_post_request=lambda **kwargs: None,
            )
        ),
    )
    monkeypatch.setattr(
        router, "log_audit", lambda *args, **kwargs: audit.append(kwargs)
    )

    router.handle_request(stream)

    assert responses[0]["code"] == 200
    assert Token.from_raw(responses[0]["data"]["token"], user.secret_key).sub == user.id
    assert audit[0]["user_id"] == user.id
    assert audit[0]["target"] == "alice"
