import base64
import hashlib
import threading
import time
import uuid
from dataclasses import FrozenInstanceError
from types import SimpleNamespace

import jwt
import orjson
import pyotp
import pytest
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from pydantic import ValidationError
from sqlalchemy import delete, select
from sqlalchemy.orm import sessionmaker

from include.config.constants import ESCALATION_TOKEN_EXPIRY_SECONDS
from include.config.validation import RequestRateControlPolicy
from include.database.models.auth import (
    UserAuthPolicy,
    UserAuthPublicKey,
    UserPasswordCredential,
    UserTotpCredential,
)
from include.database.models.identity import User, UserStatus
from include.database.models.security import (
    AccountThrottle,
    LoginThrottle,
    TrafficThrottle,
)
from include.database.session import Base
from include.domains.identity.auth import auth_registry, flows
from include.domains.identity.auth.base import AuthVerificationResult
from include.domains.identity.auth.flows import (
    create_authentication_context,
    get_login_progress,
)
from include.domains.identity.auth.policies import evaluate_auth_policy
from include.domains.identity.auth.providers import password as password_provider
from include.domains.identity.auth.providers import publickey
from include.domains.identity.auth.providers import totp as totp_provider
from include.domains.identity.auth.types import (
    AuthenticationContext,
    AuthEvidence,
    AuthPurpose,
    RegisteredCredential,
    auth_chains_adapter,
)
from include.domains.identity.commands.auth_policies import (
    AuthPolicyConflict,
    replace_auth_policy,
)
from include.domains.identity.commands.credentials import (
    enable_login_totp,
    remove_totp,
    set_password,
    setup_totp,
)
from include.domains.identity.handlers import auth
from include.domains.identity.tokens import Token, TokenPurpose
from include.domains.security.guards import login as login_guard
from include.domains.security.guards import request_rate_control
from include.providers.base import RateLimitDecision
from include.transport.multiplexing import Frame, FrameType

pytestmark = pytest.mark.component


@pytest.fixture
def auth_sessions(sqlite_engine_factory, tmp_path):
    engine = sqlite_engine_factory(tmp_path / "authentication.db", timeout_seconds=10)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)


@pytest.mark.parametrize(
    ("events", "expected"),
    [
        (["A", "B"], True),
        (["B", "A"], False),
        (["A", "A"], False),
        (["A"], False),
        ([], False),
    ],
)
def test_ordered_distinct_public_keys(events, expected):
    user_id = uuid.uuid4()
    credentials = [
        RegisteredCredential(
            method="publickey", credential_id=k, active=True, key_identity=k
        )
        for k in ("A", "B")
    ]
    chains = auth_chains_adapter.validate_python(
        [
            [
                {"method": "publickey", "credential_ids": ["A"]},
                {"method": "publickey", "credential_ids": ["B"]},
            ]
        ]
    )
    evidence = [
        AuthEvidence(
            user_id=user_id, attempt_id="attempt", method="publickey", credential_id=k
        )
        for k in events
    ]
    assert (
        evaluate_auth_policy(
            AuthPurpose.LOGIN,
            chains,
            credentials,
            evidence,
            user_id=user_id,
            attempt_id="attempt",
        ).satisfied
        is expected
    )


def test_key_pool_requires_two_distinct_keys_and_cannot_reuse_an_event():
    user_id = uuid.uuid4()
    credentials = [
        RegisteredCredential(
            method="publickey", credential_id=k, active=True, key_identity=k
        )
        for k in ("A", "B")
    ]
    chains = auth_chains_adapter.validate_python(
        [
            [
                {"method": "publickey", "credential_ids": ["A", "B"]},
                {"method": "publickey", "credential_ids": ["A", "B"]},
            ]
        ]
    )
    a = AuthEvidence(
        user_id=user_id, attempt_id="attempt", method="publickey", credential_id="A"
    )
    b = AuthEvidence(
        user_id=user_id, attempt_id="attempt", method="publickey", credential_id="B"
    )
    for evidence, expected in (
        ([a, b], True),
        ([b, a], True),
        ([a, a], False),
        ([a, a.model_copy(update={"event_id": "another"})], False),
    ):
        assert (
            evaluate_auth_policy(
                AuthPurpose.ESCALATION,
                chains,
                credentials,
                evidence,
                user_id=user_id,
                attempt_id="attempt",
            ).satisfied
            is expected
        )


def test_evidence_is_scoped_and_same_key_material_cannot_count_twice():
    user_id = uuid.uuid4()
    credentials = [
        RegisteredCredential(
            method="publickey", credential_id=k, active=True, key_identity="same-key"
        )
        for k in ("A", "B")
    ]
    chains = auth_chains_adapter.validate_python(
        [
            [
                {"method": "publickey", "credential_ids": ["A"]},
                {"method": "publickey", "credential_ids": ["B"]},
            ]
        ]
    )
    events = [
        AuthEvidence(
            user_id=user_id, attempt_id="attempt", method="publickey", credential_id=k
        )
        for k in ("A", "B")
    ]
    assert not evaluate_auth_policy(
        AuthPurpose.LOGIN,
        chains,
        credentials,
        events,
        user_id=user_id,
        attempt_id="attempt",
    ).satisfied
    for scope in ({"attempt_id": "other"}, {"user_id": uuid.uuid4()}):
        assert not evaluate_auth_policy(
            AuthPurpose.LOGIN,
            [chains[0][:1]],
            credentials,
            [events[0].model_copy(update=scope)],
            user_id=user_id,
            attempt_id="attempt",
        ).satisfied


def test_policy_authorization_and_optimistic_updates(auth_sessions):
    with auth_sessions.begin() as session:
        user, other = User(username="owner"), User(username="other")
        session.add_all([user, other])
        session.flush()
        set_password(session, user, "Password123!")
        session.add_all(
            [
                UserAuthPublicKey(
                    user_id=user.id, public_key_der=b"key", fingerprint=b"A" * 32
                ),
                UserAuthPublicKey(
                    user_id=other.id, public_key_der=b"key", fingerprint=b"B" * 32
                ),
            ]
        )
        session.flush()
        key = session.scalar(
            select(UserAuthPublicKey).where(UserAuthPublicKey.user_id == user.id)
        )
        foreign = session.scalar(
            select(UserAuthPublicKey).where(UserAuthPublicKey.user_id == other.id)
        )
        assert not auth_registry.evaluate_user_policy(
            session, user, AuthPurpose.LOGIN, [], attempt_id="a"
        ).satisfied
        assert not auth_registry.user_requires_mfa(session, user)
        with pytest.raises(ValueError, match="unregistered"):
            replace_auth_policy(
                session,
                user,
                AuthPurpose.LOGIN,
                [[{"method": "publickey", "credential_ids": [foreign.id]}]],
                expected_revision=0,
            )
        chains = [[{"method": "publickey", "credential_ids": [key.id]}]]
        replace_auth_policy(
            session, user, AuthPurpose.LOGIN, chains, expected_revision=0
        )
        with pytest.raises(AuthPolicyConflict):
            replace_auth_policy(
                session, user, AuthPurpose.LOGIN, [], expected_revision=0
            )
        user_id = user.id
    with auth_sessions() as first, auth_sessions() as second:
        user = first.get(User, user_id)
        stale = first.get(UserAuthPolicy, (user_id, "login"))
        replace_auth_policy(
            second,
            second.get(User, user_id),
            AuthPurpose.LOGIN,
            [],
            expected_revision=stale.revision,
        )
        second.commit()
        with pytest.raises(AuthPolicyConflict):
            replace_auth_policy(
                first, user, AuthPurpose.LOGIN, chains, expected_revision=stale.revision
            )


def test_policy_rollback_reenrollment_and_cascade(auth_sessions):
    with auth_sessions.begin() as session:
        user = User(username="owner")
        session.add(user)
        session.flush()
        set_password(session, user, "Password123!")
        session.flush()
        password = session.get(UserPasswordCredential, user.id)
        user_id, credential_id = user.id, password.credential_id
        replace_auth_policy(
            session,
            user,
            AuthPurpose.LOGIN,
            [[{"method": "password", "credential_ids": [credential_id]}]],
            expected_revision=0,
        )
    with auth_sessions() as session:
        replace_auth_policy(
            session,
            session.get(User, user_id),
            AuthPurpose.LOGIN,
            [],
            expected_revision=1,
        )
        session.rollback()
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        assert auth_registry.evaluate_user_policy(
            session, user, AuthPurpose.LOGIN, [], attempt_id="a", method="password"
        ).next_steps[0].credential_ids == [credential_id]
        set_password(session, user, "AnotherPassword123!")
        assert (
            session.get(UserPasswordCredential, user_id).credential_id == credential_id
        )
        session.delete(session.get(UserPasswordCredential, user_id))
        session.flush()
        set_password(session, user, "Replacement123!")
        session.flush()
        replacement = session.get(UserPasswordCredential, user_id)
        assert replacement.credential_id != credential_id
        assert (
            auth_registry.evaluate_user_policy(
                session, user, AuthPurpose.LOGIN, [], attempt_id="a", method="password"
            ).next_steps
            == []
        )
        session.execute(delete(User).where(User.id == user_id))
    with auth_sessions() as session:
        assert session.get(UserPasswordCredential, user_id) is None
        assert session.get(UserAuthPolicy, (user_id, "login")) is None


def test_totp_activation_does_not_imply_mfa_and_custom_removal_fails_closed(
    auth_sessions,
):
    with auth_sessions.begin() as session:
        user = User(username="totp")
        session.add(user)
        session.flush()
        credential, _ = setup_totp(session, user)
        session.flush()
        assert not auth_registry.list_user_credentials(session, user)[0].active
        credential.enable()
        assert not auth_registry.user_requires_mfa(session, user)
        enable_login_totp(session, user, credential)
        assert auth_registry.user_requires_mfa(session, user)
        mfa = session.get(UserAuthPolicy, (user.id, "mfa"))
        replace_auth_policy(
            session,
            user,
            AuthPurpose.MFA,
            [mfa.chains[0] * 2],
            expected_revision=mfa.revision,
        )
        remove_totp(session, user, credential)
        session.flush()
        assert auth_registry.user_requires_mfa(session, user)
        assert not auth_registry.evaluate_user_policy(
            session, user, AuthPurpose.MFA, [], attempt_id="a"
        ).satisfied


@pytest.fixture
def login_context(auth_sessions, monkeypatch):
    from include.domains.identity import sessions
    from include.domains.identity.auth import password_state
    from include.providers.caching.memory import MemoryCachingProvider

    cache_manager = SimpleNamespace(caching=MemoryCachingProvider())
    monkeypatch.setattr(sessions, "ProviderManager", lambda: cache_manager)
    monkeypatch.setattr(password_state, "ProviderManager", lambda: cache_manager)
    monkeypatch.setattr(
        flows, "check_request_rate", lambda *a, **k: SimpleNamespace(allowed=True)
    )
    monkeypatch.setattr(auth, "Session", auth_sessions)
    for module in (password_provider, publickey, totp_provider):
        monkeypatch.setattr(module, "DatabaseSession", auth_sessions)
    monkeypatch.setattr(auth, "get_client_ip", lambda ws: "127.0.0.1")
    monkeypatch.setattr(
        auth.LoginGuard, "evaluate", lambda *a: SimpleNamespace(allowed=True)
    )
    monkeypatch.setattr(auth.LoginGuard, "report_failure", lambda *a, **k: None)
    monkeypatch.setattr(auth.LoginGuard, "report_success", lambda *a, **k: None)
    with auth_sessions.begin() as session:
        user = User(username="login")
        session.add(user)
        session.flush()
        set_password(session, user, "Password123!")
        session.flush()
        password = session.get(UserPasswordCredential, user.id)
        replace_auth_policy(
            session,
            user,
            AuthPurpose.LOGIN,
            [[{"method": "password", "credential_ids": [password.credential_id]}]],
            expected_revision=0,
        )
        credential, codes = setup_totp(session, user)
        enable_login_totp(session, user, credential)
        return user.id, credential.secret, codes, user.secret_key


class Handler:
    def __init__(self, data, token=None):
        self.data = dict(data)
        if token is not None and "method" in data:
            self.data.setdefault("target_purpose", 2)
        self.token = token
        self.user_id = token.sub if token else None
        self.stream = SimpleNamespace(connection=SimpleNamespace(_ws=None), frame_id=1)
        self.response = None

    def conclude_request(self, code, data=None, message=None):
        self.response = {"code": code, "data": data or {}, "message": message}


@pytest.mark.parametrize("method", ["password", "publickey"])
@pytest.mark.parametrize("purpose", list(AuthPurpose))
def test_missing_account_rejects_authentication_without_unbound_throttle_records(
    auth_sessions, monkeypatch, method, purpose
):
    monkeypatch.setattr(auth, "Session", auth_sessions)
    provider_module = password_provider if method == "password" else publickey
    monkeypatch.setattr(provider_module, "DatabaseSession", auth_sessions)
    monkeypatch.setattr(login_guard, "Session", auth_sessions)
    monkeypatch.setattr(
        login_guard.AuthThrottlePolicy,
        "from_config",
        classmethod(lambda cls: login_guard.AuthThrottlePolicy()),
    )
    monkeypatch.setattr(
        login_guard.LoginGuard,
        "evaluate",
        lambda *args: login_guard.ThrottleDecision(True),
    )
    monkeypatch.setattr(auth, "get_client_ip", lambda ws: "127.0.0.1")
    proof = (
        {"password": "Password123!"}
        if method == "password"
        else {"fingerprint": "ab" * 32}
    )
    if purpose == AuthPurpose.LOGIN:
        handler = Handler(
            {"method": method, "credential": {"username": "missing", **proof}}
        )
        request_handler = auth.RequestLoginHandler()
    else:
        context = (
            AuthenticationContext(
                login_method="password",
                signing_key_digest="unused",
                login_revision=1,
                mfa_revision=1,
            )
            if purpose == AuthPurpose.MFA
            else None
        )
        token = Token.new(
            uuid.uuid4(),
            60,
            "test-signing-key" * 4,
            TokenPurpose.AUTH if purpose == AuthPurpose.MFA else TokenPurpose.GENERAL,
            auth_context=context,
        )
        handler = Handler(
            {
                "method": method,
                "data": proof,
                "target_purpose": 2 if purpose == AuthPurpose.MFA else 6,
            },
            token,
        )
        request_handler = auth.RequestExchangeTokenHandler()

    assert (
        request_handler.handle(
            handler, request_handler.request_model.model_validate(handler.data)
        ).code
        == 401
    )
    assert handler.response["code"] == 401
    assert "token" not in handler.response["data"]
    with auth_sessions() as session:
        accounts = session.scalars(select(AccountThrottle)).all()
        pairs = session.scalars(select(LoginThrottle)).all()
        traffic = session.scalars(select(TrafficThrottle)).all()
        if purpose == AuthPurpose.LOGIN:
            assert [
                (row.username, row.factor, row.failed_attempts) for row in accounts
            ] == [("missing", method, 1)]
            assert [
                (row.username, row.ip_address, row.failed_attempts) for row in pairs
            ] == [("missing", "127.0.0.1", 1)]
            assert [(row.ip_address, row.failed_attempts) for row in traffic] == [
                ("127.0.0.1", 1)
            ]
        else:
            assert accounts == []
            assert pairs == []
            assert traffic == []


def test_login_context_mfa_consumes_backup_code_and_normal_token_has_no_context(
    login_context, auth_sessions
):
    user_id, _secret, codes, signing_key = login_context
    handler = Handler(
        {
            "method": "password",
            "credential": {"username": "login", "password": "Password123!"},
        }
    )
    assert (
        auth.RequestLoginHandler()
        .handle(
            handler, auth.RequestLoginHandler.request_model.model_validate(handler.data)
        )
        .code
        == 202
    )
    token = Token.from_raw(handler.response["data"]["token"], signing_key)
    assert token.auth_context is not None
    assert "version" not in token.auth_context.model_dump()
    assert codes[0] not in token.raw
    complete = Handler({"method": "totp", "data": {"token": codes[0]}}, token)
    assert (
        auth.RequestExchangeTokenHandler()
        .handle(
            complete,
            auth.RequestExchangeTokenHandler.request_model.model_validate(
                complete.data
            ),
        )
        .code
        == 200
    )
    payload = jwt.decode(
        complete.response["data"]["token"], signing_key, algorithms=["HS256"]
    )
    assert "auth_context" not in payload
    with auth_sessions() as session:
        assert not session.get(UserTotpCredential, user_id).verify(codes[0])


def test_correct_password_can_be_disallowed_and_totp_can_be_escalation_only(
    login_context, auth_sessions
):
    user_id, _, _, _ = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        mfa = session.get(UserAuthPolicy, (user_id, "mfa"))
        replace_auth_policy(
            session, user, AuthPurpose.ESCALATION, mfa.chains, expected_revision=0
        )
        replace_auth_policy(
            session, user, AuthPurpose.MFA, [], expected_revision=mfa.revision
        )
    handler = Handler(
        {
            "method": "password",
            "credential": {"username": "login", "password": "Password123!"},
        }
    )
    assert (
        auth.RequestLoginHandler()
        .handle(
            handler, auth.RequestLoginHandler.request_model.model_validate(handler.data)
        )
        .code
        == 200
    )
    with auth_sessions.begin() as session:
        replace_auth_policy(
            session,
            session.get(User, user_id),
            AuthPurpose.LOGIN,
            [],
            expected_revision=1,
        )
    assert (
        auth.RequestLoginHandler()
        .handle(
            handler, auth.RequestLoginHandler.request_model.model_validate(handler.data)
        )
        .code
        == 401
    )
    assert "token" not in handler.response["data"]


def test_unauthorized_totp_fails_without_consuming_backup_code(
    login_context, auth_sessions
):
    user_id, _, codes, _ = login_context
    with auth_sessions.begin() as session:
        password = session.get(UserPasswordCredential, user_id)
        replace_auth_policy(
            session,
            session.get(User, user_id),
            AuthPurpose.ESCALATION,
            [[{"method": "password", "credential_ids": [password.credential_id]}]],
            expected_revision=0,
        )
    handler = Handler({})
    attempt = flows.AuthenticationAttempt(
        "totp", AuthPurpose.ESCALATION, "127.0.0.1", 2, user_id=user_id
    )
    result = auth.authenticate_request(handler, attempt, {"token": codes[0]})
    assert result.code == 401
    assert handler.response["code"] == 401
    assert handler.response["data"] == {}
    with auth_sessions() as session:
        assert session.get(UserTotpCredential, user_id).verify(codes[0])


@pytest.mark.parametrize("change", ["policy", "delete", "pending", "legacy"])
def test_auth_continuation_rejects_changed_or_legacy_context(
    login_context, auth_sessions, change
):
    user_id, secret, _, signing_key = login_context
    handler = Handler(
        {
            "method": "password",
            "credential": {"username": "login", "password": "Password123!"},
        }
    )
    auth.RequestLoginHandler().handle(
        handler, auth.RequestLoginHandler.request_model.model_validate(handler.data)
    )
    token = Token.from_raw(handler.response["data"]["token"], signing_key)
    with auth_sessions.begin() as session:
        if change == "policy":
            mfa = session.get(UserAuthPolicy, (user_id, "mfa"))
            replace_auth_policy(
                session,
                session.get(User, user_id),
                AuthPurpose.MFA,
                [],
                expected_revision=mfa.revision,
            )
        elif change == "delete":
            session.delete(session.get(UserPasswordCredential, user_id))
        elif change == "pending":
            session.get(UserTotpCredential, user_id).enabled = False
        else:
            token = Token.new(user_id, 60, signing_key, TokenPurpose.AUTH)
    complete = Handler(
        {"method": "totp", "data": {"token": pyotp.TOTP(secret).now()}}, token
    )
    assert auth.RequestExchangeTokenHandler().handle(
        complete,
        auth.RequestExchangeTokenHandler.request_model.model_validate(complete.data),
    ).code in {401, 403}
    assert "token" not in complete.response["data"]


def test_login_evidence_cannot_satisfy_mfa(login_context, auth_sessions):
    user_id, _, _, _ = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        policy = session.get(UserAuthPolicy, (user_id, "login"))
        replace_auth_policy(
            session, user, AuthPurpose.MFA, policy.chains, expected_revision=1
        )
        credential = session.get(UserPasswordCredential, user_id)
        context = create_authentication_context(
            session, user, AuthPurpose.LOGIN, "password"
        )
        context = context.model_copy(
            update={
                "evidence": [
                    AuthEvidence(
                        user_id=user_id,
                        attempt_id=context.attempt_id,
                        method="password",
                        credential_id=credential.credential_id,
                    )
                ]
            }
        )
        progress = get_login_progress(session, user, context)
        assert not progress.satisfied
        assert progress.purpose == AuthPurpose.MFA
        assert progress.next_steps == []
    handler = password_login()
    assert (
        auth.RequestLoginHandler()
        .handle(
            handler, auth.RequestLoginHandler.request_model.model_validate(handler.data)
        )
        .code
        == 403
    )
    assert "token" not in handler.response["data"]


def test_totp_setup_validation_does_not_use_authentication_throttle(
    monkeypatch, auth_sessions
):
    import pyotp

    from include.database.models.auth import UserAuthPolicy, UserTotpCredential
    from include.domains.security.handlers import two_factor
    from include.domains.security.handlers.two_factor import RequestValidate2FAHandler

    sessions = auth_sessions
    secret = pyotp.random_base32()
    with sessions.begin() as session:
        user = User(username="alice")
        session.add(user)
        session.flush()
        user_id = user.id
        session.add(UserTotpCredential(user_id=user_id, secret=secret, enabled=False))

    def unexpected_throttle_call(*_args, **_kwargs):
        raise AssertionError(
            "2FA setup validation must not use authentication throttle"
        )

    responses = []
    handler = SimpleNamespace(
        user_id=user_id,
        data={"token": "invalid"},
        conclude_request=lambda *args, **kwargs: responses.append((args, kwargs)),
    )
    monkeypatch.setattr(two_factor, "Session", sessions)
    monkeypatch.setattr(two_factor, "get_client_ip", unexpected_throttle_call)
    for name in ("evaluate", "report_failure", "report_success"):
        monkeypatch.setattr(two_factor.LoginGuard, name, unexpected_throttle_call)
    assert (
        RequestValidate2FAHandler()
        .handle(
            handler,
            RequestValidate2FAHandler.request_model.model_validate(handler.data),
        )
        .code
        == 401
    )
    assert [(args[:2], kwargs) for args, kwargs in responses] == [((401, {}), {})]
    handler.data["token"] = pyotp.TOTP(secret).now()
    responses.clear()
    assert (
        RequestValidate2FAHandler()
        .handle(
            handler,
            RequestValidate2FAHandler.request_model.model_validate(handler.data),
        )
        .code
        == 0
    )
    assert responses[0][1]["code"] == 200
    with sessions() as session:
        credential = session.get(UserTotpCredential, user_id)
        assert credential.enabled
        assert session.get(UserAuthPolicy, (user_id, "mfa")).chains == [
            [
                {
                    "method": "totp",
                    "credential_ids": [credential.credential_id],
                }
            ]
        ]


def test_password_does_not_collect_more_credentials(login_context, auth_sessions):
    user_id, _, _, _ = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        policy = session.get(UserAuthPolicy, (user_id, "login"))
        replace_auth_policy(
            session,
            user,
            AuthPurpose.LOGIN,
            [policy.chains[0] * 2],
            expected_revision=1,
        )
    handler = password_login()
    handler.stream = DialogStream(
        lambda message: pytest.fail(
            "Password login must not request another credential"
        )
    )
    assert (
        auth.RequestLoginHandler()
        .handle(
            handler, auth.RequestLoginHandler.request_model.model_validate(handler.data)
        )
        .code
        == 403
    )
    assert handler.stream.messages == []
    assert "token" not in handler.response["data"]


def test_policy_alternatives_and_unavailable_credentials_are_independent():
    user_id = uuid.uuid4()
    chains = auth_chains_adapter.validate_python(
        [
            [{"method": "password", "credential_ids": ["password"]}],
            [{"method": "totp", "credential_ids": ["totp"]}],
        ]
    )
    credentials = [
        RegisteredCredential(method="password", credential_id="password", active=False),
        RegisteredCredential(method="totp", credential_id="totp", active=True),
    ]
    for method, expected in (("password", False), ("totp", True)):
        evidence = [
            AuthEvidence(
                user_id=user_id,
                attempt_id="attempt",
                method=method,
                credential_id=method,
            )
        ]
        assert (
            evaluate_auth_policy(
                AuthPurpose.ESCALATION,
                chains,
                credentials,
                evidence,
                user_id=user_id,
                attempt_id="attempt",
            ).satisfied
            is expected
        )


def password_login():
    return Handler(
        {
            "method": "password",
            "credential": {
                "username": "login",
                "password": "Password123!",
            },
        }
    )


def complete_with_backup(handler, signing_key, backup_code):
    token = Token.from_raw(handler.response["data"]["token"], signing_key)
    complete = Handler({"method": "totp", "data": {"token": backup_code}}, token)
    auth.RequestExchangeTokenHandler().handle(
        complete,
        auth.RequestExchangeTokenHandler.request_model.model_validate(complete.data),
    )
    return complete


@pytest.mark.parametrize("requirement", ["rules", "forced", "expired"])
def test_password_change_is_offered_only_after_mfa(
    login_context, auth_sessions, monkeypatch, requirement
):
    from include.config.settings import global_config

    user_id, _, codes, signing_key = login_context
    with auth_sessions.begin() as session:
        session.get(User, user_id).last_login = 10
        credential = session.get(UserPasswordCredential, user_id)
        if requirement == "forced":
            credential.passwd_last_modified = 0
        elif requirement == "expired":
            credential.passwd_last_modified = 1
    cfg = global_config["security"]
    monkeypatch.setitem(cfg, "enable_passwd_force_expiration", requirement == "expired")
    if requirement == "rules":
        monkeypatch.setitem(cfg, "passwd_min_length", 30)
    handler = password_login()
    assert (
        auth.RequestLoginHandler()
        .handle(
            handler, auth.RequestLoginHandler.request_model.model_validate(handler.data)
        )
        .code
        == 202
    )
    raw = handler.response["data"]["token"]
    payload = jwt.decode(raw, signing_key, algorithms=["HS256"])
    assert payload["auth_context"]["login_method"] == "password"
    assert not (
        {"required_actions", "rules_satisfied", "policy_digest"} & payload.keys()
    )
    assert "rules_satisfied" not in orjson.dumps(payload).decode()
    failed = complete_with_backup(handler, signing_key, "incorrect")
    assert failed.response["code"] == 401
    assert failed.response["data"] == {}
    complete = complete_with_backup(handler, signing_key, codes[0])
    assert complete.response["code"] == (4001 if requirement == "rules" else 4002)
    assert set(complete.response["data"]) == {
        "token",
        "exp",
        "required_actions",
        "purpose",
    }
    token = Token.from_raw(complete.response["data"]["token"], signing_key)
    assert token.purpose == TokenPurpose.POST_AUTH
    assert token.auth_context.login_method == "password"
    assert "version" not in token.auth_context.model_dump()
    assert token.exp <= payload["exp"]
    assert 0 < token.exp - token.iat <= 300
    with auth_sessions() as session:
        assert session.get(User, user_id).last_login == 10
        assert not session.get(UserTotpCredential, user_id).verify(codes[0])


@pytest.mark.parametrize("change", ["cache", "rules", "signing_key"])
def test_mfa_rejects_lost_or_changed_password_state(
    login_context, auth_sessions, monkeypatch, change
):
    from include.config.settings import global_config
    from include.domains.identity import sessions

    user_id, _, codes, signing_key = login_context
    handler = password_login()
    assert (
        auth.RequestLoginHandler()
        .handle(
            handler, auth.RequestLoginHandler.request_model.model_validate(handler.data)
        )
        .code
        == 202
    )
    token = Token.from_raw(handler.response["data"]["token"], signing_key)
    if change == "cache":
        sessions.ProviderManager().caching.delete(
            f"auth:password:{token.auth_context.attempt_id}"
        )
    elif change == "rules":
        cfg = global_config["security"]
        monkeypatch.setitem(cfg, "passwd_min_length", cfg["passwd_min_length"] + 1)
    else:
        with auth_sessions.begin() as session:
            session.get(User, user_id).secret_key = "changed" * 10
    complete = complete_with_backup(handler, signing_key, codes[0])
    assert complete.response["code"] == 401
    assert "token" not in complete.response["data"]


def test_post_auth_password_change_rotates_secret_and_requires_new_login(
    login_context, auth_sessions, monkeypatch
):
    from include.domains.identity.handlers import users

    monkeypatch.setattr(users, "Session", auth_sessions)
    user_id, _, codes, signing_key = login_context
    with auth_sessions.begin() as session:
        session.get(UserPasswordCredential, user_id).passwd_last_modified = 0
    handler = password_login()
    auth.RequestLoginHandler().handle(
        handler, auth.RequestLoginHandler.request_model.model_validate(handler.data)
    )
    complete = complete_with_backup(handler, signing_key, codes[0])
    token = Token.from_raw(complete.response["data"]["token"], signing_key)
    rejected = Handler({"new_passwd": "short"}, token)
    assert (
        users.RequestSetPasswdHandler()
        .handle(
            rejected,
            users.RequestSetPasswdHandler.request_model.model_validate(rejected.data),
        )
        .code
        == 400
    )
    assert "token" not in rejected.response["data"]
    changed = Handler({"new_passwd": "UpdatedPassword456!"}, token)
    assert (
        users.RequestSetPasswdHandler()
        .handle(
            changed,
            users.RequestSetPasswdHandler.request_model.model_validate(changed.data),
        )
        .code
        == 200
    )
    assert changed.response["data"] == {}
    assert (
        users.RequestSetPasswdHandler()
        .handle(
            changed,
            users.RequestSetPasswdHandler.request_model.model_validate(changed.data),
        )
        .code
        == 401
    )
    with auth_sessions() as session:
        user = session.get(User, user_id)
        credential = session.get(UserPasswordCredential, user_id)
        assert credential.verify("UpdatedPassword456!")
        assert credential.passwd_last_modified > 0
        assert user.secret_key != signing_key
        assert not user.is_token_valid(token, purpose=TokenPurpose.POST_AUTH)
    handler.data["credential"]["password"] = "UpdatedPassword456!"
    assert (
        auth.RequestLoginHandler()
        .handle(
            handler, auth.RequestLoginHandler.request_model.model_validate(handler.data)
        )
        .code
        == 202
    )


def test_concurrent_post_auth_password_change_has_one_winner(
    login_context, auth_sessions, monkeypatch
):
    from include.domains.identity.handlers import users

    monkeypatch.setattr(users, "Session", auth_sessions)
    user_id, _, codes, signing_key = login_context
    with auth_sessions.begin() as session:
        session.get(UserPasswordCredential, user_id).passwd_last_modified = 0
    handler = password_login()
    auth.RequestLoginHandler().handle(
        handler, auth.RequestLoginHandler.request_model.model_validate(handler.data)
    )
    complete = complete_with_backup(handler, signing_key, codes[0])
    token = Token.from_raw(complete.response["data"]["token"], signing_key)
    barrier = threading.Barrier(2)
    results, errors = [], []
    original = users.set_password

    def competing_update(*args, **kwargs):
        barrier.wait(timeout=5)
        original(*args, **kwargs)

    def worker(password):
        try:
            request = Handler({"new_passwd": password}, token)
            result = users.RequestSetPasswdHandler().handle(
                request,
                users.RequestSetPasswdHandler.request_model.model_validate(
                    request.data
                ),
            )
            results.append((result.code, password))
        except Exception as exc:  # noqa: BLE001 -- propagate worker failures to the test thread
            errors.append(exc)

    monkeypatch.setattr(users, "set_password", competing_update)
    workers = [
        threading.Thread(target=worker, args=(p,))
        for p in ("WinnerPassword123!", "WinnerPassword456!")
    ]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join(timeout=10)
        assert not thread.is_alive()
    assert errors == []
    assert sorted(code for code, _ in results) == [200, 401]
    with auth_sessions() as session:
        credential = session.get(UserPasswordCredential, user_id)
        assert credential.verify(next(p for code, p in results if code == 200))


class DialogStream:
    def __init__(self, reply):
        self.connection = SimpleNamespace(_ws=None)
        self.frame_id = 1
        self.messages = []
        self.reply = reply
        self.response_frame_type = FrameType.PROCESS
        self.timeouts = []

    def send(self, data, frame_type):
        assert frame_type == FrameType.PROCESS
        self.messages.append(orjson.loads(data))

    def recv(self, timeout=None):
        self.timeouts.append(timeout)
        message = self.messages[-1]
        response = self.reply(message)
        return Frame(
            self.frame_id,
            self.response_frame_type,
            orjson.dumps(
                {
                    "action": "auth_response",
                    "interaction_id": message["data"]["interaction_id"],
                    **response,
                }
            ),
        )


def register_key(session, user_id):
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    key = UserAuthPublicKey(
        user_id=user_id,
        public_key_der=public.public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        ),
        fingerprint=hashlib.sha256(
            public.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        ).digest(),
    )
    session.add(key)
    session.flush()
    return key.id, key.fingerprint.hex(), private


@pytest.mark.parametrize("method", ["password", "publickey"])
@pytest.mark.parametrize(
    "case",
    [
        "missing_user",
        "missing_credential",
        "empty_policy",
        "other_method",
        "invalid_proof",
    ],
)
def test_login_failures_do_not_disclose_account_or_method_availability(
    auth_sessions, monkeypatch, method, case
):
    monkeypatch.setattr(auth, "Session", auth_sessions)
    for module in (password_provider, publickey):
        monkeypatch.setattr(module, "DatabaseSession", auth_sessions)
    monkeypatch.setattr(login_guard, "Session", auth_sessions)
    monkeypatch.setattr(
        login_guard.AuthThrottlePolicy,
        "from_config",
        classmethod(lambda cls: login_guard.AuthThrottlePolicy()),
    )
    monkeypatch.setattr(
        login_guard.LoginGuard,
        "evaluate",
        lambda *args: login_guard.ThrottleDecision(True),
    )
    monkeypatch.setattr(auth, "get_client_ip", lambda ws: "127.0.0.1")
    monkeypatch.setattr(
        flows,
        "check_request_rate",
        lambda *args, **kwargs: SimpleNamespace(allowed=True),
    )
    fingerprint = "ab" * 32
    user_id = None
    with auth_sessions.begin() as session:
        if case != "missing_user":
            user = User(username="login")
            session.add(user)
            session.flush()
            user_id = user.id
            if case != "missing_credential":
                set_password(session, user, "Password123!")
                session.flush()
                password_id = session.get(UserPasswordCredential, user.id).credential_id
                key_id, fingerprint, _ = register_key(session, user.id)
                if case != "empty_policy":
                    policy_method = (
                        ("publickey" if method == "password" else "password")
                        if case == "other_method"
                        else method
                    )
                    replace_auth_policy(
                        session,
                        user,
                        AuthPurpose.LOGIN,
                        [
                            [
                                {
                                    "method": policy_method,
                                    "credential_ids": [
                                        password_id
                                        if policy_method == "password"
                                        else key_id
                                    ],
                                }
                            ]
                        ],
                        expected_revision=0,
                    )
    credential = (
        {"password": "wrong-password" if case == "invalid_proof" else "Password123!"}
        if method == "password"
        else {"fingerprint": fingerprint}
    )
    handler = Handler(
        {"method": method, "credential": {"username": "login", **credential}}
    )
    handler.stream = DialogStream(
        lambda message: {
            "method": "publickey",
            "data": {
                "fingerprint": fingerprint,
                "signature": base64.b64encode(b"invalid").decode(),
            },
        }
    )
    result = auth.RequestLoginHandler().handle(
        handler, auth.RequestLoginHandler.request_model.model_validate(handler.data)
    )
    assert result.code == 401
    assert result.user_id is None
    assert handler.response["code"] == 401
    assert handler.response["data"] == {}
    assert len(handler.stream.messages) == int(
        method == "publickey" and case == "invalid_proof"
    )
    with auth_sessions() as session:
        accounts = session.scalars(select(AccountThrottle)).all()
        pairs = session.scalars(select(LoginThrottle)).all()
        traffic = session.scalars(select(TrafficThrottle)).all()
        assert [
            (row.username, row.factor, row.failed_attempts) for row in accounts
        ] == [("login", method, 1)]
        assert [
            (row.username, row.ip_address, row.failed_attempts) for row in pairs
        ] == [("login", "127.0.0.1", 1)]
        assert [(row.ip_address, row.failed_attempts) for row in traffic] == [
            ("127.0.0.1", 1)
        ]
        if user_id is not None:
            assert session.get(User, user_id).last_login is None
            assert all(
                key.last_used_time is None
                for key in session.scalars(select(UserAuthPublicKey))
            )


@pytest.mark.parametrize("stage", ["login", "mfa"])
def test_public_key_challenge_payload_serialization_and_defaults(stage):
    user_id = uuid.uuid4()
    fields = {
        "user_id": user_id,
        "attempt_id": "attempt",
        "stage": stage,
        "stream_id": 42,
        "interaction_id": "interaction",
        "fingerprint": "f" * 64,
    }
    challenge = publickey.PublicKeyChallenge(**fields)
    serialized = publickey.public_key_challenge_adapter.dump_json(challenge)
    assert isinstance(serialized, bytes)
    contents = orjson.loads(serialized)
    nonce = contents.pop("nonce")
    assert isinstance(nonce, str)
    assert nonce
    assert contents == {
        "scope": "cfms.auth.publickey",
        "user_id": str(user_id),
        "attempt_id": "attempt",
        "stage": stage,
        "stream_id": 42,
        "interaction_id": "interaction",
        "fingerprint": "f" * 64,
    }
    assert publickey.PublicKeyChallenge(**fields).nonce != nonce
    assert nonce not in repr(challenge)
    with pytest.raises(FrozenInstanceError):
        challenge.user_id = uuid.uuid4()


@pytest.mark.parametrize("expired", [False, True], ids=["valid", "expired"])
def test_public_key_challenge_expiry_and_single_use(
    login_context, auth_sessions, monkeypatch, expired
):
    user_id, _, _, _ = login_context
    now = 100.0
    monkeypatch.setattr(
        publickey, "time", SimpleNamespace(monotonic=lambda: now, time=lambda: 123.0)
    )
    with auth_sessions.begin() as session:
        key_id, fingerprint, private = register_key(session, user_id)
        user = session.get(User, user_id)
        context = {
            "attempt_id": "attempt",
            "stage": "mfa",
            "stream_id": 42,
            "interaction_id": "interaction",
            "fingerprint": fingerprint,
        }
        provider = publickey.PublicKeyAuthProvider()
        response = provider.create_challenge(session, user, context=context)
        challenge_bytes = base64.b64decode(response["challenge"])
        contents = orjson.loads(challenge_bytes)
        nonce = contents.pop("nonce")
        assert nonce
        assert contents == {
            "scope": "cfms.auth.publickey",
            "user_id": str(user_id),
            "attempt_id": "attempt",
            "stage": "mfa",
            "stream_id": 42,
            "interaction_id": "interaction",
            "fingerprint": fingerprint,
        }
        assert response["expires_in"] == 60
        assert "nonce" not in repr(context["publickey_challenge"])
        payload = {
            "fingerprint": fingerprint,
            "signature": base64.b64encode(private.sign(challenge_bytes)).decode(),
        }
        now = 160.0 if expired else 159.0
        result = provider.verify(session, user, payload, context)
        assert result.success is (not expired)
        if expired:
            assert result.error_code == 401
        else:
            assert result.credential_id == key_id
        assert "publickey_challenge" not in context
        replay = provider.verify(session, user, payload, context)
        assert not replay.success
        assert replay.error_code == 401
    with auth_sessions() as session:
        assert session.get(UserAuthPublicKey, key_id).last_used_time == (
            None if expired else 123.0
        )


def test_public_key_login_and_mfa_use_separate_streams(login_context, auth_sessions):
    user_id, _, codes, signing_key = login_context
    with auth_sessions.begin() as session:
        key_id, fingerprint, private = register_key(session, user_id)
        replace_auth_policy(
            session,
            session.get(User, user_id),
            AuthPurpose.LOGIN,
            [[{"method": "publickey", "credential_ids": [key_id]}]],
            expected_revision=1,
        )
        session.get(UserPasswordCredential, user_id).passwd_last_modified = 0

    def sign(message):
        challenge = base64.b64decode(message["data"]["challenge"])
        contents = orjson.loads(challenge)
        assert contents["scope"] == "cfms.auth.publickey"
        assert "protocol" not in contents
        assert contents["user_id"] == str(user_id)
        assert contents["stage"] == "login"
        assert contents["stream_id"] == 1
        return {
            "method": "publickey",
            "data": {
                "fingerprint": fingerprint,
                "signature": base64.b64encode(private.sign(challenge)).decode(),
            },
        }

    handler = Handler(
        {
            "method": "publickey",
            "credential": {"username": "login", "fingerprint": fingerprint},
        }
    )
    handler.stream = DialogStream(sign)
    assert (
        auth.RequestLoginHandler()
        .handle(
            handler, auth.RequestLoginHandler.request_model.model_validate(handler.data)
        )
        .code
        == 202
    )
    assert [m["action"] for m in handler.stream.messages] == ["auth_challenge"]
    complete = complete_with_backup(handler, signing_key, codes[0])
    assert complete.response["code"] == 200
    with auth_sessions() as session:
        assert session.get(UserAuthPublicKey, key_id).last_used_time is not None


@pytest.mark.parametrize("purpose", list(AuthPurpose))
def test_policy_rejects_mixed_methods_without_changing_state(
    login_context, auth_sessions, purpose
):
    user_id, _, _, _ = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        key_id, _, _ = register_key(session, user_id)
        credential = session.get(UserPasswordCredential, user_id)
        policy = session.get(UserAuthPolicy, (user_id, purpose.value))
        revision = policy.revision if policy else 0
        original = policy.chains if policy else None
        with pytest.raises(ValueError, match="one method"):
            replace_auth_policy(
                session,
                user,
                purpose,
                [
                    [
                        {
                            "method": "password",
                            "credential_ids": [credential.credential_id],
                        },
                        {"method": "publickey", "credential_ids": [key_id]},
                    ]
                ],
                expected_revision=revision,
            )
        session.expire_all()
        stored = session.get(UserAuthPolicy, (user_id, purpose.value))
        assert (stored.chains if stored else None) == original
        assert (stored.revision if stored else 0) == revision


def test_same_method_mfa_is_excluded_even_with_another_key(
    login_context, auth_sessions
):
    user_id, _, codes, signing_key = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        first, fingerprint, private = register_key(session, user_id)
        second, _, _ = register_key(session, user_id)
        replace_auth_policy(
            session,
            user,
            AuthPurpose.LOGIN,
            [[{"method": "publickey", "credential_ids": [first]}]],
            expected_revision=1,
        )
        mfa = session.get(UserAuthPolicy, (user_id, "mfa"))
        replace_auth_policy(
            session,
            user,
            AuthPurpose.MFA,
            [[{"method": "publickey", "credential_ids": [second]}], mfa.chains[0]],
            expected_revision=1,
        )
    login = Handler(
        {
            "method": "publickey",
            "credential": {"username": "login", "fingerprint": fingerprint},
        }
    )
    login.stream = DialogStream(
        lambda message: {
            "method": "publickey",
            "data": {
                "fingerprint": fingerprint,
                "signature": base64.b64encode(
                    private.sign(base64.b64decode(message["data"]["challenge"]))
                ).decode(),
            },
        }
    )
    assert (
        auth.RequestLoginHandler()
        .handle(
            login, auth.RequestLoginHandler.request_model.model_validate(login.data)
        )
        .code
        == 202
    )
    assert login.response["data"]["methods"] == ["totp"]
    token = Token.from_raw(login.response["data"]["token"], signing_key)
    rejected = Handler(
        {"method": "publickey", "data": {"fingerprint": fingerprint}}, token
    )
    rejected.stream = DialogStream(
        lambda message: pytest.fail(
            "Same-method MFA must be rejected before challenging"
        )
    )
    assert (
        auth.RequestExchangeTokenHandler()
        .handle(
            rejected,
            auth.RequestExchangeTokenHandler.request_model.model_validate(
                rejected.data
            ),
        )
        .code
        == 403
    )
    assert rejected.stream.messages == []
    assert complete_with_backup(login, signing_key, codes[0]).response["code"] == 200


@pytest.mark.parametrize("stage", [AuthPurpose.LOGIN, AuthPurpose.MFA])
@pytest.mark.parametrize(
    "failure",
    [
        "interaction",
        "method",
        "frame",
        "validation",
        "signature",
        "expired",
        "timeout",
        "disconnect",
        "policy",
        "revoked",
        "rate",
    ],
)
def test_public_key_dialog_rejects_invalid_or_stale_proofs(
    login_context, auth_sessions, monkeypatch, stage, failure
):
    user_id, _, _, signing_key = login_context
    elapsed = [100]
    monkeypatch.setattr(
        publickey, "time", SimpleNamespace(monotonic=lambda: elapsed[0], time=time.time)
    )
    with auth_sessions.begin() as session:
        key_id, fingerprint, private = register_key(session, user_id)
        user = session.get(User, user_id)
        replace_auth_policy(
            session,
            user,
            stage,
            [[{"method": "publickey", "credential_ids": [key_id]}]],
            expected_revision=1,
        )

    def reply(message):
        if failure == "expired":
            elapsed[0] += 61
        if failure == "timeout":
            raise TimeoutError
        if failure == "disconnect":
            raise ConnectionError
        if failure in {"policy", "revoked"}:
            with auth_sessions.begin() as session:
                if failure == "policy":
                    replace_auth_policy(
                        session,
                        session.get(User, user_id),
                        stage,
                        [],
                        expected_revision=2,
                    )
                else:
                    session.delete(session.get(UserAuthPublicKey, key_id))
        challenge = base64.b64decode(message["data"]["challenge"])
        if failure == "signature":
            challenge = b"another stream's challenge"
        result = {
            "method": "password" if failure == "method" else "publickey",
            "data": {
                "fingerprint": fingerprint,
                "signature": base64.b64encode(private.sign(challenge)).decode(),
            },
        }
        if failure == "interaction":
            result["interaction_id"] = "wrong"
        elif failure == "validation":
            result["action"] = "unexpected"
        return result

    if stage == AuthPurpose.LOGIN:
        handler = Handler(
            {
                "method": "publickey",
                "credential": {"username": "login", "fingerprint": fingerprint},
            }
        )
        request_handler = auth.RequestLoginHandler()
    else:
        login = password_login()
        assert (
            auth.RequestLoginHandler()
            .handle(
                login, auth.RequestLoginHandler.request_model.model_validate(login.data)
            )
            .code
            == 202
        )
        token = Token.from_raw(login.response["data"]["token"], signing_key)
        handler = Handler(
            {"method": "publickey", "data": {"fingerprint": fingerprint}}, token
        )
        request_handler = auth.RequestExchangeTokenHandler()
    handler.stream = DialogStream(reply)
    if failure == "frame":
        handler.stream.response_frame_type = FrameType.CONCLUSION
    elif failure == "rate":
        charges = []

        def deny(pending, **kwargs):
            charges.extend(pending)
            return RateLimitDecision(False, retry_after_seconds=17)

        policy = RequestRateControlPolicy(
            mode="enforce", action_costs=(("login", 9), ("exchange_token", 7))
        )
        monkeypatch.setattr(
            request_rate_control.RequestRateControlPolicy,
            "from_config",
            classmethod(lambda cls: policy),
        )
        monkeypatch.setattr(
            request_rate_control,
            "ProviderManager",
            lambda: SimpleNamespace(rate_limit=SimpleNamespace(consume=deny)),
        )
        monkeypatch.setattr(
            flows, "check_request_rate", request_rate_control.check_request_rate
        )
    result = request_handler.handle(
        handler, request_handler.request_model.model_validate(handler.data)
    )
    expected = {
        "interaction": 400,
        "method": 400,
        "frame": 400,
        "validation": 400,
        "signature": 401,
        "expired": 401,
        "timeout": 408,
        "disconnect": 499,
        "policy": 401,
        "revoked": 401,
        "rate": 429,
    }[failure]
    assert result.code == expected
    assert result.target == "login"
    assert result.user_id == (user_id if stage == AuthPurpose.MFA else None)
    if failure == "disconnect":
        assert handler.response is None
    else:
        assert handler.response["code"] == expected
        assert handler.response["data"] == (
            {"retry_after_seconds": 17} if failure == "rate" else {}
        )
    if failure == "rate":
        cost = 9 if stage == AuthPurpose.LOGIN else 7
        assert [(charge.scope, charge.cost) for charge in charges] == [("ip", cost)]
    with auth_sessions() as session:
        assert session.get(User, user_id).last_login is None
        if failure != "revoked":
            assert session.get(UserAuthPublicKey, key_id).last_used_time is None


@pytest.mark.parametrize("stage", [AuthPurpose.LOGIN, AuthPurpose.MFA])
def test_public_key_dialog_has_no_fixed_round_limit_and_waits_outside_transactions(
    login_context, auth_sessions, monkeypatch, stage
):
    from sqlalchemy.orm import Session as ORMSession

    user_id, _, _, signing_key = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        keys = [register_key(session, user_id) for _ in range(12)]
        replace_auth_policy(
            session,
            user,
            stage,
            [[{"method": "publickey", "credential_ids": [key[0]]} for key in keys]],
            expected_revision=1,
        )
        if stage == AuthPurpose.LOGIN:
            replace_auth_policy(session, user, AuthPurpose.MFA, [], expected_revision=1)
    if stage == AuthPurpose.LOGIN:
        handler = Handler(
            {
                "method": "publickey",
                "credential": {"username": "login", "fingerprint": keys[0][1]},
            }
        )
        request_handler = auth.RequestLoginHandler()
    else:
        login = password_login()
        assert (
            auth.RequestLoginHandler()
            .handle(
                login, auth.RequestLoginHandler.request_model.model_validate(login.data)
            )
            .code
            == 202
        )
        handler = Handler(
            {"method": "publickey", "data": {"fingerprint": keys[0][1]}},
            Token.from_raw(login.response["data"]["token"], signing_key),
        )
        request_handler = auth.RequestExchangeTokenHandler()
    opened = []

    class TrackingSession(ORMSession):
        def __enter__(self):
            opened.append(self)
            return super().__enter__()

        def __exit__(self, *args):
            opened.remove(self)
            return super().__exit__(*args)

    monkeypatch.setattr(
        publickey,
        "DatabaseSession",
        sessionmaker(bind=auth_sessions.kw["bind"], class_=TrackingSession),
    )
    pending = iter(keys[1:])
    private_keys = {fingerprint: private for _, fingerprint, private in keys}

    def reply(message):
        assert opened == []
        if message["action"] == "auth_continue":
            return {"method": "publickey", "data": {"fingerprint": next(pending)[1]}}
        challenge = base64.b64decode(message["data"]["challenge"])
        fingerprint = orjson.loads(challenge)["fingerprint"]
        return {
            "method": "publickey",
            "data": {
                "fingerprint": fingerprint,
                "signature": base64.b64encode(
                    private_keys[fingerprint].sign(challenge)
                ).decode(),
            },
        }

    handler.stream = DialogStream(reply)
    assert (
        request_handler.handle(
            handler, request_handler.request_model.model_validate(handler.data)
        ).code
        == 200
    )
    assert len(handler.stream.messages) == 23
    assert handler.stream.timeouts == [None] * 23
    with auth_sessions() as session:
        assert all(
            session.get(UserAuthPublicKey, key_id).last_used_time is not None
            for key_id, _, _ in keys
        )


@pytest.mark.parametrize("stage", [AuthPurpose.LOGIN, AuthPurpose.MFA])
def test_dialog_can_advance_interleaved_policy_alternatives(
    login_context, auth_sessions, stage
):
    user_id, _, _, signing_key = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        keys = [register_key(session, user_id) for _ in range(3)]
        steps = [
            {"method": "publickey", "credential_ids": [key_id]} for key_id, _, _ in keys
        ]
        replace_auth_policy(
            session,
            user,
            stage,
            [[steps[0], steps[2]], [steps[1], steps[2]]],
            expected_revision=1,
        )
        if stage == AuthPurpose.LOGIN:
            replace_auth_policy(session, user, AuthPurpose.MFA, [], expected_revision=1)

    following_keys = iter(keys[1:])
    private_keys = {fingerprint: private for _, fingerprint, private in keys}

    def reply(message):
        assert message["data"]["stage"] == stage.value
        if message["action"] == "auth_continue":
            _, fingerprint, _ = next(following_keys)
            return {"method": "publickey", "data": {"fingerprint": fingerprint}}
        challenge = base64.b64decode(message["data"]["challenge"])
        fingerprint = orjson.loads(challenge)["fingerprint"]
        return {
            "method": "publickey",
            "data": {
                "fingerprint": fingerprint,
                "signature": base64.b64encode(
                    private_keys[fingerprint].sign(challenge)
                ).decode(),
            },
        }

    fingerprint = keys[0][1]
    if stage == AuthPurpose.LOGIN:
        handler = Handler(
            {
                "method": "publickey",
                "credential": {"username": "login", "fingerprint": fingerprint},
            }
        )
        request_handler = auth.RequestLoginHandler()
    else:
        login = password_login()
        assert (
            auth.RequestLoginHandler()
            .handle(
                login, auth.RequestLoginHandler.request_model.model_validate(login.data)
            )
            .code
            == 202
        )
        token = Token.from_raw(login.response["data"]["token"], signing_key)
        handler = Handler(
            {"method": "publickey", "data": {"fingerprint": fingerprint}}, token
        )
        request_handler = auth.RequestExchangeTokenHandler()
    handler.stream = DialogStream(reply)

    result = request_handler.handle(
        handler, request_handler.request_model.model_validate(handler.data)
    )

    assert result.code == 200
    assert result.user_id == user_id
    assert handler.response["code"] == 200
    assert handler.response["data"]["user_id"] == str(user_id)
    assert [message["action"] for message in handler.stream.messages] == [
        "auth_challenge",
        "auth_continue",
        "auth_challenge",
        "auth_continue",
        "auth_challenge",
    ]
    assert handler.stream.timeouts == [None] * 5
    with auth_sessions() as session:
        assert session.get(User, user_id).last_login is not None
        for key_id, _, _ in keys:
            assert session.get(UserAuthPublicKey, key_id).last_used_time is not None


@pytest.mark.parametrize(
    "extra",
    [
        {"username": "other"},
        {"user_id": str(uuid.uuid4())},
        {"old_passwd": "Password123!"},
        {"bypass_passwd_requirements": True},
        {"force_update_after_login": True},
    ],
)
def test_post_auth_cannot_select_other_accounts_or_options(
    login_context, auth_sessions, monkeypatch, extra
):
    from include.domains.identity.handlers import users

    monkeypatch.setattr(users, "Session", auth_sessions)
    user_id, _, codes, signing_key = login_context
    with auth_sessions.begin() as session:
        session.get(UserPasswordCredential, user_id).passwd_last_modified = 0
    login = password_login()
    auth.RequestLoginHandler().handle(
        login, auth.RequestLoginHandler.request_model.model_validate(login.data)
    )
    complete = complete_with_backup(login, signing_key, codes[0])
    token = Token.from_raw(complete.response["data"]["token"], signing_key)
    handler = Handler({"new_passwd": "UpdatedPassword456!", **extra}, token)
    if "username" in extra or "old_passwd" in extra:
        with pytest.raises(ValidationError) as error:
            users.RequestSetPasswdHandler.request_model.model_validate(handler.data)
        assert [(item["type"], item["loc"]) for item in error.value.errors()] == [
            ("value_error", ())
        ]
    else:
        request = users.RequestSetPasswdHandler.request_model.model_validate(
            handler.data
        )
        assert users.RequestSetPasswdHandler().handle(handler, request).code == 400
    with auth_sessions() as session:
        assert session.get(UserPasswordCredential, user_id).verify("Password123!")


@pytest.mark.parametrize(
    "mutation", ["missing_context", "login_method", "stage", "mixed"]
)
def test_continuation_tokens_reject_missing_context_and_cross_purpose_claims(
    login_context, mutation
):
    _, _, _, signing_key = login_context
    login = password_login()
    auth.RequestLoginHandler().handle(
        login, auth.RequestLoginHandler.request_model.model_validate(login.data)
    )
    payload = jwt.decode(
        login.response["data"]["token"], signing_key, algorithms=["HS256"]
    )
    if mutation == "missing_context":
        del payload["auth_context"]
    elif mutation == "login_method":
        del payload["auth_context"]["login_method"]
    elif mutation == "stage":
        payload["auth_context"]["stage"] = "post_auth"
    else:
        payload["purpose"] |= TokenPurpose.GENERAL
    with pytest.raises(jwt.InvalidTokenError):
        Token.from_raw(jwt.encode(payload, signing_key, algorithm="HS256"), signing_key)


@pytest.mark.parametrize(
    "action",
    ["server_info", "login", "refresh_token", "exchange_token", "get_user_info"],
)
def test_post_auth_router_rejects_every_other_action(
    login_context, auth_sessions, monkeypatch, action
):
    from include.transport import router

    monkeypatch.setattr(router, "Session", auth_sessions)
    monkeypatch.setattr(
        router.LoginGuard,
        "evaluate_subnet_access",
        lambda _: SimpleNamespace(allowed=True),
    )
    user_id, _, codes, signing_key = login_context
    with auth_sessions.begin() as session:
        session.get(UserPasswordCredential, user_id).passwd_last_modified = 0
    login = password_login()
    auth.RequestLoginHandler().handle(
        login, auth.RequestLoginHandler.request_model.model_validate(login.data)
    )
    complete = complete_with_backup(login, signing_key, codes[0])
    request = orjson.dumps(
        {"action": action, "data": {}, "token": complete.response["data"]["token"]}
    )
    responses = []
    stream = SimpleNamespace(
        connection=SimpleNamespace(
            _ws=SimpleNamespace(
                remote_address=("127.0.0.1", 1), request=SimpleNamespace(headers={})
            )
        ),
        recv=lambda: SimpleNamespace(data=request),
        send=lambda data, **kw: responses.append(orjson.loads(data)),
    )
    router.handle_request(stream)
    assert responses[0]["code"] == 403
    assert responses[0]["data"] == {}


@pytest.mark.parametrize("position", [0, 1, 2], ids=["first", "middle", "last"])
@pytest.mark.parametrize("existing", [False, True], ids=["create", "replace"])
def test_login_policy_rejects_totp_without_changing_persisted_state(
    login_context, auth_sessions, position, existing
):
    user_id, _, _, _ = login_context
    with auth_sessions.begin() as session:
        login = session.get(UserAuthPolicy, (user_id, "login"))
        original_chains = login.chains
        original_revision = login.revision
        if not existing:
            session.delete(login)
            session.flush()
        password_step = original_chains[0][0]
        totp_step = session.get(UserAuthPolicy, (user_id, "mfa")).chains[0][0]
        chain = [password_step, password_step]
        chain.insert(position, totp_step)
        with pytest.raises(ValueError, match="one method"):
            replace_auth_policy(
                session,
                session.get(User, user_id),
                AuthPurpose.LOGIN,
                [chain],
                expected_revision=original_revision if existing else 0,
            )
    with auth_sessions() as session:
        policy = session.get(UserAuthPolicy, (user_id, "login"))
        if existing:
            assert policy.chains == original_chains
            assert policy.revision == original_revision
        else:
            assert policy is None


@pytest.mark.parametrize("position", [0, 1, 2], ids=["first", "middle", "last"])
@pytest.mark.parametrize("alternative", [False, True], ids=["blocked", "alternative"])
def test_legacy_login_totp_chain_is_unavailable_without_shortening(
    login_context, auth_sessions, position, alternative
):
    user_id, _, codes, _ = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        login = session.get(UserAuthPolicy, (user_id, "login"))
        password_step = login.chains[0][0]
        totp_step = session.get(UserAuthPolicy, (user_id, "mfa")).chains[0][0]
        chain = [password_step, password_step]
        chain.insert(position, totp_step)
        legacy_chains = [chain, [password_step]] if alternative else [chain]
        login.chains = legacy_chains
        session.flush()
        initial = auth_registry.evaluate_user_policy(
            session, user, AuthPurpose.LOGIN, [], attempt_id="attempt"
        )
        assert not initial.satisfied
        assert [step.model_dump() for step in initial.next_steps] == (
            [password_step] if alternative else []
        )
        evidence = [
            AuthEvidence(
                user_id=user_id,
                attempt_id="attempt",
                method=step["method"],
                credential_id=step["credential_ids"][0],
            )
            for step in chain
        ]
        assert (
            auth_registry.evaluate_user_policy(
                session, user, AuthPurpose.LOGIN, evidence, attempt_id="attempt"
            ).satisfied
            is alternative
        )
    handler = password_login()
    if position == 0 and not alternative:
        handler.data = {
            "method": "totp",
            "credential": {"username": "login", "token": codes[0]},
        }
    assert auth.RequestLoginHandler().handle(
        handler, auth.RequestLoginHandler.request_model.model_validate(handler.data)
    ).code == (202 if alternative else (403 if position == 0 else 401))
    if not alternative:
        assert handler.response["data"] == {}
    with auth_sessions() as session:
        login = session.get(UserAuthPolicy, (user_id, "login"))
        assert login.chains == legacy_chains
        assert login.revision == 1
        assert session.get(UserTotpCredential, user_id).verify(codes[0])
        assert session.get(User, user_id).last_login is None


@pytest.mark.parametrize("purpose", [AuthPurpose.MFA, AuthPurpose.ESCALATION])
@pytest.mark.parametrize("backup", [False, True], ids=["totp", "backup-code"])
def test_totp_remains_usable_for_mfa_and_escalation(
    login_context, auth_sessions, purpose, backup
):
    user_id, secret, codes, _ = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        credential = session.get(UserTotpCredential, user_id)
        replace_auth_policy(
            session,
            user,
            purpose,
            [[{"method": "totp", "credential_ids": [credential.credential_id]}]],
            expected_revision=1 if purpose == AuthPurpose.MFA else 0,
        )
        result = auth_registry.get("totp").verify(
            session,
            user,
            {"token": codes[0] if backup else pyotp.TOTP(secret).now()},
            {},
        )
        assert result.success
        assert result.credential_id == credential.credential_id
        decision = auth_registry.evaluate_user_policy(
            session,
            user,
            purpose,
            [
                AuthEvidence(
                    user_id=user_id,
                    attempt_id="attempt",
                    method="totp",
                    credential_id=result.credential_id,
                )
            ],
            attempt_id="attempt",
        )
        assert decision.satisfied
    with auth_sessions() as session:
        assert session.get(UserTotpCredential, user_id).verify(codes[0]) is (not backup)


def test_rehash_preserves_forced_marker_and_commits_before_post_auth(
    login_context, auth_sessions
):
    user_id, _, codes, signing_key = login_context
    with auth_sessions.begin() as session:
        credential = session.get(UserPasswordCredential, user_id)
        credential.pass_hash = PasswordHasher(time_cost=1).hash("Password123!")
        credential.passwd_last_modified = 0
    login = password_login()
    assert (
        auth.RequestLoginHandler()
        .handle(
            login, auth.RequestLoginHandler.request_model.model_validate(login.data)
        )
        .code
        == 202
    )
    with auth_sessions() as session:
        credential = session.get(UserPasswordCredential, user_id)
        assert not credential.check_needs_rehash()
        assert credential.passwd_last_modified == 0
    assert complete_with_backup(login, signing_key, codes[0]).response["code"] == 4002


def test_accepted_backup_code_is_consumed_when_policy_cannot_finish(
    login_context, auth_sessions
):
    user_id, _, codes, signing_key = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        mfa = session.get(UserAuthPolicy, (user_id, "mfa"))
        replace_auth_policy(
            session, user, AuthPurpose.MFA, [mfa.chains[0] * 2], expected_revision=1
        )
    login = password_login()
    assert (
        auth.RequestLoginHandler()
        .handle(
            login, auth.RequestLoginHandler.request_model.model_validate(login.data)
        )
        .code
        == 202
    )
    complete = complete_with_backup(login, signing_key, codes[0])
    assert complete.response["code"] == 403
    assert "token" not in complete.response["data"]
    with auth_sessions() as session:
        assert not session.get(UserTotpCredential, user_id).verify(codes[0])
        assert session.get(User, user_id).last_login is None


@pytest.mark.parametrize("purpose", [TokenPurpose.AUTH, TokenPurpose.POST_AUTH])
def test_http_rejects_authentication_tokens(
    login_context, auth_sessions, monkeypatch, purpose
):
    from fastapi import HTTPException

    from include.extensions.http_api import security

    monkeypatch.setattr(security, "Session", auth_sessions)
    user_id, _, codes, signing_key = login_context
    with auth_sessions.begin() as session:
        session.get(UserPasswordCredential, user_id).passwd_last_modified = 0
    login = password_login()
    auth.RequestLoginHandler().handle(
        login, auth.RequestLoginHandler.request_model.model_validate(login.data)
    )
    response = (
        login
        if purpose == TokenPurpose.AUTH
        else complete_with_backup(login, signing_key, codes[0])
    )
    with pytest.raises(HTTPException) as error:
        security._principal_from_token(response.response["data"]["token"])
    assert error.value.status_code == 401


def test_concurrent_backup_code_verification_has_one_winner(
    login_context, auth_sessions, monkeypatch
):
    _, _, codes, signing_key = login_context
    login = password_login()
    auth.RequestLoginHandler().handle(
        login, auth.RequestLoginHandler.request_model.model_validate(login.data)
    )
    original = UserTotpCredential.verify
    barrier = threading.Barrier(2)
    results, errors = [], []

    def competing_verify(credential, value):
        result = original(credential, value)
        barrier.wait(timeout=5)
        return result

    def worker():
        try:
            results.append(
                complete_with_backup(login, signing_key, codes[0]).response["code"]
            )
        except Exception as exc:  # noqa: BLE001 -- propagate worker failures to the test thread
            errors.append(exc)

    monkeypatch.setattr(UserTotpCredential, "verify", competing_verify)
    workers = [threading.Thread(target=worker) for _ in range(2)]
    for thread in workers:
        thread.start()
    for thread in workers:
        thread.join(timeout=10)
        assert not thread.is_alive()
    assert errors == []
    assert sorted(results) == [200, 401]


def test_public_key_proof_cannot_be_replayed_on_another_stream(
    login_context, auth_sessions
):
    user_id, _, _, _ = login_context
    with auth_sessions.begin() as session:
        key_id, fingerprint, private = register_key(session, user_id)
        replace_auth_policy(
            session,
            session.get(User, user_id),
            AuthPurpose.LOGIN,
            [[{"method": "publickey", "credential_ids": [key_id]}]],
            expected_revision=1,
        )
    proof = None

    def sign_once(message):
        nonlocal proof
        challenge = base64.b64decode(message["data"]["challenge"])
        if proof is None:
            proof = base64.b64encode(private.sign(challenge)).decode()
        return {
            "method": "publickey",
            "data": {"fingerprint": fingerprint, "signature": proof},
        }

    for stream_id, expected in ((1, 202), (3, 401)):
        handler = Handler(
            {
                "method": "publickey",
                "credential": {"username": "login", "fingerprint": fingerprint},
            }
        )
        handler.stream = DialogStream(sign_once)
        handler.stream.frame_id = stream_id
        assert (
            auth.RequestLoginHandler()
            .handle(
                handler,
                auth.RequestLoginHandler.request_model.model_validate(handler.data),
            )
            .code
            == expected
        )


@pytest.mark.parametrize("stage", [AuthPurpose.LOGIN, AuthPurpose.MFA])
def test_authentication_wait_has_no_idle_or_total_deadline(
    login_context, auth_sessions, monkeypatch, stage
):
    user_id, _, _, signing_key = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        key_id, fingerprint, private = register_key(session, user_id)
        replace_auth_policy(
            session,
            user,
            stage,
            [[{"method": "publickey", "credential_ids": [key_id]}]],
            expected_revision=1,
        )
        if stage == AuthPurpose.LOGIN:
            replace_auth_policy(session, user, AuthPurpose.MFA, [], expected_revision=1)
    if stage == AuthPurpose.LOGIN:
        handler = Handler(
            {
                "method": "publickey",
                "credential": {"username": "login", "fingerprint": fingerprint},
            }
        )
        request_handler = auth.RequestLoginHandler()
    else:
        login = password_login()
        assert (
            auth.RequestLoginHandler()
            .handle(
                login, auth.RequestLoginHandler.request_model.model_validate(login.data)
            )
            .code
            == 202
        )
        handler = Handler(
            {"method": "publickey", "data": {"fingerprint": fingerprint}},
            Token.from_raw(login.response["data"]["token"], signing_key),
        )
        request_handler = auth.RequestExchangeTokenHandler()
    now = [time.time()]
    monkeypatch.setattr(flows, "time", SimpleNamespace(time=lambda: now[0]))

    def reply(message):
        now[0] += 301
        return {
            "method": "publickey",
            "data": {
                "fingerprint": fingerprint,
                "signature": base64.b64encode(
                    private.sign(base64.b64decode(message["data"]["challenge"]))
                ).decode(),
            },
        }

    handler.stream = DialogStream(reply)
    assert (
        request_handler.handle(
            handler, request_handler.request_model.model_validate(handler.data)
        ).code
        == 200
    )
    assert handler.stream.timeouts == [None]


@pytest.mark.parametrize("interaction", ["challenge", "continuation"])
def test_mfa_rechecks_auth_expiry_after_wait_before_verifying(
    login_context, auth_sessions, monkeypatch, interaction
):
    user_id, _, _, signing_key = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        keys = [register_key(session, user_id) for _ in range(2)]
        replace_auth_policy(
            session,
            user,
            AuthPurpose.MFA,
            [[{"method": "publickey", "credential_ids": [key[0]]} for key in keys]],
            expected_revision=1,
        )
    login = password_login()
    assert (
        auth.RequestLoginHandler()
        .handle(
            login, auth.RequestLoginHandler.request_model.model_validate(login.data)
        )
        .code
        == 202
    )
    token = Token.from_raw(login.response["data"]["token"], signing_key)
    now = [time.time()]
    token.exp = now[0] + 12
    monkeypatch.setattr(flows, "time", SimpleNamespace(time=lambda: now[0]))

    def reply(message):
        if message["action"] == "auth_continue":
            now[0] += 13
            return {"method": "publickey", "data": {"fingerprint": keys[1][1]}}
        if interaction == "challenge":
            now[0] += 13
        return {
            "method": "publickey",
            "data": {
                "fingerprint": keys[0][1],
                "signature": base64.b64encode(
                    keys[0][2].sign(base64.b64decode(message["data"]["challenge"]))
                ).decode(),
            },
        }

    handler = Handler(
        {"method": "publickey", "data": {"fingerprint": keys[0][1]}}, token
    )
    handler.stream = DialogStream(reply)
    result = auth.RequestExchangeTokenHandler().handle(
        handler,
        auth.RequestExchangeTokenHandler.request_model.model_validate(handler.data),
    )
    assert result.code == 401
    assert result.user_id == user_id
    assert "token" not in handler.response["data"]
    with auth_sessions() as session:
        assert (
            session.get(UserAuthPublicKey, keys[0][0]).last_used_time is not None
        ) is (interaction == "continuation")
        assert session.get(UserAuthPublicKey, keys[1][0]).last_used_time is None
        assert session.get(User, user_id).last_login is None


def test_mfa_rejects_expired_auth_token_without_consuming_backup_code(
    login_context, auth_sessions
):
    user_id, _, codes, signing_key = login_context
    login = password_login()
    assert (
        auth.RequestLoginHandler()
        .handle(
            login, auth.RequestLoginHandler.request_model.model_validate(login.data)
        )
        .code
        == 202
    )
    token = Token.from_raw(login.response["data"]["token"], signing_key)
    token.exp = time.time() - 1
    handler = Handler({"method": "totp", "data": {"token": codes[0]}}, token)

    result = auth.RequestExchangeTokenHandler().handle(
        handler,
        auth.RequestExchangeTokenHandler.request_model.model_validate(handler.data),
    )

    assert result.code == 401
    assert result.target == "login"
    assert result.user_id == user_id
    assert handler.response["code"] == 401
    assert handler.response["data"] == {}
    with auth_sessions() as session:
        assert session.get(User, user_id).last_login is None
        assert session.get(UserTotpCredential, user_id).verify(codes[0])


@pytest.mark.parametrize(
    ("source", "target"),
    [
        (TokenPurpose.AUTH, 6),
        (TokenPurpose.GENERAL, 2),
        (TokenPurpose.POST_AUTH, 2),
        (TokenPurpose.GENERAL | TokenPurpose.ESCALATION, 6),
    ],
)
def test_mfa_rejects_cross_purpose_exchanges(
    login_context, auth_sessions, source, target
):
    user_id, _, codes, signing_key = login_context
    token = Token.new(user_id, 60, signing_key, source)
    handler = Handler(
        {"method": "totp", "data": {"token": codes[0]}, "target_purpose": target}, token
    )
    assert (
        auth.RequestExchangeTokenHandler()
        .handle(
            handler,
            auth.RequestExchangeTokenHandler.request_model.model_validate(handler.data),
        )
        .code
        == 403
    )
    with auth_sessions() as session:
        assert session.get(UserTotpCredential, user_id).verify(codes[0])


@pytest.mark.parametrize("method", ["password", "publickey", "totp"])
def test_escalation_uses_its_own_policy_and_new_expiry(
    login_context, auth_sessions, method
):
    user_id, _, codes, signing_key = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        user.last_login = 10
        if method == "password":
            credential_id = session.get(UserPasswordCredential, user_id).credential_id
            data = {"password": "Password123!"}
        elif method == "totp":
            credential_id = session.get(UserTotpCredential, user_id).credential_id
            data = {"token": codes[0]}
        else:
            credential_id, fingerprint, private = register_key(session, user_id)
            data = {"fingerprint": fingerprint}
        replace_auth_policy(
            session,
            user,
            AuthPurpose.ESCALATION,
            [[{"method": method, "credential_ids": [credential_id]}]],
            expected_revision=0,
        )
    source = Token.new(user_id, 20, signing_key)
    handler = Handler({"method": method, "data": data, "target_purpose": 6}, source)
    if method == "publickey":

        def reply(message):
            challenge = base64.b64decode(message["data"]["challenge"])
            assert orjson.loads(challenge)["stage"] == "escalation"
            return {
                "method": method,
                "data": {
                    "fingerprint": fingerprint,
                    "signature": base64.b64encode(private.sign(challenge)).decode(),
                },
            }

        handler.stream = DialogStream(reply)
    assert (
        auth.RequestExchangeTokenHandler()
        .handle(
            handler,
            auth.RequestExchangeTokenHandler.request_model.model_validate(handler.data),
        )
        .code
        == 200
    )
    token = Token.from_raw(handler.response["data"]["token"], signing_key)
    assert token.purpose == TokenPurpose.GENERAL | TokenPurpose.ESCALATION
    assert handler.response["data"]["purpose"] == 6
    assert token.exp - token.iat == ESCALATION_TOKEN_EXPIRY_SECONDS
    assert token.exp > source.exp
    assert token.auth_context is None
    with auth_sessions() as session:
        user = session.get(User, user_id)
        assert user.last_login == 10
        assert user.all_permissions == set()
    refreshed = Handler({}, token)
    assert (
        auth.RequestRefreshTokenHandler()
        .handle(
            refreshed,
            auth.RequestRefreshTokenHandler.request_model.model_validate(
                refreshed.data
            ),
        )
        .code
        == 0
    )
    assert (
        Token.from_raw(refreshed.response["data"]["token"], signing_key).purpose
        == TokenPurpose.GENERAL
    )
    assert refreshed.response["data"]["purpose"] == 2


@pytest.mark.parametrize("policy", [None, []])
def test_escalation_without_a_policy_needs_no_further_proof(
    login_context, auth_sessions, policy
):
    user_id, _, codes, signing_key = login_context
    if policy is not None:
        with auth_sessions.begin() as session:
            replace_auth_policy(
                session,
                session.get(User, user_id),
                AuthPurpose.ESCALATION,
                policy,
                expected_revision=0,
            )
    handler = Handler(
        {"method": "totp", "data": {"token": codes[0]}, "target_purpose": 6},
        Token.new(user_id, 60, signing_key),
    )
    assert (
        auth.RequestExchangeTokenHandler()
        .handle(
            handler,
            auth.RequestExchangeTokenHandler.request_model.model_validate(handler.data),
        )
        .code
        == 200
    )
    token = Token.from_raw(handler.response["data"]["token"], signing_key)
    assert token.purpose == TokenPurpose.GENERAL | TokenPurpose.ESCALATION
    assert token.exp - token.iat == ESCALATION_TOKEN_EXPIRY_SECONDS
    with auth_sessions() as session:
        assert session.get(UserTotpCredential, user_id).verify(codes[0])


@pytest.mark.parametrize("missing", ["method", "data", "both"])
def test_login_mfa_still_requires_method_and_data(
    login_context, auth_sessions, missing
):
    user_id, _, codes, signing_key = login_context
    login = password_login()
    assert (
        auth.RequestLoginHandler()
        .handle(
            login, auth.RequestLoginHandler.request_model.model_validate(login.data)
        )
        .code
        == 202
    )
    token = Token.from_raw(login.response["data"]["token"], signing_key)
    data = {"method": "totp", "data": {"token": codes[0]}, "target_purpose": 2}
    for field in ("method", "data") if missing == "both" else (missing,):
        data.pop(field)
    handler = Handler(data, token)
    assert (
        auth.RequestExchangeTokenHandler()
        .handle(
            handler,
            auth.RequestExchangeTokenHandler.request_model.model_validate(handler.data),
        )
        .code
        == 400
    )
    assert "token" not in handler.response["data"]
    with auth_sessions() as session:
        assert session.get(UserTotpCredential, user_id).verify(codes[0])


@pytest.mark.parametrize("purpose", list(AuthPurpose))
def test_registered_extension_method_uses_the_same_entrypoints(
    login_context, auth_sessions, monkeypatch, purpose
):
    class ExtensionMethod(password_provider.PasswordAuthProvider):
        method_id = "extension-proof"
        throttle_factor = "extension-factor"

    provider = ExtensionMethod()
    monkeypatch.setattr(
        auth_registry,
        "_providers",
        {**auth_registry._providers, provider.method_id: provider},
    )
    user_id, _, _, signing_key = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        credential = session.get(UserPasswordCredential, user_id)
        replace_auth_policy(
            session,
            user,
            purpose,
            [
                [
                    {
                        "method": provider.method_id,
                        "credential_ids": [credential.credential_id],
                    }
                ]
            ],
            expected_revision=0 if purpose == AuthPurpose.ESCALATION else 1,
        )
        if purpose == AuthPurpose.LOGIN:
            replace_auth_policy(session, user, AuthPurpose.MFA, [], expected_revision=1)
    factors = []
    monkeypatch.setattr(
        flows.LoginGuard,
        "evaluate",
        lambda ip, username, factor: (
            factors.append(factor) or SimpleNamespace(allowed=True)
        ),
    )
    if purpose == AuthPurpose.LOGIN:
        handler = Handler(
            {
                "method": provider.method_id,
                "credential": {"username": "login", "password": "Password123!"},
            }
        )
        result = auth.RequestLoginHandler().handle(
            handler, auth.RequestLoginHandler.request_model.model_validate(handler.data)
        )
    else:
        if purpose == AuthPurpose.MFA:
            login = password_login()
            assert (
                auth.RequestLoginHandler()
                .handle(
                    login,
                    auth.RequestLoginHandler.request_model.model_validate(login.data),
                )
                .code
                == 202
            )
            token = Token.from_raw(login.response["data"]["token"], signing_key)
        else:
            token = Token.new(user_id, 60, signing_key)
        handler = Handler(
            {
                "method": provider.method_id,
                "data": {"password": "Password123!"},
                "target_purpose": 6 if purpose == AuthPurpose.ESCALATION else 2,
            },
            token,
        )
        result = auth.RequestExchangeTokenHandler().handle(
            handler,
            auth.RequestExchangeTokenHandler.request_model.model_validate(handler.data),
        )
    assert result.code == 200
    assert "extension-factor" in factors
    assert handler.response["data"]["purpose"] == (
        6 if purpose == AuthPurpose.ESCALATION else 2
    )


def test_password_login_never_enumerates_unrelated_extensions(
    login_context, auth_sessions, monkeypatch
):
    class UnrelatedMethod(password_provider.PasswordAuthProvider):
        method_id = "unused"

        def list_credentials(self, session, user):
            pytest.fail("Unrelated extension credentials must not be queried")

    monkeypatch.setattr(
        auth_registry,
        "_providers",
        {**auth_registry._providers, "unused": UnrelatedMethod()},
    )
    handler = password_login()
    request = auth.RequestLoginHandler.request_model.model_validate(handler.data)
    assert auth.RequestLoginHandler().handle(handler, request).code == 202


def test_login_rejects_totp_before_verification(login_context, auth_sessions):
    user_id, _, codes, _ = login_context
    handler = Handler(
        {"method": "totp", "credential": {"username": "login", "token": codes[0]}}
    )
    assert (
        auth.RequestLoginHandler()
        .handle(
            handler, auth.RequestLoginHandler.request_model.model_validate(handler.data)
        )
        .code
        == 403
    )
    with auth_sessions() as session:
        assert session.get(UserTotpCredential, user_id).verify(codes[0])


@pytest.mark.parametrize(
    "change", ["expiry", "signing_key", "policy", "revoked", "inactive"]
)
def test_escalation_rechecks_source_and_account_after_wait(
    login_context, auth_sessions, monkeypatch, change
):
    user_id, _, _, signing_key = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        key_id, fingerprint, private = register_key(session, user_id)
        replace_auth_policy(
            session,
            user,
            AuthPurpose.ESCALATION,
            [[{"method": "publickey", "credential_ids": [key_id]}]],
            expected_revision=0,
        )
    source = Token.new(user_id, 60, signing_key)
    now = [time.time()]
    monkeypatch.setattr(flows, "time", SimpleNamespace(time=lambda: now[0]))

    def reply(message):
        if change == "expiry":
            now[0] = source.exp + 1
        else:
            with auth_sessions.begin() as session:
                user = session.get(User, user_id)
                if change == "signing_key":
                    user.secret_key = "replacement-secret-key-for-authentication"
                elif change == "policy":
                    replace_auth_policy(
                        session, user, AuthPurpose.ESCALATION, [], expected_revision=1
                    )
                elif change == "revoked":
                    session.delete(session.get(UserAuthPublicKey, key_id))
                else:
                    user.status = UserStatus.DISABLED
        challenge = base64.b64decode(message["data"]["challenge"])
        return {
            "method": "publickey",
            "data": {
                "fingerprint": fingerprint,
                "signature": base64.b64encode(private.sign(challenge)).decode(),
            },
        }

    handler = Handler(
        {
            "method": "publickey",
            "data": {"fingerprint": fingerprint},
            "target_purpose": 6,
        },
        source,
    )
    handler.stream = DialogStream(reply)
    assert auth.RequestExchangeTokenHandler().handle(
        handler,
        auth.RequestExchangeTokenHandler.request_model.model_validate(handler.data),
    ).code == (4003 if change == "inactive" else 401)
    assert "token" not in handler.response["data"]
    with auth_sessions() as session:
        if change != "revoked":
            assert session.get(UserAuthPublicKey, key_id).last_used_time is None


def test_authentication_snapshots_and_payload_repr_hide_secrets():
    result = AuthVerificationResult(success=True, credential_id="credential")
    with pytest.raises(FrozenInstanceError):
        result.success = False
    with pytest.raises(ValueError, match="credential"):
        AuthVerificationResult(success=True)
    credential = password_provider.PasswordCredentialSchema(
        username="alice", password="private-password"
    )
    assert "private-password" not in repr(credential)
    proof = publickey.PublicKeyCredentialSchema(
        fingerprint="fingerprint", signature="private-signature"
    )
    assert "private-signature" not in repr(proof)
    response = flows.AuthenticationResponse(
        action="auth_response",
        interaction_id="interaction",
        method="extension",
        data={"secret": "private-proof"},
    )
    assert "private-proof" not in repr(response)
