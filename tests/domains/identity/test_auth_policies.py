import uuid
from types import SimpleNamespace

import jwt
import pyotp
import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import sessionmaker

from include.database.models.auth import (
    UserAuthPolicy,
    UserAuthPublicKey,
    UserPasswordCredential,
    UserTotpCredential,
)
from include.database.models.identity import User
from include.database.session import Base
from include.domains.identity.auth import auth_registry
from include.domains.identity.auth.flows import (
    get_login_progress,
    start_login_attempt,
)
from include.domains.identity.auth.policies import evaluate_auth_policy
from include.domains.identity.auth.types import (
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

pytestmark = pytest.mark.component


@pytest.fixture
def auth_sessions(sqlite_engine_factory):
    engine = sqlite_engine_factory()
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
        assert start_login_attempt(session, user, "password", credential_id) is not None
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
            start_login_attempt(session, user, "password", replacement.credential_id)
            is None
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
    monkeypatch.setattr(auth, "Session", auth_sessions)
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
        self.data = data
        self.token = token
        self.user_id = token.sub if token else None
        self.stream = SimpleNamespace(connection=SimpleNamespace(_ws=None))
        self.response = None

    def conclude_request(self, code, data=None, message=None):
        self.response = {"code": code, "data": data or {}, "message": message}


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
    assert auth.RequestLoginHandler().handle(handler).code == 202
    token = Token.from_raw(handler.response["data"]["token"], signing_key)
    assert token.auth_context is not None
    assert codes[0] not in token.raw
    complete = Handler({"method": "totp", "data": {"token": codes[0]}}, token)
    assert auth.RequestCompleteMFAHandler().handle(complete).code == 200
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
    assert auth.RequestLoginHandler().handle(handler).code == 200
    with auth_sessions.begin() as session:
        replace_auth_policy(
            session,
            session.get(User, user_id),
            AuthPurpose.LOGIN,
            [],
            expected_revision=1,
        )
    assert auth.RequestLoginHandler().handle(handler).code == 401
    assert "token" not in handler.response["data"]


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
    auth.RequestLoginHandler().handle(handler)
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
    assert auth.RequestCompleteMFAHandler().handle(complete).code in {401, 403}
    assert "token" not in complete.response["data"]


def test_login_chain_evidence_can_also_satisfy_mfa(login_context, auth_sessions):
    user_id, _, _, _ = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        login = session.get(UserAuthPolicy, (user_id, "login"))
        mfa = session.get(UserAuthPolicy, (user_id, "mfa"))
        replace_auth_policy(
            session,
            user,
            AuthPurpose.LOGIN,
            [login.chains[0] + mfa.chains[0]],
            expected_revision=login.revision,
        )
        password = session.get(UserPasswordCredential, user_id)
        context = start_login_attempt(session, user, "password", password.credential_id)
        assert [
            s.method for s in get_login_progress(session, user, context).next_steps
        ] == ["totp"]
        context = context.model_copy(
            update={
                "evidence": [
                    *context.evidence,
                    AuthEvidence(
                        user_id=user_id,
                        attempt_id=context.attempt_id,
                        method="totp",
                        credential_id=session.get(
                            UserTotpCredential, user_id
                        ).credential_id,
                    ),
                ]
            }
        )
        assert get_login_progress(session, user, context).satisfied


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
    assert RequestValidate2FAHandler().handle(handler).code == 401
    assert responses == [((401, {}, "Invalid verification code"), {})]
    handler.data["token"] = pyotp.TOTP(secret).now()
    responses.clear()
    assert RequestValidate2FAHandler().handle(handler).code == 0
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


def test_verified_password_cannot_skip_unimplemented_chain_steps(
    login_context, auth_sessions
):
    user_id, _, _, _ = login_context
    with auth_sessions.begin() as session:
        user = session.get(User, user_id)
        key = UserAuthPublicKey(
            user_id=user_id, public_key_der=b"key", fingerprint=b"k" * 32
        )
        session.add(key)
        session.flush()
        login = session.get(UserAuthPolicy, (user_id, "login"))
        replace_auth_policy(
            session,
            user,
            AuthPurpose.LOGIN,
            [
                login.chains[0]
                + [
                    {
                        "method": "publickey",
                        "credential_ids": [key.id],
                    }
                ]
            ],
            expected_revision=login.revision,
        )
    handler = Handler(
        {
            "method": "password",
            "credential": {"username": "login", "password": "Password123!"},
        }
    )
    assert auth.RequestLoginHandler().handle(handler).code == 403
    assert handler.response["data"] == {}


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
