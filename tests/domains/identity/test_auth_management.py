import hashlib
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import orjson
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
from sqlalchemy import delete, event
from sqlalchemy.orm import sessionmaker

from include.config.constants import ESCALATION_TOKEN_EXPIRY_SECONDS
from include.database.models.auth import (
    UserAuthPolicy,
    UserAuthPublicKey,
    UserPasswordCredential,
    UserTotpCredential,
)
from include.database.models.identity import User, UserPermission, UserStatus
from include.database.session import Base
from include.domains.access.permissions import Permissions
from include.domains.identity.auth import registry
from include.domains.identity.auth.base import BaseAuthMethodProvider
from include.domains.identity.auth.flows import (
    create_authentication_context,
    get_login_progress,
)
from include.domains.identity.auth.providers.password import PasswordAuthProvider
from include.domains.identity.auth.types import (
    AuthPurpose,
    InvalidAuthenticationAttempt,
)
from include.domains.identity.commands.auth_policies import replace_auth_policy
from include.domains.identity.commands.credentials import set_password, setup_totp
from include.domains.identity.handlers import auth, auth_management, users
from include.domains.identity.tokens import Token, TokenPurpose
from include.domains.operations.commands import audit
from include.domains.security.guards import replay
from include.providers.caching.memory import MemoryCachingProvider
from include.transport import router

pytestmark = pytest.mark.component

HANDLERS = {
    "get": auth_management.RequestGetUserAuthenticationHandler,
    "password": users.RequestSetPasswdHandler,
    "set": auth_management.RequestSetUserAuthPoliciesHandler,
    "register": auth_management.RequestRegisterUserAuthPublicKeyHandler,
    "update": auth_management.RequestUpdateUserAuthPublicKeyHandler,
    "delete": auth_management.RequestDeleteUserAuthPublicKeyHandler,
}


class Handler:
    def __init__(self, data, token):
        self.data = data
        self.token = token
        self.user_id = token.sub if token else None
        self.response = None

    def conclude_request(self, code, data=None, message=None):
        self.response = {"code": code, "data": data or {}}


def policy(purpose, chains, revision=0):
    return {"purpose": purpose, "expected_revision": revision, "chains": chains}


def chain(method, *credential_ids):
    return [{"method": method, "credential_ids": list(credential_ids)}]


def ssh_key(private=None):
    private = private or ed25519.Ed25519PrivateKey.generate()
    return (
        private.public_key()
        .public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        .decode()
    )


@pytest.fixture
def management(sqlite_engine_factory, tmp_path, monkeypatch):
    engine = sqlite_engine_factory(tmp_path / "management.db", timeout_seconds=10)
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(auth_management, "Session", sessions)
    monkeypatch.setattr(auth, "Session", sessions)
    monkeypatch.setattr(users, "Session", sessions)
    with sessions.begin() as session:
        user = User(username="owner", last_login=10)
        other = User(username="other")
        session.add_all([user, other])
        session.flush()
        for account in (user, other):
            set_password(session, account, "Password123!")
            session.flush()
            credential = session.get(UserPasswordCredential, account.id)
            replace_auth_policy(
                session,
                account,
                AuthPurpose.LOGIN,
                [chain("password", credential.credential_id)],
                expected_revision=0,
            )
        session.add(
            UserPermission(
                user_id=user.id,
                permission=Permissions.CONFIGURE_AUTH_METHODS,
                granted=True,
                start_time=0,
            )
        )
        setup_totp(session, user)
        session.flush()
        user_id, other_id = user.id, other.id
        password_id = session.get(UserPasswordCredential, user.id).credential_id
        signing_key = user.secret_key
    token = Token.new(
        user_id, 60, signing_key, TokenPurpose.GENERAL | TokenPurpose.ESCALATION
    )

    def call(action, data=None, *, source=token):
        handler = Handler(data or {}, source)
        result = HANDLERS[action]().handle(
            handler, HANDLERS[action].request_model.model_validate(handler.data)
        )
        assert result.code == handler.response["code"]
        handler.result = result
        return handler

    return SimpleNamespace(
        sessions=sessions,
        call=call,
        user_id=user_id,
        other_id=other_id,
        password_id=password_id,
        signing_key=signing_key,
        token=token,
    )


def test_inventory_contains_registered_pending_credentials_without_secrets(management):
    response = management.call("get").response
    assert response["code"] == 200
    data = response["data"]
    assert data["user_id"] == str(management.user_id)
    assert data["methods"]["totp"]["purposes"] == ["escalation", "mfa"]
    assert {c["method"]: c["active"] for c in data["credentials"]} == {
        "password": True,
        "totp": False,
    }
    assert data["policies"]["escalation"] == {"revision": 0, "chains": []}
    assert data["policies"]["mfa"] == {"revision": 0, "chains": []}
    assert data["policies"]["login"]["revision"] == 1
    with management.sessions() as session:
        credential = session.get(UserTotpCredential, management.user_id)
        password = session.get(UserPasswordCredential, management.user_id)
        serialized = orjson.dumps(data)
        assert credential.secret.encode() not in serialized
        assert password.pass_hash.encode() not in serialized
        assert management.signing_key.encode() not in serialized


@pytest.mark.parametrize(
    ("action", "data"),
    [
        ("set", {"policies": [policy("mfa", [])]}),
        ("register", {"public_key": "invalid"}),
        ("update", {"credential_id": "missing", "label": None}),
        ("delete", {"credential_id": "missing"}),
    ],
)
def test_mutations_require_escalation(management, action, data):
    ordinary = Token.new(management.user_id, 60, management.signing_key)
    assert management.call(action, data, source=ordinary).response["code"] == 403


def test_unauthenticated_inventory_is_rejected(management):
    assert management.call("get", source=None).response["code"] == 401


@pytest.mark.parametrize("exists", [False, True])
def test_cross_user_access_checks_permission_before_existence(management, exists):
    target = management.other_id if exists else uuid.uuid4()
    for action, data in (("get", {}), ("register", {"public_key": ssh_key()})):
        request = management.call(action, {**data, "user_id": str(target)})
        assert request.response["code"] == 403
        assert request.result.target == str(target)
    with management.sessions.begin() as session:
        session.add(
            UserPermission(
                user_id=management.user_id,
                permission=Permissions.SUPER_CONFIGURE_AUTH_METHODS,
                granted=True,
                start_time=0,
            )
        )
    with management.sessions.begin() as session:
        session.add(
            UserPermission(
                user_id=management.user_id,
                permission=Permissions.SUPER_LIST_USER_AUTH_METHODS,
                granted=True,
                start_time=0,
            )
        )
    assert management.call("get", {"user_id": str(target)}).response["code"] == (
        200 if exists else 404
    )
    registered = management.call(
        "register", {"user_id": str(target), "public_key": ssh_key()}
    )
    assert registered.response["code"] == (200 if exists else 404)
    if exists:
        key_id = registered.response["data"]["credential_id"]
        with management.sessions() as session:
            assert (
                session.get(
                    UserAuthPublicKey, registered.response["data"]["credential_id"]
                ).user_id
                == target
            )
        for action, data in (
            ("set", {"policies": [policy("mfa", [])]}),
            ("update", {"credential_id": key_id, "label": "admin label"}),
            ("delete", {"credential_id": key_id}),
        ):
            assert (
                management.call(action, {**data, "user_id": str(target)}).response[
                    "code"
                ]
                == 200
            )


@pytest.mark.parametrize("kind", ["ed25519", "rsa", "ecdsa"])
def test_registration_canonicalizes_keys_and_grants_no_policy(management, kind):
    private = (
        rsa.generate_private_key(public_exponent=65537, key_size=2048)
        if kind == "rsa"
        else ec.generate_private_key(ec.SECP256R1())
        if kind == "ecdsa"
        else ed25519.Ed25519PrivateKey.generate()
    )
    public_key = ssh_key(private)
    request = management.call(
        "register", {"public_key": public_key + " label@host", "label": "laptop"}
    )
    assert request.response["code"] == 200
    data = request.response["data"]
    assert data["fingerprint"] == hashlib.sha256(public_key.encode()).hexdigest()
    with management.sessions() as session:
        credential = session.get(UserAuthPublicKey, data["credential_id"])
        assert credential.public_key_der == private.public_key().public_bytes(
            Encoding.DER, PublicFormat.SubjectPublicKeyInfo
        )
        assert credential.label == "laptop"
        assert session.get(UserAuthPolicy, (management.user_id, "login")).chains == [
            chain("password", management.password_id)
        ]
    assert request.result.data["credential_id"] == data["credential_id"]
    assert "public_key" not in request.result.data
    duplicate = management.call("register", {"public_key": public_key})
    assert duplicate.response["code"] == 409
    assert duplicate.response["data"]["reason"] == "duplicate_public_key"


@pytest.mark.parametrize(
    "public_key", ["invalid", "ssh-ed25519 !!!", "-----BEGIN PRIVATE KEY-----"]
)
def test_invalid_keys_are_rejected(management, public_key):
    response = management.call("register", {"public_key": public_key}).response
    assert response["code"] == 400
    assert response["data"]["reason"] == "invalid_public_key"


def test_labels_and_deletion_are_scoped_to_target_user(management):
    registered = management.call("register", {"public_key": ssh_key()}).response["data"]
    key_id = registered["credential_id"]
    for label in ("renamed", None):
        response = management.call(
            "update", {"credential_id": key_id, "label": label}
        ).response
        assert response["code"] == 200
        assert response["data"]["label"] == label
        with management.sessions() as session:
            assert session.get(UserAuthPublicKey, key_id).label == label
    with management.sessions.begin() as session:
        session.add(
            UserPermission(
                user_id=management.user_id,
                permission=Permissions.SUPER_CONFIGURE_AUTH_METHODS,
                granted=True,
                start_time=0,
            )
        )
    for action, data in (("update", {"label": None}), ("delete", {})):
        response = management.call(
            action,
            {**data, "user_id": str(management.other_id), "credential_id": key_id},
        ).response
        assert response["code"] == 404
    assert management.call("delete", {"credential_id": key_id}).response["code"] == 200
    assert management.call("delete", {"credential_id": key_id}).response["code"] == 404


def test_batch_policy_updates_are_atomic_and_revision_checked(management):
    password = chain("password", management.password_id)
    response = management.call(
        "set",
        {
            "policies": [
                policy("mfa", []),
                policy("escalation", [password], revision=1),
            ]
        },
    ).response
    assert response["code"] == 409
    assert response["data"]["reason"] == "revision_conflict"
    with management.sessions() as session:
        assert session.get(UserAuthPolicy, (management.user_id, "mfa")) is None
        assert session.get(UserAuthPolicy, (management.user_id, "escalation")) is None
    response = management.call(
        "set",
        {
            "policies": [
                policy("mfa", []),
                policy("escalation", [password]),
            ]
        },
    ).response
    assert response["code"] == 200
    assert response["data"]["policies"]["escalation"]["revision"] == 1
    response = management.call(
        "set",
        {"policies": [policy("escalation", [], 1), policy("mfa", [])]},
    ).response
    assert response["code"] == 409
    assert response["data"]["reason"] == "revision_conflict"
    with management.sessions() as session:
        escalation = session.get(UserAuthPolicy, (management.user_id, "escalation"))
        assert escalation.revision == 1
        assert escalation.chains == [password]


@pytest.mark.parametrize(
    "case", ["totp_login", "foreign", "unknown", "duplicate", "mixed"]
)
def test_invalid_policies_roll_back_earlier_changes(management, case):
    with management.sessions() as session:
        totp_id = session.get(UserTotpCredential, management.user_id).credential_id
        foreign_id = session.get(
            UserPasswordCredential, management.other_id
        ).credential_id
    password = chain("password", management.password_id)
    invalid = {
        "totp_login": chain("totp", totp_id),
        "foreign": chain("password", foreign_id),
        "unknown": chain("missing", management.password_id),
        "duplicate": chain("password", management.password_id, management.password_id),
        "mixed": password + chain("totp", totp_id),
    }[case]
    response = management.call(
        "set", {"policies": [policy("mfa", []), policy("login", [invalid], 1)]}
    ).response
    assert response["code"] == 400
    assert response["data"]["reason"] == "invalid_policy"
    with management.sessions() as session:
        assert session.get(UserAuthPolicy, (management.user_id, "mfa")) is None
        assert session.get(UserAuthPolicy, (management.user_id, "login")).revision == 1


@pytest.mark.parametrize(
    "case", ["empty_login", "same_method_mfa", "pending_totp", "repeated_password"]
)
def test_policy_updates_must_leave_a_complete_login_path(management, case):
    password = chain("password", management.password_id)
    with management.sessions() as session:
        totp_id = session.get(UserTotpCredential, management.user_id).credential_id
    update = {
        "empty_login": policy("login", [], 1),
        "same_method_mfa": policy("mfa", [password]),
        "pending_totp": policy("mfa", [chain("totp", totp_id)]),
        "repeated_password": policy("login", [password * 2], 1),
    }[case]
    response = management.call("set", {"policies": [update]}).response
    assert response["code"] == 409
    assert response["data"]["reason"] == "login_unavailable"
    assert management.call("get").response["data"]["policies"]["login"]["revision"] == 1


def test_pending_credentials_cannot_be_the_only_escalation_path(management):
    with management.sessions() as session:
        totp_id = session.get(UserTotpCredential, management.user_id).credential_id
    response = management.call(
        "set", {"policies": [policy("escalation", [chain("totp", totp_id)])]}
    ).response
    assert response["code"] == 409
    assert response["data"]["reason"] == "escalation_unavailable"


def test_one_complete_login_alternative_is_enough_and_mfa_can_be_cleared(management):
    key_id = management.call("register", {"public_key": ssh_key()}).response["data"][
        "credential_id"
    ]
    password = chain("password", management.password_id)
    response = management.call(
        "set",
        {
            "policies": [
                policy("login", [password, chain("publickey", key_id)], 1),
                policy("mfa", [password]),
            ]
        },
    ).response
    assert response["code"] == 200
    deleted = management.call("delete", {"credential_id": key_id}).response
    assert deleted["code"] == 409
    assert deleted["data"]["reason"] == "login_unavailable"
    assert (
        management.call("set", {"policies": [policy("mfa", [], 1)]}).response["code"]
        == 200
    )
    assert management.call("delete", {"credential_id": key_id}).response["code"] == 200
    login = management.call("get").response["data"]["policies"]["login"]
    assert login["chains"] == [password]
    assert login["revision"] == 3


@pytest.mark.parametrize("purpose", ["login"])
def test_deleting_the_last_required_key_rolls_back(management, purpose):
    key_id = management.call("register", {"public_key": ssh_key()}).response["data"][
        "credential_id"
    ]
    assert (
        management.call(
            "set",
            {
                "policies": [
                    policy(
                        purpose,
                        [chain("publickey", key_id)],
                        1 if purpose == "login" else 0,
                    )
                ]
            },
        ).response["code"]
        == 200
    )
    response = management.call("delete", {"credential_id": key_id}).response
    assert response["code"] == 409
    assert response["data"]["reason"] == f"{purpose}_unavailable"
    with management.sessions() as session:
        assert session.get(UserAuthPublicKey, key_id) is not None


def test_multi_step_keys_require_a_distinct_assignment(management):
    key_ids = [
        management.call("register", {"public_key": ssh_key()}).response["data"][
            "credential_id"
        ]
        for _ in range(3)
    ]
    a, b, c = key_ids
    impossible = chain("publickey", a) * 2 + chain("publickey", b, c)
    assert (
        management.call(
            "set", {"policies": [policy("login", [impossible], 1)]}
        ).response["code"]
        == 409
    )
    possible = (
        chain("publickey", a, b) + chain("publickey", a) + chain("publickey", b, c)
    )
    assert (
        management.call("set", {"policies": [policy("login", [possible], 1)]}).response[
            "code"
        ]
        == 200
    )
    assert management.call("delete", {"credential_id": c}).response["code"] == 409


@pytest.mark.parametrize("mutation", ["policy", "delete"])
def test_competing_writes_cannot_remove_the_last_login_path(management, mutation):
    key_ids = [
        management.call("register", {"public_key": ssh_key()}).response["data"][
            "credential_id"
        ]
        for _ in range(2)
    ]
    assert (
        management.call(
            "set", {"policies": [policy("login", [chain("publickey", *key_ids)], 1)]}
        ).response["code"]
        == 200
    )
    barrier = threading.Barrier(2)
    results, errors = [], []

    def worker(key_id):
        try:
            barrier.wait(timeout=5)
            if mutation == "policy":
                request = management.call(
                    "set",
                    {"policies": [policy("login", [chain("publickey", key_id)], 2)]},
                )
            else:
                request = management.call("delete", {"credential_id": key_id})
            results.append(request.response["code"])
        except Exception as exc:  # noqa: BLE001 -- propagate worker failures to the test thread
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(key_id,)) for key_id in key_ids]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=15)
        assert not thread.is_alive()
    assert errors == []
    assert sorted(results) == [200, 409]


def test_extension_credentials_participate_in_inventory_and_policies(
    management, monkeypatch
):
    class ExtensionProvider(PasswordAuthProvider):
        method_id = "extension-proof"
        supported_purposes = frozenset({AuthPurpose.ESCALATION})

    provider: BaseAuthMethodProvider = ExtensionProvider()
    monkeypatch.setattr(
        registry.auth_registry,
        "_providers",
        {**registry.auth_registry._providers, provider.method_id: provider},
    )
    data = management.call("get").response["data"]
    assert data["methods"][provider.method_id]["purposes"] == ["escalation"]
    assert any(c["method"] == provider.method_id for c in data["credentials"])
    assert (
        management.call(
            "set",
            {
                "policies": [
                    policy(
                        "escalation",
                        [chain(provider.method_id, management.password_id)],
                    )
                ]
            },
        ).response["code"]
        == 200
    )
    assert (
        management.call(
            "set",
            {
                "policies": [
                    policy(
                        "login", [chain(provider.method_id, management.password_id)], 1
                    )
                ]
            },
        ).response["code"]
        == 400
    )


@pytest.mark.parametrize("policy_state", ["absent", "empty", "cleared"])
def test_no_policy_escalation_issues_short_lived_token_without_proof(
    management, policy_state
):
    source = Token.new(management.user_id, 60, management.signing_key)
    if policy_state == "cleared":
        configured = management.call(
            "set",
            {
                "policies": [
                    policy("escalation", [chain("password", management.password_id)])
                ]
            },
        ).response
        assert configured["code"] == 200
        denied = management.call(
            "set", {"policies": [policy("escalation", [], 1)]}, source=source
        ).response
        assert denied["code"] == 403
    if policy_state != "absent":
        revision = 1 if policy_state == "cleared" else 0
        cleared = management.call(
            "set", {"policies": [policy("escalation", [], revision)]}
        ).response
        assert cleared["code"] == 200
        assert cleared["data"]["policies"]["escalation"] == {
            "revision": revision + 1,
            "chains": [],
        }
        with management.sessions() as session:
            escalation = session.get(UserAuthPolicy, (management.user_id, "escalation"))
            assert escalation.revision == revision + 1
            assert escalation.chains == []
    handler = Handler({"target_purpose": TokenPurpose.GENERAL_WITH_ESCALATION}, source)
    assert (
        auth.RequestExchangeTokenHandler()
        .handle(
            handler,
            auth.RequestExchangeTokenHandler.request_model.model_validate(handler.data),
        )
        .code
        == 200
    )
    issued = Token.from_raw(handler.response["data"]["token"], management.signing_key)
    assert issued.purpose == TokenPurpose.GENERAL | TokenPurpose.ESCALATION
    assert issued.exp - issued.iat == ESCALATION_TOKEN_EXPIRY_SECONDS
    assert issued.auth_context is None
    with management.sessions() as session:
        user = session.get(User, management.user_id)
        assert user.last_login == 10
        assert user.all_permissions == {Permissions.CONFIGURE_AUTH_METHODS}
    refreshed = Handler({}, issued)
    auth.RequestRefreshTokenHandler().handle(
        refreshed,
        auth.RequestRefreshTokenHandler.request_model.model_validate(refreshed.data),
    )
    assert refreshed.response["data"]["purpose"] == TokenPurpose.GENERAL


@pytest.mark.parametrize(
    ("change", "expected"),
    [("expired", 401), ("rotated", 401), ("disabled", 4003), ("deleted", 401)],
)
def test_direct_escalation_rechecks_token_and_account(management, change, expected):
    source = Token.new(
        management.user_id, -1 if change == "expired" else 60, management.signing_key
    )
    with management.sessions.begin() as session:
        user = session.get(User, management.user_id)
        if change == "rotated":
            user.secret_key = "replacement-signing-key" * 2
        elif change == "disabled":
            user.status = UserStatus.DISABLED
        elif change == "deleted":
            session.delete(user)
    handler = Handler({"target_purpose": TokenPurpose.GENERAL_WITH_ESCALATION}, source)
    assert (
        auth.RequestExchangeTokenHandler()
        .handle(
            handler,
            auth.RequestExchangeTokenHandler.request_model.model_validate(handler.data),
        )
        .code
        == expected
    )
    assert "token" not in handler.response["data"]


@pytest.mark.parametrize(
    ("change", "expected"), [("signing_key", 401), ("policy", 400)]
)
def test_direct_escalation_rechecks_state_after_waiting_for_writer(
    management, change, expected
):
    source = Token.new(management.user_id, 60, management.signing_key)
    database = management.sessions.kw["bind"]
    waiting = threading.Event()

    @event.listens_for(database, "before_cursor_execute")
    def observe_lock(_conn, _cursor, statement, _params, _context, _many):
        if (
            threading.current_thread() is not threading.main_thread()
            and statement == "BEGIN IMMEDIATE"
        ):
            waiting.set()

    def exchange_token():
        handler = Handler(
            {"target_purpose": TokenPurpose.GENERAL_WITH_ESCALATION}, source
        )
        auth.RequestExchangeTokenHandler().handle(
            handler,
            auth.RequestExchangeTokenHandler.request_model.model_validate(handler.data),
        )
        return handler.response

    try:
        with (
            management.sessions() as writer,
            ThreadPoolExecutor(max_workers=1) as workers,
        ):
            user = writer.get(User, management.user_id, with_for_update=True)
            if change == "signing_key":
                user.secret_key = "replacement-signing-key" * 2
            else:
                replace_auth_policy(
                    writer,
                    user,
                    AuthPurpose.ESCALATION,
                    [chain("password", management.password_id)],
                    expected_revision=0,
                )
            writer.flush()
            result = workers.submit(exchange_token)
            try:
                assert waiting.wait(5)
            finally:
                writer.commit()
            response = result.result(timeout=10)
    finally:
        event.remove(database, "before_cursor_execute", observe_lock)
    assert response["code"] == expected
    assert "token" not in response["data"]


@pytest.mark.parametrize(
    "purpose",
    [
        TokenPurpose.AUTH,
        TokenPurpose.POST_AUTH,
        TokenPurpose.GENERAL | TokenPurpose.ESCALATION,
    ],
)
def test_direct_escalation_rejects_restricted_or_already_elevated_sources(
    management, purpose
):
    source = Token.new(management.user_id, 60, management.signing_key, purpose)
    handler = Handler({"target_purpose": TokenPurpose.GENERAL_WITH_ESCALATION}, source)
    assert (
        auth.RequestExchangeTokenHandler()
        .handle(
            handler,
            auth.RequestExchangeTokenHandler.request_model.model_validate(handler.data),
        )
        .code
        == 403
    )


@pytest.mark.parametrize("missing", ["method", "data", "both"])
def test_configured_escalation_requires_method_and_data(management, missing):
    assert (
        management.call(
            "set",
            {
                "policies": [
                    policy("escalation", [chain("password", management.password_id)])
                ]
            },
        ).response["code"]
        == 200
    )
    data = {
        "method": "password",
        "data": {"password": "Password123!"},
        "target_purpose": TokenPurpose.GENERAL_WITH_ESCALATION,
    }
    for field in ("method", "data") if missing == "both" else (missing,):
        data.pop(field)
    handler = Handler(data, Token.new(management.user_id, 60, management.signing_key))
    assert (
        auth.RequestExchangeTokenHandler()
        .handle(
            handler,
            auth.RequestExchangeTokenHandler.request_model.model_validate(handler.data),
        )
        .code
        == 400
    )


@pytest.mark.parametrize(
    ("action", "data"),
    [
        ("set", {"policies": [policy("mfa", [])]}),
        ("register", {"public_key": "invalid"}),
        ("update", {"credential_id": "missing", "label": None}),
        ("delete", {"credential_id": "missing"}),
        ("password", {"new_passwd": "UpdatedPassword456!"}),
    ],
)
def test_self_mutations_require_configuration_permission(management, action, data):
    with management.sessions.begin() as session:
        session.execute(
            delete(UserPermission).where(UserPermission.user_id == management.user_id)
        )
    response = management.call(action, data).response
    assert response["code"] == 403
    assert management.call("get").response["code"] == 200
    with management.sessions() as session:
        assert session.get(UserPasswordCredential, management.user_id).verify(
            "Password123!"
        )
        assert session.get(UserAuthPolicy, (management.user_id, "mfa")) is None


@pytest.mark.parametrize(
    ("permission", "write_code"),
    [
        (Permissions.CONFIGURE_AUTH_METHODS, 403),
        (Permissions.SUPER_CONFIGURE_AUTH_METHODS, 200),
        (Permissions.SUPER_LIST_USER_AUTH_METHODS, 403),
    ],
)
def test_super_configuration_covers_self_without_ordinary_permission(
    management, permission, write_code
):
    with management.sessions.begin() as session:
        session.execute(
            delete(UserPermission).where(UserPermission.user_id == management.user_id)
        )
        session.add(
            UserPermission(
                user_id=management.user_id,
                permission=permission,
                granted=True,
                start_time=0,
            )
        )
    assert management.call("get").response["code"] == 200
    response = management.call("register", {"public_key": ssh_key()}).response
    assert response["code"] == (
        200 if permission != Permissions.SUPER_LIST_USER_AUTH_METHODS else 403
    )
    other = {"user_id": str(management.other_id)}
    assert management.call("get", other).response["code"] == (
        200 if permission == Permissions.SUPER_LIST_USER_AUTH_METHODS else 403
    )
    assert (
        management.call("register", {**other, "public_key": ssh_key()}).response["code"]
        == write_code
    )


@pytest.mark.parametrize("target", ["self", "other"])
@pytest.mark.parametrize(
    "purpose", [TokenPurpose.ESCALATION, TokenPurpose.GENERAL_WITH_ESCALATION]
)
@pytest.mark.parametrize(
    "permission",
    [
        None,
        Permissions.CONFIGURE_AUTH_METHODS,
        Permissions.SUPER_CONFIGURE_AUTH_METHODS,
    ],
)
def test_elevated_password_configuration_uses_ids_and_rotates_tokens(
    management, target, purpose, permission
):
    with management.sessions.begin() as session:
        session.execute(
            delete(UserPermission).where(UserPermission.user_id == management.user_id)
        )
        if permission is not None:
            session.add(
                UserPermission(
                    user_id=management.user_id,
                    permission=permission,
                    granted=True,
                    start_time=0,
                )
            )
    target_id = management.user_id if target == "self" else management.other_id
    data = {"new_passwd": "UpdatedPassword456!"}
    if target == "other":
        data["user_id"] = str(target_id)
    source = Token.new(management.user_id, 60, management.signing_key, purpose)
    result = management.call("password", data, source=source)
    allowed = permission == Permissions.SUPER_CONFIGURE_AUTH_METHODS or (
        target == "self" and permission == Permissions.CONFIGURE_AUTH_METHODS
    )
    assert result.response["code"] == (200 if allowed else 403)
    assert result.result.target == str(target_id)
    assert result.result.user_id == management.user_id
    with management.sessions() as session:
        credential = session.get(UserPasswordCredential, target_id)
        assert credential.verify("UpdatedPassword456!" if allowed else "Password123!")
        if allowed and target == "self":
            assert not session.get(User, target_id).is_token_valid(
                source, purpose=TokenPurpose.ESCALATION
            )


def test_password_configuration_revalidates_escalation(management):
    general = Token.new(management.user_id, 60, management.signing_key)
    assert (
        management.call(
            "password", {"new_passwd": "UpdatedPassword456!"}, source=general
        ).response["code"]
        == 401
    )
    with management.sessions() as session:
        assert session.get(UserPasswordCredential, management.user_id).verify(
            "Password123!"
        )


@pytest.mark.parametrize(
    ("purpose", "expected_code"),
    [
        (None, 401),
        (TokenPurpose.GENERAL, 403),
        (TokenPurpose.AUTH, 403),
        (TokenPurpose.ESCALATION, 200),
        (TokenPurpose.GENERAL_WITH_ESCALATION, 200),
    ],
)
def test_password_configuration_router_enforces_token_purpose(
    management, monkeypatch, purpose, expected_code
):
    cache_manager = SimpleNamespace(caching=MemoryCachingProvider())
    monkeypatch.setattr(replay, "ProviderManager", lambda: cache_manager)
    monkeypatch.setattr(router, "Session", management.sessions)
    monkeypatch.setattr(audit, "Session", management.sessions)
    monkeypatch.setattr(
        router.LoginGuard,
        "evaluate_subnet_access",
        lambda _ip: SimpleNamespace(allowed=True),
    )
    monkeypatch.setattr(
        router,
        "check_request_rate",
        lambda *_args, **_kwargs: SimpleNamespace(allowed=True),
    )
    monkeypatch.setattr(
        router.lockdown_state_manager,
        "get_state",
        lambda: SimpleNamespace(enabled=False),
    )
    envelope = {
        "action": "set_passwd",
        "data": {"new_passwd": "UpdatedPassword456!"},
        "nonce": uuid.uuid4().hex,
        "timestamp": time.time(),
    }
    if purpose is not None:
        context = None
        if purpose == TokenPurpose.AUTH:
            with management.sessions() as session:
                context = create_authentication_context(
                    session,
                    session.get(User, management.user_id),
                    AuthPurpose.LOGIN,
                    "password",
                )
        envelope["token"] = Token.new(
            management.user_id,
            60,
            management.signing_key,
            purpose,
            auth_context=context,
        ).raw
    responses = []
    stream = SimpleNamespace(
        connection=SimpleNamespace(
            _ws=SimpleNamespace(
                remote_address=("192.0.2.10", 1), request=SimpleNamespace(headers={})
            )
        ),
        recv=lambda: SimpleNamespace(data=orjson.dumps(envelope)),
        send=lambda data, **_kwargs: responses.append(orjson.loads(data)),
    )

    router.handle_request(stream)

    assert len(responses) == 1
    assert responses[0]["code"] == expected_code
    assert responses[0]["data"] == {}
    with management.sessions() as session:
        assert session.get(UserPasswordCredential, management.user_id).verify(
            "UpdatedPassword456!" if expected_code == 200 else "Password123!"
        )
        signing_key = session.get(User, management.user_id).secret_key
        if expected_code == 200:
            assert signing_key != management.signing_key
        else:
            assert signing_key == management.signing_key


@pytest.mark.parametrize(
    "purpose", [TokenPurpose.ESCALATION, TokenPurpose.GENERAL_WITH_ESCALATION]
)
@pytest.mark.parametrize(
    "options",
    [
        {"bypass_passwd_requirements": True},
        {"force_update_after_login": True},
    ],
)
def test_password_management_options_require_super_permission(
    management, purpose, options
):
    source = Token.new(management.user_id, 60, management.signing_key, purpose)
    response = management.call(
        "password", {"new_passwd": "UpdatedPassword456!", **options}, source=source
    ).response
    assert response["code"] == 403
    with management.sessions() as session:
        assert session.get(UserPasswordCredential, management.user_id).verify(
            "Password123!"
        )


@pytest.mark.parametrize(
    "purpose", [TokenPurpose.ESCALATION, TokenPurpose.GENERAL_WITH_ESCALATION]
)
def test_super_password_configuration_can_bypass_rules_and_require_change(
    management, purpose
):
    with management.sessions.begin() as session:
        session.add(
            UserPermission(
                user_id=management.user_id,
                permission=Permissions.SUPER_CONFIGURE_AUTH_METHODS,
                granted=True,
                start_time=0,
            )
        )
    source = Token.new(management.user_id, 60, management.signing_key, purpose)
    response = management.call(
        "password",
        {
            "new_passwd": "short",
            "bypass_passwd_requirements": True,
            "force_update_after_login": True,
        },
        source=source,
    ).response
    assert response["code"] == 200
    with management.sessions() as session:
        credential = session.get(UserPasswordCredential, management.user_id)
        assert credential.verify("short")
        assert credential.passwd_last_modified == 0


@pytest.mark.parametrize("password", ["Password123!", "x"])
def test_password_configuration_preserves_password_rules(management, password):
    assert management.call("password", {"new_passwd": password}).response["code"] == 400
    with management.sessions() as session:
        assert session.get(UserPasswordCredential, management.user_id).verify(
            "Password123!"
        )


@pytest.mark.parametrize("purpose", ["login", "mfa", "escalation"])
@pytest.mark.parametrize("reverse_pool", [False, True])
def test_duplicate_complete_flows_roll_back_the_batch(
    management, purpose, reverse_pool
):
    keys = [
        management.call("register", {"public_key": ssh_key()}).response["data"][
            "credential_id"
        ]
        for _ in range(2)
    ]
    first = chain("publickey", *keys)
    second = chain("publickey", *(keys[::-1] if reverse_pool else keys))
    changes = [policy(purpose, [first, second], 1 if purpose == "login" else 0)]
    if purpose != "mfa":
        changes.insert(0, policy("mfa", []))
    response = management.call("set", {"policies": changes}).response
    assert response["code"] == 400
    assert response["data"]["reason"] == "invalid_policy"
    with management.sessions() as session:
        assert session.get(UserAuthPolicy, (management.user_id, "login")).revision == 1
        assert session.get(UserAuthPolicy, (management.user_id, "mfa")) is None
        assert session.get(UserAuthPolicy, (management.user_id, "escalation")) is None


def test_identical_password_alternatives_are_rejected(management):
    password = chain("password", management.password_id)
    response = management.call(
        "set", {"policies": [policy("login", [password, password], 1)]}
    ).response
    assert response["code"] == 400
    assert response["data"]["reason"] == "invalid_policy"


def test_distinct_ordered_flows_can_be_reused_across_purposes(management):
    keys = [
        management.call("register", {"public_key": ssh_key()}).response["data"][
            "credential_id"
        ]
        for _ in range(2)
    ]
    a, b = [chain("publickey", key) for key in keys]
    flows = [a + b, b + a]
    response = management.call(
        "set", {"policies": [policy("login", flows, 1), policy("escalation", flows)]}
    ).response
    assert response["code"] == 200
    assert response["data"]["policies"]["login"]["chains"] == flows
    assert response["data"]["policies"]["escalation"]["chains"] == flows


def test_deletion_prunes_all_purposes_and_invalidates_authentication_context(
    management,
):
    key = management.call("register", {"public_key": ssh_key()}).response["data"][
        "credential_id"
    ]
    password = chain("password", management.password_id)
    assert (
        management.call(
            "set",
            {
                "policies": [
                    policy("login", [password, chain("publickey", key)], 1),
                    policy("mfa", [chain("publickey", key)]),
                    policy("escalation", [chain("publickey", key)]),
                ]
            },
        ).response["code"]
        == 200
    )
    with management.sessions() as session:
        context = create_authentication_context(
            session,
            session.get(User, management.user_id),
            AuthPurpose.LOGIN,
            "password",
        )
    assert management.call("delete", {"credential_id": key}).response["code"] == 200
    state = management.call("get").response["data"]["policies"]
    assert state["login"] == {"revision": 3, "chains": [password]}
    assert state["mfa"] == {"revision": 2, "chains": []}
    assert state["escalation"] == {"revision": 2, "chains": []}
    with management.sessions() as session:
        assert session.get(UserAuthPublicKey, key) is None
        with pytest.raises(InvalidAuthenticationAttempt):
            get_login_progress(session, session.get(User, management.user_id), context)


def test_deletion_deduplicates_reduced_pools_and_removes_impossible_chains(management):
    keys = [
        management.call("register", {"public_key": ssh_key()}).response["data"][
            "credential_id"
        ]
        for _ in range(2)
    ]
    a, b = keys
    password = chain("password", management.password_id)
    assert (
        management.call(
            "set",
            {
                "policies": [
                    policy(
                        "login",
                        [
                            password,
                            chain("publickey", a, b),
                            chain("publickey", b),
                            chain("publickey", a, b) * 2,
                        ],
                        1,
                    )
                ]
            },
        ).response["code"]
        == 200
    )
    assert management.call("delete", {"credential_id": a}).response["code"] == 200
    state = management.call("get").response["data"]["policies"]["login"]
    assert state == {"revision": 3, "chains": [password, chain("publickey", b)]}


def test_unreferenced_deletion_does_not_change_policy_revisions(management):
    key = management.call("register", {"public_key": ssh_key()}).response["data"][
        "credential_id"
    ]
    assert management.call("delete", {"credential_id": key}).response["code"] == 200
    assert management.call("get").response["data"]["policies"]["login"]["revision"] == 1


@pytest.mark.parametrize(
    ("handler_type", "data"),
    [
        ("RequestSetup2FAHandler", {}),
        ("RequestValidate2FAHandler", {"token": "invalid"}),
        ("RequestDisable2FAHandler", {"password": "Password123!"}),
        ("RequestCancel2FASetupHandler", {}),
    ],
)
def test_totp_mutations_authorize_before_credential_access(
    management, monkeypatch, handler_type, data
):
    from include.domains.security.handlers import two_factor

    monkeypatch.setattr(two_factor, "Session", management.sessions)
    with management.sessions.begin() as session:
        session.execute(
            delete(UserPermission).where(UserPermission.user_id == management.user_id)
        )
        credential_id = session.get(
            UserTotpCredential, management.user_id
        ).credential_id
    handler = Handler(data, management.token)
    handler_class = getattr(two_factor, handler_type)
    result = handler_class().handle(
        handler, handler_class.request_model.model_validate(data)
    )
    assert result.code == handler.response["code"] == 403
    with management.sessions() as session:
        credential = session.get(UserTotpCredential, management.user_id)
        assert credential.credential_id == credential_id
        assert credential.enabled is False


@pytest.mark.parametrize(
    "permission",
    [Permissions.CONFIGURE_AUTH_METHODS, Permissions.SUPER_CONFIGURE_AUTH_METHODS],
)
def test_cancelling_pending_totp_prunes_all_dependent_policies(
    management, monkeypatch, permission
):
    from include.domains.security.handlers import two_factor

    monkeypatch.setattr(two_factor, "Session", management.sessions)
    with management.sessions.begin() as session:
        session.execute(
            delete(UserPermission).where(UserPermission.user_id == management.user_id)
        )
        session.add(
            UserPermission(
                user_id=management.user_id,
                permission=permission,
                granted=True,
                start_time=0,
            )
        )
        user = session.get(User, management.user_id)
        credential_id = session.get(UserTotpCredential, user.id).credential_id
        for purpose in (AuthPurpose.MFA, AuthPurpose.ESCALATION):
            replace_auth_policy(
                session,
                user,
                purpose,
                [chain("totp", credential_id)],
                expected_revision=0,
            )
    handler = Handler({}, management.token)
    handler_class = two_factor.RequestCancel2FASetupHandler
    handler_class().handle(handler, handler_class.request_model.model_validate({}))
    assert handler.response["code"] == 200
    with management.sessions() as session:
        assert session.get(UserTotpCredential, management.user_id) is None
        assert session.get(UserAuthPolicy, (management.user_id, "login")).revision == 1
        for purpose in ("mfa", "escalation"):
            updated = session.get(UserAuthPolicy, (management.user_id, purpose))
            assert updated.chains == []
            assert updated.revision == 2


@pytest.mark.parametrize(
    ("permission", "expected"),
    [
        (Permissions.SUPER_CONFIGURE_AUTH_METHODS, 403),
        (Permissions.SUPER_LIST_USER_AUTH_METHODS, 200),
    ],
)
def test_totp_status_requires_independent_cross_user_read_permission(
    management, monkeypatch, permission, expected
):
    from include.domains.security.handlers import two_factor

    monkeypatch.setattr(two_factor, "Session", management.sessions)
    with management.sessions.begin() as session:
        session.add(
            UserPermission(
                user_id=management.user_id,
                permission=permission,
                granted=True,
                start_time=0,
            )
        )
    data = {"user_id": str(management.other_id)}
    handler = Handler(data, management.token)
    handler_class = two_factor.RequestGet2FAStatusHandler
    result = handler_class().handle(
        handler, handler_class.request_model.model_validate(data)
    )
    assert result.code == handler.response["code"] == expected


def test_credential_pruning_does_not_discard_pending_registrations(management):
    from include.domains.identity.commands.auth_policies import (
        remove_credential_from_auth_policies,
    )

    key = management.call("register", {"public_key": ssh_key()}).response["data"][
        "credential_id"
    ]
    with management.sessions.begin() as session:
        user = session.get(User, management.user_id, with_for_update=True)
        pending = session.get(UserTotpCredential, user.id)
        replace_auth_policy(
            session,
            user,
            AuthPurpose.MFA,
            [chain("totp", pending.credential_id)],
            expected_revision=0,
        )
        replace_auth_policy(
            session,
            user,
            AuthPurpose.ESCALATION,
            [chain("publickey", key)],
            expected_revision=0,
        )
        remove_credential_from_auth_policies(session, user, "publickey", key)
        assert session.get(UserAuthPolicy, (user.id, "mfa")).chains == [
            chain("totp", pending.credential_id)
        ]
        assert session.get(UserAuthPolicy, (user.id, "mfa")).revision == 1
        assert pending.enabled is False


def test_user_can_add_password_without_an_existing_password(management):
    key = management.call("register", {"public_key": ssh_key()}).response["data"][
        "credential_id"
    ]
    key_chain = chain("publickey", key)
    assert (
        management.call(
            "set", {"policies": [policy("login", [key_chain], 1)]}
        ).response["code"]
        == 200
    )
    with management.sessions.begin() as session:
        session.delete(session.get(UserPasswordCredential, management.user_id))
    assert (
        management.call("password", {"new_passwd": "AddedPassword456!"}).response[
            "code"
        ]
        == 200
    )
    with management.sessions() as session:
        credential = session.get(UserPasswordCredential, management.user_id)
        assert credential.verify("AddedPassword456!")
        assert credential.credential_id != management.password_id
        assert session.get(UserAuthPolicy, (management.user_id, "login")).chains == [
            key_chain
        ]


@pytest.mark.parametrize("invalid", ["expired", "wrong_signature", "disabled"])
def test_password_configuration_rejects_invalid_authentication(management, invalid):
    source = management.token
    if invalid == "expired":
        source = Token.new(
            management.user_id,
            -60,
            management.signing_key,
            TokenPurpose.GENERAL_WITH_ESCALATION,
        )
    elif invalid == "wrong_signature":
        source = Token.new(
            management.user_id,
            60,
            "incorrect-signing-key-for-authentication-tests",
            TokenPurpose.GENERAL_WITH_ESCALATION,
        )
    else:
        with management.sessions.begin() as session:
            session.get(User, management.user_id).status = UserStatus.DISABLED
    response = management.call(
        "password", {"new_passwd": "UpdatedPassword456!"}, source=source
    ).response
    assert response["code"] == 401
    with management.sessions() as session:
        assert session.get(UserPasswordCredential, management.user_id).verify(
            "Password123!"
        )


def test_failed_delete_rolls_back_pruning_in_all_purposes(management):
    key = management.call("register", {"public_key": ssh_key()}).response["data"][
        "credential_id"
    ]
    assert (
        management.call(
            "set",
            {
                "policies": [
                    policy("login", [chain("publickey", key)], 1),
                    policy("mfa", [chain("password", management.password_id)]),
                    policy("escalation", [chain("publickey", key)]),
                ]
            },
        ).response["code"]
        == 200
    )
    before = management.call("get").response["data"]["policies"]
    response = management.call("delete", {"credential_id": key}).response
    assert response["code"] == 409
    assert response["data"]["reason"] == "login_unavailable"
    assert management.call("get").response["data"]["policies"] == before
    with management.sessions() as session:
        assert session.get(UserAuthPublicKey, key) is not None
