import hashlib
import threading
import uuid
from types import SimpleNamespace

import orjson
import pytest
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, rsa
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
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
from include.domains.identity.auth.providers.password import PasswordAuthProvider
from include.domains.identity.auth.types import AuthPurpose
from include.domains.identity.commands.auth_policies import replace_auth_policy
from include.domains.identity.commands.credentials import set_password, setup_totp
from include.domains.identity.handlers import auth, auth_management
from include.domains.identity.tokens import Token, TokenPurpose

pytestmark = pytest.mark.component

HANDLERS = {
    "get": auth_management.RequestGetUserAuthenticationHandler,
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
        result = HANDLERS[action]().handle(handler)
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
                permission=Permissions.MANAGE_USER_AUTHENTICATION,
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
                permission=Permissions.MANAGE_USER_AUTHENTICATION,
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
    assert (
        management.call("set", {"policies": [policy("escalation", [], 1)]}).response[
            "data"
        ]["reason"]
        == "escalation_required"
    )
    assert (
        management.call("set", {"policies": [policy("mfa", [])]}).response["data"][
            "reason"
        ]
        == "revision_conflict"
    )


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
    assert login["chains"][1] == chain("publickey", key_id)
    assert login["revision"] == 2


@pytest.mark.parametrize("purpose", ["login", "escalation"])
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


@pytest.mark.parametrize("empty_policy", [False, True])
def test_no_policy_escalation_issues_short_lived_token_without_proof(
    management, empty_policy
):
    if empty_policy:
        assert (
            management.call("set", {"policies": [policy("escalation", [])]}).response[
                "code"
            ]
            == 200
        )
    source = Token.new(management.user_id, 60, management.signing_key)
    handler = Handler({"target_purpose": 6}, source)
    assert auth.RequestExchangeTokenHandler().handle(handler).code == 200
    issued = Token.from_raw(handler.response["data"]["token"], management.signing_key)
    assert issued.purpose == TokenPurpose.GENERAL | TokenPurpose.ESCALATION
    assert issued.exp - issued.iat == ESCALATION_TOKEN_EXPIRY_SECONDS
    assert issued.auth_context is None
    with management.sessions() as session:
        user = session.get(User, management.user_id)
        assert user.last_login == 10
        assert user.all_permissions == set()
    refreshed = Handler({}, issued)
    auth.RequestRefreshTokenHandler().handle(refreshed)
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
    handler = Handler({"target_purpose": 6}, source)
    assert auth.RequestExchangeTokenHandler().handle(handler).code == expected
    assert "token" not in handler.response["data"]


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
    handler = Handler({"target_purpose": 6}, source)
    assert auth.RequestExchangeTokenHandler().handle(handler).code == 403


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
        "target_purpose": 6,
    }
    for field in ("method", "data") if missing == "both" else (missing,):
        data.pop(field)
    handler = Handler(data, Token.new(management.user_id, 60, management.signing_key))
    assert auth.RequestExchangeTokenHandler().handle(handler).code == 400
