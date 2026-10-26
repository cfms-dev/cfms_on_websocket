import base64
import hashlib
import uuid

import jwt
import orjson
import pytest
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from include.config.constants import USERNAME_MAX_LENGTH
from include.database.models.auth import UserAuthPublicKey, UserPasswordCredential
from include.database.models.identity import User
from include.database.session import Session
from include.domains.identity.auth.types import AuthPurpose
from include.domains.identity.commands.auth_policies import replace_auth_policy
from include.domains.identity.commands.credentials import setup_totp
from include.domains.identity.tokens import TokenPurpose
from include.transport.multiplexing import FrameType, encode_frame

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
@pytest.mark.parametrize("purpose", [AuthPurpose.LOGIN, AuthPurpose.MFA])
async def test_public_key_authentication_and_late_conclusion_keep_connection_usable(
    user_factory, unauthenticated_client, purpose
):
    account = await user_factory()
    user_id = uuid.UUID(account["user_id"])
    private = ed25519.Ed25519PrivateKey.generate()
    public = private.public_key()
    fingerprint = hashlib.sha256(
        public.public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
    ).digest()
    with Session.begin() as session:
        user = session.get(User, user_id)
        key = UserAuthPublicKey(
            user_id=user_id,
            public_key_der=public.public_bytes(
                Encoding.DER, PublicFormat.SubjectPublicKeyInfo
            ),
            fingerprint=fingerprint,
        )
        session.add(key)
        session.flush()
        replace_auth_policy(
            session,
            user,
            purpose,
            [[{"method": "publickey", "credential_ids": [key.id]}]],
            expected_revision=1 if purpose == AuthPurpose.LOGIN else 0,
        )

    stream_ids = []

    async def respond(message):
        assert message["data"]["stage"] == purpose.value
        challenge = base64.b64decode(message["data"]["challenge"])
        stream_ids.append(orjson.loads(challenge)["stream_id"])
        return {
            "method": "publickey",
            "data": {
                "fingerprint": fingerprint.hex(),
                "signature": base64.b64encode(private.sign(challenge)).decode(),
            },
        }

    client = unauthenticated_client
    if purpose == AuthPurpose.LOGIN:
        response = await client.send_request(
            "core.auth.login",
            {
                "method": "publickey",
                "credential": {
                    "username": account["username"],
                    "fingerprint": fingerprint.hex(),
                },
            },
            include_auth=False,
            auth_responder=respond,
        )
    else:
        login = await client.login(account["username"], account["password"])
        assert login["code"] == 202
        response = await client.send_request(
            "core.auth.token.exchange",
            {
                "method": "publickey",
                "data": {"fingerprint": fingerprint.hex()},
                "target_purpose": TokenPurpose.GENERAL,
            },
            token=login["data"]["token"],
            auth_responder=respond,
        )
    assert response["code"] == 200
    assert response["data"]["purpose"] == TokenPurpose.GENERAL
    assert len(stream_ids) == 1
    await client.websocket.send(encode_frame(stream_ids[0], FrameType.CONCLUSION, b""))
    following = await client.send_request(
        "core.server.info.get", {}, token=response["data"]["token"]
    )
    assert following["code"] == 200


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["password", "publickey"])
async def test_login_method_rejects_oversized_username(unauthenticated_client, method):
    credential = {"username": "u" * (USERNAME_MAX_LENGTH + 1)}
    credential.update(
        {"password": "secret"} if method == "password" else {"fingerprint": "f" * 64}
    )
    response = await unauthenticated_client.send_request(
        "core.auth.login",
        {"method": method, "credential": credential},
        include_auth=False,
    )
    assert response["code"] == 400
    assert "token" not in response["data"]


@pytest.mark.asyncio
async def test_password_mfa_post_auth_over_websocket(
    user_factory, unauthenticated_client
):
    account = await user_factory()
    user_id = uuid.UUID(account["user_id"])
    with Session.begin() as session:
        user = session.get(User, user_id)
        user.last_login = 10
        session.get(UserPasswordCredential, user_id).passwd_last_modified = 0
        totp, codes = setup_totp(session, user)
        totp.enable()
        session.flush()
        replace_auth_policy(
            session,
            user,
            AuthPurpose.MFA,
            [[{"method": "totp", "credential_ids": [totp.credential_id]}]],
            expected_revision=0,
        )
        signing_key = user.secret_key
    client = unauthenticated_client
    login = await client.login(account["username"], account["password"])
    assert login["code"] == 202
    auth_token = login["data"]["token"]
    payload = jwt.decode(auth_token, signing_key, algorithms=["HS256"])
    assert payload["purpose"] == TokenPurpose.AUTH
    assert "version" not in payload["auth_context"]
    assert "required_actions" not in login["data"]
    denied = await client.send_request(
        "core.user.password.set",
        {"new_passwd": "UpdatedPassword456!"},
        token=auth_token,
    )
    assert denied["code"] == 403
    complete = await client.send_request(
        "core.auth.token.exchange",
        {
            "method": "totp",
            "data": {"token": codes[0]},
            "target_purpose": TokenPurpose.GENERAL,
        },
        token=auth_token,
    )
    assert complete["code"] == 4002
    post_token = complete["data"]["token"]
    assert (
        "version"
        not in jwt.decode(post_token, signing_key, algorithms=["HS256"])["auth_context"]
    )
    assert complete["data"]["required_actions"] == ["change_password"]
    assert (
        jwt.decode(post_token, signing_key, algorithms=["HS256"])["purpose"]
        == TokenPurpose.POST_AUTH
    )
    with Session() as session:
        assert session.get(User, user_id).last_login == 10
    for action, data in (
        ("core.auth.token.refresh", {}),
        ("core.server.info.get", {}),
        (
            "core.auth.token.exchange",
            {
                "method": "totp",
                "data": {"token": codes[1]},
                "target_purpose": TokenPurpose.GENERAL,
            },
        ),
    ):
        denied = await client.send_request(action, data, token=post_token)
        assert denied["code"] == 403
    changed = await client.send_request(
        "core.user.password.set",
        {"new_passwd": "UpdatedPassword456!"},
        token=post_token,
    )
    assert changed["code"] == 200
    assert changed["data"] == {}
    replay = await client.send_request(
        "core.user.password.set",
        {"new_passwd": "AnotherPassword789!"},
        token=post_token,
    )
    assert replay["code"] == 401
    logged_in = await client.login(
        account["username"], "UpdatedPassword456!", totp_token=codes[1]
    )
    assert logged_in["code"] == 200


@pytest.mark.asyncio
async def test_multiple_public_keys_in_one_login_request_then_separate_mfa(
    user_factory, unauthenticated_client
):
    account = await user_factory()
    user_id = uuid.UUID(account["user_id"])
    keys = {}
    with Session.begin() as session:
        user = session.get(User, user_id)
        chain = []
        for _ in range(2):
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
            keys[key.fingerprint.hex()] = private
            chain.append({"method": "publickey", "credential_ids": [key.id]})
        replace_auth_policy(
            session, user, AuthPurpose.LOGIN, [chain], expected_revision=1
        )
        totp, codes = setup_totp(session, user)
        totp.enable()
        session.flush()
        replace_auth_policy(
            session,
            user,
            AuthPurpose.MFA,
            [[{"method": "totp", "credential_ids": [totp.credential_id]}]],
            expected_revision=0,
        )
        session.get(UserPasswordCredential, user_id).passwd_last_modified = 0
    events, stream_ids = [], []
    fingerprints = list(keys)

    async def respond(message):
        events.append(message["action"])
        if message["action"] == "auth_continue":
            assert message["data"]["stage"] == "login"
            return {"method": "publickey", "data": {"fingerprint": fingerprints[1]}}
        challenge = base64.b64decode(message["data"]["challenge"])
        details = orjson.loads(challenge)
        stream_ids.append(details["stream_id"])
        fingerprint = details["fingerprint"]
        return {
            "method": "publickey",
            "data": {
                "fingerprint": fingerprint,
                "signature": base64.b64encode(
                    keys[fingerprint].sign(challenge)
                ).decode(),
            },
        }

    client = unauthenticated_client
    login = await client.send_request(
        "core.auth.login",
        {
            "method": "publickey",
            "credential": {
                "username": account["username"],
                "fingerprint": fingerprints[0],
            },
        },
        include_auth=False,
        auth_responder=respond,
    )
    assert login["code"] == 202
    assert events == ["auth_challenge", "auth_continue", "auth_challenge"]
    assert len(stream_ids) == 2
    assert stream_ids[0] == stream_ids[1]
    complete = await client.send_request(
        "core.auth.token.exchange",
        {
            "method": "totp",
            "data": {"token": codes[0]},
            "target_purpose": TokenPurpose.GENERAL,
        },
        token=login["data"]["token"],
    )
    assert complete["code"] == 200
    assert "required_actions" not in complete["data"]


@pytest.mark.asyncio
async def test_password_escalation_and_refresh_over_websocket(
    user_factory, unauthenticated_client
):
    account = await user_factory()
    user_id = uuid.UUID(account["user_id"])
    with Session.begin() as session:
        user = session.get(User, user_id)
        credential = session.get(UserPasswordCredential, user_id)
        replace_auth_policy(
            session,
            user,
            AuthPurpose.ESCALATION,
            [[{"method": "password", "credential_ids": [credential.credential_id]}]],
            expected_revision=0,
        )
        signing_key = user.secret_key
    client = unauthenticated_client
    login = await client.login(account["username"], account["password"])
    assert login["code"] == 200
    elevated = await client.send_request(
        "core.auth.token.exchange",
        {
            "method": "password",
            "data": {"password": account["password"]},
            "target_purpose": TokenPurpose.GENERAL_WITH_ESCALATION,
        },
    )
    assert elevated["code"] == 200
    assert elevated["data"]["purpose"] == TokenPurpose.GENERAL_WITH_ESCALATION
    token = elevated["data"]["token"]
    assert (
        jwt.decode(token, signing_key, algorithms=["HS256"])["purpose"]
        == TokenPurpose.GENERAL_WITH_ESCALATION
    )
    refreshed = await client.send_request("core.auth.token.refresh", {}, token=token)
    assert refreshed["code"] == 200
    assert refreshed["data"]["purpose"] == TokenPurpose.GENERAL
    rejected = await client.send_request(
        "core.auth.token.exchange",
        {
            "method": "password",
            "data": {"password": account["password"]},
            "target_purpose": TokenPurpose.GENERAL,
        },
        token=refreshed["data"]["token"],
    )
    assert rejected["code"] == 403


@pytest.mark.asyncio
async def test_user_manages_public_key_login_and_mfa_over_websocket(
    user_factory, unauthenticated_client
):
    account = await user_factory(groups=[{"group_name": "user", "start_time": 0}])
    client = unauthenticated_client
    login = await client.login(account["username"], account["password"])
    assert login["code"] == 200
    general = login["data"]["token"]
    inventory = await client.send_request(
        "core.user.authentication.get", {}, token=general
    )
    assert inventory["code"] == 200
    password_id = next(
        c["credential_id"]
        for c in inventory["data"]["credentials"]
        if c["method"] == "password"
    )
    private = ed25519.Ed25519PrivateKey.generate()
    public = (
        private.public_key()
        .public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        .decode()
    )
    denied = await client.send_request(
        "core.user.authentication.public_key.register",
        {"public_key": public},
        token=general,
    )
    assert denied["code"] == 403
    elevated = await client.send_request(
        "core.auth.token.exchange",
        {"target_purpose": TokenPurpose.GENERAL_WITH_ESCALATION},
        token=general,
    )
    assert elevated["code"] == 200
    assert elevated["data"]["purpose"] == TokenPurpose.GENERAL_WITH_ESCALATION
    elevated_token = elevated["data"]["token"]
    registered = await client.send_request(
        "core.user.authentication.public_key.register",
        {"public_key": public, "label": "test key"},
        token=elevated_token,
    )
    assert registered["code"] == 200
    key = registered["data"]

    async def respond(message):
        challenge = base64.b64decode(message["data"]["challenge"])
        return {
            "method": "publickey",
            "data": {
                "fingerprint": key["fingerprint"],
                "signature": base64.b64encode(private.sign(challenge)).decode(),
            },
        }

    async def key_login():
        return await client.send_request(
            "core.auth.login",
            {
                "method": "publickey",
                "credential": {
                    "username": account["username"],
                    "fingerprint": key["fingerprint"],
                },
            },
            include_auth=False,
            auth_responder=respond,
        )

    unauthorized = await key_login()
    assert unauthorized["code"] == 401
    assert "token" not in unauthorized["data"]
    configured = await client.send_request(
        "core.user.authentication.policy.set",
        {
            "policies": [
                {
                    "purpose": "login",
                    "expected_revision": 1,
                    "chains": [
                        [
                            {
                                "method": "publickey",
                                "credential_ids": [key["credential_id"]],
                            }
                        ]
                    ],
                },
                {
                    "purpose": "mfa",
                    "expected_revision": 0,
                    "chains": [
                        [{"method": "password", "credential_ids": [password_id]}]
                    ],
                },
                {
                    "purpose": "escalation",
                    "expected_revision": 0,
                    "chains": [
                        [
                            {
                                "method": "publickey",
                                "credential_ids": [key["credential_id"]],
                            }
                        ]
                    ],
                },
            ]
        },
        token=elevated_token,
    )
    assert configured["code"] == 200
    assert configured["data"]["policies"]["login"]["revision"] == 2
    updated = await client.send_request(
        "core.user.authentication.public_key.update",
        {"credential_id": key["credential_id"], "label": None},
        token=elevated_token,
    )
    assert updated["code"] == 200
    assert updated["data"]["label"] is None
    blocked = await client.send_request(
        "core.user.authentication.public_key.delete",
        {"credential_id": key["credential_id"]},
        token=elevated_token,
    )
    assert blocked["code"] == 409
    assert blocked["data"]["reason"] == "login_unavailable"
    new_login = await key_login()
    assert new_login["code"] == 202
    assert new_login["data"]["purpose"] == TokenPurpose.AUTH
    assert "password" in new_login["data"]["methods"]
    complete = await client.send_request(
        "core.auth.token.exchange",
        {
            "target_purpose": TokenPurpose.GENERAL,
            "method": "password",
            "data": {"password": account["password"]},
        },
        token=new_login["data"]["token"],
    )
    assert complete["code"] == 200
    assert complete["data"]["purpose"] == TokenPurpose.GENERAL
    source = complete["data"]["token"]
    missing_proof = await client.send_request(
        "core.auth.token.exchange",
        {"target_purpose": TokenPurpose.GENERAL_WITH_ESCALATION},
        token=source,
    )
    assert missing_proof["code"] == 400
    verified = await client.send_request(
        "core.auth.token.exchange",
        {
            "target_purpose": TokenPurpose.GENERAL_WITH_ESCALATION,
            "method": "publickey",
            "data": {"fingerprint": key["fingerprint"]},
        },
        token=source,
        auth_responder=respond,
    )
    assert verified["code"] == 200
    assert verified["data"]["purpose"] == TokenPurpose.GENERAL_WITH_ESCALATION

    cleared = await client.send_request(
        "core.user.authentication.policy.set",
        {"policies": [{"purpose": "escalation", "expected_revision": 1, "chains": []}]},
        token=verified["data"]["token"],
    )
    assert cleared["code"] == 200
    assert cleared["data"]["policies"]["escalation"] == {
        "revision": 2,
        "chains": [],
    }
    direct = await client.send_request(
        "core.auth.token.exchange",
        {"target_purpose": TokenPurpose.GENERAL_WITH_ESCALATION},
        token=source,
    )
    assert direct["code"] == 200
    assert direct["data"]["purpose"] == TokenPurpose.GENERAL_WITH_ESCALATION
    assert "token" in direct["data"]


@pytest.mark.asyncio
async def test_authentication_management_schema_rejects_invalid_fields(
    user_factory, unauthenticated_client
):
    account = await user_factory()
    client = unauthenticated_client
    assert (await client.login(account["username"], account["password"]))["code"] == 200
    for action, data, location in (
        ("core.user.authentication.get", {"user_id": "invalid"}, ["user_id", "uuid"]),
        (
            "core.user.authentication.public_key.register",
            {"public_key": "key", "label": "x" * 256},
            ["label"],
        ),
        ("core.user.authentication.policy.set", {"policies": []}, ["policies"]),
        (
            "core.user.authentication.public_key.update",
            {"credential_id": "key"},
            ["label"],
        ),
    ):
        response = await client.send_request(action, data)
        assert response["code"] == 400
        assert response["data"]["errors"][0]["loc"] == location
        assert "input" not in response["data"]["errors"][0]


@pytest.mark.asyncio
async def test_default_sysop_manages_another_users_authentication(
    authenticated_client, user_factory
):
    account = await user_factory()
    client = authenticated_client
    user_id = account["user_id"]
    inventory = await client.send_request(
        "core.user.authentication.get", {"user_id": user_id}
    )
    assert inventory["code"] == 200
    assert inventory["data"]["user_id"] == user_id
    elevated = await client.send_request(
        "core.auth.token.exchange",
        {"target_purpose": TokenPurpose.GENERAL_WITH_ESCALATION},
    )
    assert elevated["code"] == 200
    token = elevated["data"]["token"]
    public_key = (
        ed25519.Ed25519PrivateKey.generate()
        .public_key()
        .public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH)
        .decode()
    )
    registered = await client.send_request(
        "core.user.authentication.public_key.register",
        {"user_id": user_id, "public_key": public_key},
        token=token,
    )
    assert registered["code"] == 200
    key_id = registered["data"]["credential_id"]
    for action, data in (
        (
            "core.user.authentication.policy.set",
            {"policies": [{"purpose": "mfa", "expected_revision": 0, "chains": []}]},
        ),
        (
            "core.user.authentication.public_key.update",
            {"credential_id": key_id, "label": "managed by sysop"},
        ),
        ("core.user.authentication.public_key.delete", {"credential_id": key_id}),
    ):
        response = await client.send_request(
            action, {**data, "user_id": user_id}, token=token
        )
        assert response["code"] == 200
