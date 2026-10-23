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
from include.domains.identity.commands.credentials import enable_login_totp, setup_totp
from include.domains.identity.tokens import TokenPurpose

pytestmark = pytest.mark.integration


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["password", "publickey"])
async def test_login_method_rejects_oversized_username(unauthenticated_client, method):
    credential = {"username": "u" * (USERNAME_MAX_LENGTH + 1)}
    credential.update(
        {"password": "secret"} if method == "password" else {"fingerprint": "f" * 64}
    )
    response = await unauthenticated_client.send_request(
        "login", {"method": method, "credential": credential}, include_auth=False
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
        enable_login_totp(session, user, totp)
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
        "set_passwd", {"new_passwd": "UpdatedPassword456!"}, token=auth_token
    )
    assert denied["code"] == 403
    complete = await client.send_request(
        "complete_mfa",
        {"method": "totp", "data": {"token": codes[0]}, "target_purpose": 2},
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
        ("refresh_token", {}),
        ("server_info", {}),
        (
            "complete_mfa",
            {"method": "totp", "data": {"token": codes[1]}, "target_purpose": 2},
        ),
    ):
        denied = await client.send_request(action, data, token=post_token)
        assert denied["code"] == 403
    changed = await client.send_request(
        "set_passwd", {"new_passwd": "UpdatedPassword456!"}, token=post_token
    )
    assert changed["code"] == 200
    assert changed["data"] == {}
    replay = await client.send_request(
        "set_passwd", {"new_passwd": "AnotherPassword789!"}, token=post_token
    )
    assert replay["code"] == 401
    logged_in = await client.login(
        account["username"], "UpdatedPassword456!", two_fa_token=codes[1]
    )
    assert logged_in["code"] == 200
    assert (await client.server_info())["data"]["protocol_version"] == 30


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
        enable_login_totp(session, user, totp)
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
        "login",
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
        "complete_mfa",
        {"method": "totp", "data": {"token": codes[0]}, "target_purpose": 2},
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
        "complete_mfa",
        {
            "method": "password",
            "data": {"password": account["password"]},
            "target_purpose": 6,
        },
    )
    assert elevated["code"] == 200
    assert elevated["data"]["purpose"] == 6
    token = elevated["data"]["token"]
    assert jwt.decode(token, signing_key, algorithms=["HS256"])["purpose"] == 6
    refreshed = await client.send_request("refresh_token", {}, token=token)
    assert refreshed["code"] == 200
    assert refreshed["data"]["purpose"] == 2
    rejected = await client.send_request(
        "complete_mfa",
        {
            "method": "password",
            "data": {"password": account["password"]},
            "target_purpose": 2,
        },
        token=refreshed["data"]["token"],
    )
    assert rejected["code"] == 403
