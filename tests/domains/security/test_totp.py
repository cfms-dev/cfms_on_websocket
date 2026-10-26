"""Public TOTP setup, validation, disabling, and login contracts."""

import uuid

import orjson
import pyotp
import pytest
import pytest_asyncio
from argon2 import PasswordHasher
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

import include.database.models  # noqa: F401
from include.database.models import auth
from include.database.models.auth import UserTotpCredential
from include.database.models.identity import User
from include.database.session import Base
from include.domains.identity.tokens import TokenPurpose
from tests.support.client import CFMSTestClient
from tests.support.utils import assert_error, assert_success


@pytest_asyncio.fixture
async def test_user(user_factory):
    return await user_factory(groups=[{"group_name": "user", "start_time": 0}])


@pytest_asyncio.fixture
async def pending_totp(user_client: CFMSTestClient):
    return assert_success(await user_client.setup_totp())


@pytest_asyncio.fixture
async def enabled_totp(user_client: CFMSTestClient, pending_totp):
    token = pyotp.TOTP(pending_totp["secret"]).now()
    assert_success(await user_client.confirm_totp_setup(token))
    return pending_totp


@pytest_asyncio.fixture
async def login_mfa(user_client: CFMSTestClient, enabled_totp):
    assert_success(await user_client.elevate_token())
    authentication = assert_success(
        await user_client.send_request("core.user.authentication.get")
    )
    credential = next(
        item for item in authentication["credentials"] if item["method"] == "totp"
    )
    assert_success(
        await user_client.send_request(
            "core.user.authentication.policy.set",
            {
                "policies": [
                    {
                        "purpose": "mfa",
                        "expected_revision": authentication["policies"]["mfa"][
                            "revision"
                        ],
                        "chains": [
                            [
                                {
                                    "method": "totp",
                                    "credential_ids": [credential["credential_id"]],
                                }
                            ]
                        ],
                    }
                ]
            },
        )
    )
    return enabled_totp


@pytest.mark.integration
class TestTotpCredentials:
    @pytest.mark.asyncio
    async def test_administrator_cannot_delete_totp_for_missing_user(
        self, authenticated_client: CFMSTestClient
    ):
        response = await authenticated_client.send_request(
            "core.user.authentication.totp.delete", {"user_id": str(uuid.uuid4())}
        )
        assert_error(response, 400)

    @pytest.mark.asyncio
    async def test_administrator_deletes_totp_by_user_id(
        self,
        authenticated_client,
        user_client,
        test_user,
        enabled_totp,
    ):
        status = assert_success(
            await authenticated_client.send_request(
                "core.user.authentication.totp.status.get",
                {"user_id": test_user["user_id"]},
            )
        )
        assert status["enabled"] is True
        assert_success(
            await authenticated_client.send_request(
                "core.user.authentication.totp.delete",
                {"user_id": test_user["user_id"]},
            )
        )
        assert assert_success(await user_client.get_totp_status())["enabled"] is False

    @pytest.mark.asyncio
    async def test_delete_totp_does_not_disclose_cross_user_target(
        self,
        user_client: CFMSTestClient,
        test_user,
        enabled_totp,
        low_privilege_client: CFMSTestClient,
    ):
        existing_response = await low_privilege_client.send_request(
            "core.user.authentication.totp.delete", {"user_id": test_user["user_id"]}
        )
        missing_response = await low_privilege_client.send_request(
            "core.user.authentication.totp.delete",
            {"user_id": "00000000-0000-4000-8000-000000000001"},
        )

        for response in (existing_response, missing_response):
            assert response["code"] == 403
            assert response["data"] == {}
        assert assert_success(await user_client.get_totp_status())["enabled"] is True

    @pytest.mark.asyncio
    async def test_super_list_auth_methods_preserves_target_diagnostics(
        self,
        authenticated_client: CFMSTestClient,
        test_user,
    ):
        existing_response = await authenticated_client.send_request(
            "core.user.authentication.totp.status.get",
            {"user_id": test_user["user_id"]},
        )
        missing_response = await authenticated_client.send_request(
            "core.user.authentication.totp.status.get",
            {"user_id": "00000000-0000-4000-8000-000000000001"},
        )

        assert_success(existing_response)
        assert_error(missing_response, 404)

    @pytest.mark.asyncio
    async def test_get_totp_status_disabled_by_default(
        self, user_client: CFMSTestClient
    ):
        status = assert_success(await user_client.get_totp_status())

        assert status["enabled"] is False
        assert status["configured"] is False
        assert status["backup_codes_count"] == 0

    @pytest.mark.asyncio
    async def test_setup_totp(self, user_client: CFMSTestClient):
        data = assert_success(await user_client.setup_totp())

        assert isinstance(data["secret"], str)
        assert data["secret"]
        assert isinstance(data["backup_codes"], list)
        assert len(data["backup_codes"]) == 10
        assert data["provisioning_uri"].startswith("otpauth://totp/")
        assert pyotp.parse_uri(data["provisioning_uri"]).secret == data["secret"]
        status = assert_success(await user_client.get_totp_status())
        assert status == {
            "configured": True,
            "enabled": False,
            "backup_codes_count": 10,
        }

    @pytest.mark.asyncio
    async def test_active_totp_does_not_require_login_mfa(
        self, client, test_user, enabled_totp
    ):
        response = await client.login(test_user["username"], test_user["password"])
        assert response["code"] == 200
        assert response["data"]["purpose"] == TokenPurpose.GENERAL

    @pytest.mark.asyncio
    async def test_confirm_totp_setup_with_valid_token(
        self,
        user_client: CFMSTestClient,
        pending_totp,
    ):
        token = pyotp.TOTP(pending_totp["secret"]).now()

        data = assert_success(await user_client.confirm_totp_setup(token))

        assert data == {"method": "totp"}
        status = assert_success(await user_client.get_totp_status())
        assert status["enabled"] is True
        assert status["configured"] is True
        authentication = assert_success(
            await user_client.send_request("core.user.authentication.get")
        )
        assert authentication["policies"]["mfa"] == {"revision": 0, "chains": []}

    @pytest.mark.asyncio
    async def test_confirm_totp_setup_with_invalid_token(
        self,
        user_client: CFMSTestClient,
        pending_totp,
    ):
        response = await user_client.confirm_totp_setup("invalid-totp")

        assert_error(response, 401)
        assert assert_success(await user_client.get_totp_status())["enabled"] is False

    @pytest.mark.asyncio
    async def test_confirm_totp_setup_without_setup(self, user_client: CFMSTestClient):
        response = await user_client.confirm_totp_setup("123456")

        assert_error(response, 400)

    @pytest.mark.asyncio
    async def test_setup_totp_twice_fails(
        self, user_client: CFMSTestClient, enabled_totp
    ):
        response = await user_client.setup_totp()

        error = assert_error(response, 400)
        assert error["data"] == {"method": "totp"}
        assert assert_success(await user_client.get_totp_status())["enabled"] is True

    @pytest.mark.asyncio
    async def test_delete_totp_with_valid_password(
        self,
        user_client: CFMSTestClient,
        test_user,
        enabled_totp,
    ):
        response = await user_client.delete_totp(test_user["password"])

        assert_success(response)
        status = assert_success(await user_client.get_totp_status())
        assert status["enabled"] is False
        assert status["configured"] is False
        assert status["backup_codes_count"] == 0

    @pytest.mark.asyncio
    async def test_delete_totp_with_invalid_password(
        self,
        user_client: CFMSTestClient,
        test_user,
        enabled_totp,
    ):
        response = await user_client.delete_totp("wrong_password")

        assert_error(response, 401)
        assert assert_success(await user_client.get_totp_status())["enabled"] is True
        assert_success(await user_client.delete_totp(test_user["password"]))
        assert assert_success(await user_client.get_totp_status())["enabled"] is False

    @pytest.mark.asyncio
    async def test_delete_totp_when_not_enabled(
        self,
        user_client: CFMSTestClient,
        test_user,
    ):
        response = await user_client.delete_totp(test_user["password"])

        assert_error(response, 400)


@pytest.mark.integration
@pytest.mark.usefixtures("login_mfa")
class TestMfaLogin:
    @pytest.mark.asyncio
    async def test_login_with_mfa_policy_returns_202(
        self,
        client: CFMSTestClient,
        test_user,
        enabled_totp,
    ):
        response = await client.login(test_user["username"], test_user["password"])

        assert response["code"] == 202
        assert response["data"]["methods"] == ["totp"]

    @pytest.mark.asyncio
    async def test_totp_mfa_login_with_valid_token(
        self,
        client: CFMSTestClient,
        test_user,
        enabled_totp,
    ):
        token = pyotp.TOTP(enabled_totp["secret"]).now()

        data = assert_success(
            await client.login(
                test_user["username"], test_user["password"], totp_token=token
            )
        )

        assert data["token"]
        assert "exp" in data

    @pytest.mark.asyncio
    async def test_totp_mfa_login_with_invalid_token(
        self,
        client: CFMSTestClient,
        test_user,
        enabled_totp,
    ):
        response = await client.login(
            test_user["username"], test_user["password"], totp_token="invalid-totp"
        )

        assert_error(response, 401)

    @pytest.mark.asyncio
    async def test_totp_mfa_login_consumes_backup_code_once(
        self,
        client: CFMSTestClient,
        user_client: CFMSTestClient,
        test_user,
        enabled_totp,
    ):
        backup_code = enabled_totp["backup_codes"][0]
        before = assert_success(await user_client.get_totp_status())
        assert before["backup_codes_count"] == 10

        data = assert_success(
            await client.login(
                test_user["username"],
                test_user["password"],
                totp_token=backup_code,
            )
        )

        assert data["token"]
        after = assert_success(await user_client.get_totp_status())
        assert after["backup_codes_count"] == 9

        replay = await client.login(
            test_user["username"], test_user["password"], totp_token=backup_code
        )

        error = assert_error(replay, 401)
        assert error["data"] == {}
        remaining = assert_success(await user_client.get_totp_status())
        assert remaining["backup_codes_count"] == 9
        assert remaining["enabled"] is True


@pytest.fixture
def backup_code_sessions(monkeypatch, sqlite_engine_factory):
    database = sqlite_engine_factory()
    Base.metadata.create_all(database)
    sessions = sessionmaker(bind=database)
    pepper = "backup-code-test-pepper"
    monkeypatch.setattr(auth, "global_config", {"security": {"pepper": pepper}})
    hasher = PasswordHasher()
    hashes = [hasher.hash(code + pepper) for code in ("deadbeef", "cafebabe")]
    with sessions.begin() as session:
        session.add(
            UserTotpCredential(
                user=User(username="alice", created_time=0.0),
                secret=pyotp.random_base32(),
                enabled=True,
                backup_codes=orjson.dumps(hashes).decode("utf-8"),
            )
        )
    return sessions, hashes[1]


@pytest.mark.component
def test_backup_code_consumption_is_committed_and_reuse_preserves_remaining_codes(
    backup_code_sessions,
):
    sessions, remaining_hash = backup_code_sessions

    with sessions.begin() as session:
        assert session.scalar(select(UserTotpCredential)).verify("deadbeef") is True

    with sessions() as session:
        persisted = session.scalar(select(UserTotpCredential))
        assert orjson.loads(persisted.backup_codes) == [remaining_hash]
        assert persisted.verify("deadbeef") is False

    with sessions() as session:
        persisted = session.scalar(select(UserTotpCredential))
        assert orjson.loads(persisted.backup_codes) == [remaining_hash]
        assert persisted.enabled is True


@pytest.mark.component
def test_consuming_last_backup_code_commits_empty_list_and_keeps_totp_enabled(
    backup_code_sessions,
):
    sessions, remaining_hash = backup_code_sessions
    with sessions.begin() as session:
        session.scalar(select(UserTotpCredential)).backup_codes = orjson.dumps(
            [remaining_hash]
        ).decode("utf-8")

    with sessions.begin() as session:
        assert session.scalar(select(UserTotpCredential)).verify("cafebabe") is True

    with sessions() as session:
        persisted = session.scalar(select(UserTotpCredential))
        assert orjson.loads(persisted.backup_codes) == []
        assert persisted.enabled is True
        assert persisted.verify("cafebabe") is False
