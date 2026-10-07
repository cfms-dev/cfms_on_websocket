"""Public two-factor setup, validation, disabling, and login contracts."""

import pyotp
import pytest
import pytest_asyncio

from tests.support.client import CFMSTestClient
from tests.support.utils import assert_error, assert_success


@pytest_asyncio.fixture
async def pending_totp(user_client: CFMSTestClient):
    return assert_success(await user_client.setup_2fa())


@pytest_asyncio.fixture
async def enabled_totp(user_client: CFMSTestClient, pending_totp):
    token = pyotp.TOTP(pending_totp["secret"]).now()
    assert_success(await user_client.validate_2fa(token))
    return pending_totp


class TestTwoFactorAuth:
    @pytest.mark.asyncio
    async def test_disable_2fa_does_not_disclose_cross_user_target(
        self,
        user_client: CFMSTestClient,
        test_user,
        enabled_totp,
        low_privilege_client: CFMSTestClient,
    ):
        existing_response = await low_privilege_client.send_request(
            "disable_2fa", {"username": test_user["username"]}
        )
        missing_response = await low_privilege_client.send_request(
            "disable_2fa", {"username": "nonexistent_user_xyz_12345"}
        )

        for response in (existing_response, missing_response):
            assert response["code"] == 403
            assert response["message"] == "Permission denied"
            assert response["data"] == {}
        assert assert_success(await user_client.get_2fa_status())["enabled"] is True

    @pytest.mark.asyncio
    async def test_manage_2fa_permission_preserves_target_diagnostics(
        self,
        authenticated_client: CFMSTestClient,
        test_user,
    ):
        existing_response = await authenticated_client.send_request(
            "get_2fa_status", {"target": test_user["username"]}
        )
        missing_response = await authenticated_client.send_request(
            "get_2fa_status", {"target": "nonexistent_user_xyz_12345"}
        )

        assert_success(existing_response)
        error = assert_error(missing_response, 404)
        assert error["message"] == "Target user not found"

    @pytest.mark.asyncio
    async def test_get_2fa_status_disabled_by_default(
        self, user_client: CFMSTestClient
    ):
        status = assert_success(await user_client.get_2fa_status())

        assert status["enabled"] is False
        assert status["method"] is None
        assert status["backup_codes_count"] == 0

    @pytest.mark.asyncio
    async def test_setup_2fa(self, user_client: CFMSTestClient):
        data = assert_success(await user_client.setup_2fa())

        assert isinstance(data["secret"], str)
        assert data["secret"]
        assert isinstance(data["backup_codes"], list)
        assert len(data["backup_codes"]) == 10
        assert data["provisioning_uri"].startswith("otpauth://totp/")
        assert pyotp.parse_uri(data["provisioning_uri"]).secret == data["secret"]

    @pytest.mark.asyncio
    async def test_validate_2fa_with_valid_token(
        self,
        user_client: CFMSTestClient,
        pending_totp,
    ):
        token = pyotp.TOTP(pending_totp["secret"]).now()

        data = assert_success(await user_client.validate_2fa(token))

        assert data == {"method": "totp"}
        status = assert_success(await user_client.get_2fa_status())
        assert status["enabled"] is True
        assert status["method"] == "totp"

    @pytest.mark.asyncio
    async def test_validate_2fa_with_invalid_token(
        self,
        user_client: CFMSTestClient,
        pending_totp,
    ):
        response = await user_client.validate_2fa("invalid-totp")

        error = assert_error(response, 401)
        assert error["message"] == "Invalid verification code"
        assert assert_success(await user_client.get_2fa_status())["enabled"] is False

    @pytest.mark.asyncio
    async def test_validate_2fa_without_setup(self, user_client: CFMSTestClient):
        response = await user_client.validate_2fa("123456")

        error = assert_error(response, 400)
        assert error["message"] == (
            "Two-factor authentication has not been set up. Please set it up first."
        )

    @pytest.mark.asyncio
    async def test_setup_2fa_twice_fails(
        self, user_client: CFMSTestClient, enabled_totp
    ):
        response = await user_client.setup_2fa()

        error = assert_error(response, 400)
        assert error["data"] == {"method": "totp"}
        assert assert_success(await user_client.get_2fa_status())["enabled"] is True

    @pytest.mark.asyncio
    async def test_cancel_2fa_with_valid_password(
        self,
        user_client: CFMSTestClient,
        test_user,
        enabled_totp,
    ):
        response = await user_client.cancel_2fa(test_user["password"])

        assert_success(response)
        status = assert_success(await user_client.get_2fa_status())
        assert status["enabled"] is False
        assert status["method"] is None
        assert status["backup_codes_count"] == 0

    @pytest.mark.asyncio
    async def test_cancel_2fa_with_invalid_password(
        self,
        user_client: CFMSTestClient,
        enabled_totp,
    ):
        response = await user_client.cancel_2fa("wrong_password")

        error = assert_error(response, 401)
        assert error["message"] == "Invalid password"
        assert assert_success(await user_client.get_2fa_status())["enabled"] is True

    @pytest.mark.asyncio
    async def test_cancel_2fa_when_not_enabled(
        self,
        user_client: CFMSTestClient,
        test_user,
    ):
        response = await user_client.cancel_2fa(test_user["password"])

        error = assert_error(response, 400)
        assert error["message"] == "2FA not enabled or user not found"


class TestTwoFactorAuthLogin:
    @pytest.mark.asyncio
    async def test_login_with_2fa_enabled_returns_202(
        self,
        client: CFMSTestClient,
        test_user,
        enabled_totp,
    ):
        response = await client.login(test_user["username"], test_user["password"])

        assert response["code"] == 202
        assert response["data"]["method"] == "totp"

    @pytest.mark.asyncio
    async def test_verify_2fa_login_with_valid_token(
        self,
        client: CFMSTestClient,
        test_user,
        enabled_totp,
    ):
        token = pyotp.TOTP(enabled_totp["secret"]).now()

        data = assert_success(
            await client.login(
                test_user["username"], test_user["password"], two_fa_token=token
            )
        )

        assert data["token"]
        assert "exp" in data

    @pytest.mark.asyncio
    async def test_verify_2fa_login_with_invalid_token(
        self,
        client: CFMSTestClient,
        test_user,
        enabled_totp,
    ):
        response = await client.login(
            test_user["username"], test_user["password"], two_fa_token="invalid-totp"
        )

        assert_error(response, 401)

    @pytest.mark.asyncio
    async def test_verify_2fa_login_with_backup_code(
        self,
        client: CFMSTestClient,
        test_user,
        enabled_totp,
    ):
        data = assert_success(
            await client.login(
                test_user["username"],
                test_user["password"],
                two_fa_token=enabled_totp["backup_codes"][0],
            )
        )

        assert data["token"]
