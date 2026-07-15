import pytest

from tests.test_client import CFMSTestClient
from tests.utils import assert_error, assert_success


class TestServerBasics:
    @pytest.mark.asyncio
    async def test_server_connection(self, client: CFMSTestClient):
        assert client.websocket is not None
        assert hasattr(client.websocket, "id")

    @pytest.mark.asyncio
    async def test_server_info(self, client: CFMSTestClient):
        response = await client.server_info()
        data = assert_success(response)

        required_fields = [
            "server_name",
            "version",
            "protocol_version",
            "lockdown",
            "lockdown_reason",
            "extension_flags",
        ]
        for field in required_fields:
            assert field in data
        assert isinstance(data["extension_flags"], list)
        assert data["lockdown"] is False
        assert data["lockdown_reason"] is None

    @pytest.mark.asyncio
    async def test_unknown_action(self, client: CFMSTestClient):
        response = await client.send_request(
            "nonexistent_action_xyz_123", include_auth=False
        )
        assert_error(response, 400)


class TestAuthentication:
    @pytest.mark.asyncio
    async def test_login_success(self, client: CFMSTestClient, admin_credentials: dict):
        response = await client.login(
            admin_credentials["username"], admin_credentials["password"]
        )
        data = assert_success(response)

        assert "token" in data
        assert isinstance(data["token"], str)
        assert len(data["token"]) > 0

        assert client.token is not None
        assert client.username == admin_credentials["username"]

    @pytest.mark.asyncio
    async def test_login_invalid_credentials(self, client: CFMSTestClient):
        response = await client.login("invalid_user_xyz", "invalid_password_xyz")
        assert_error(response, 401)

    @pytest.mark.asyncio
    async def test_login_missing_username(self, client: CFMSTestClient):
        response = await client.send_request(
            "login", {"password": "test_password"}, include_auth=False
        )
        assert_error(response, 400)

    @pytest.mark.asyncio
    async def test_login_missing_password(self, client: CFMSTestClient):
        response = await client.send_request(
            "login", {"username": "test_user"}, include_auth=False
        )
        assert_error(response, 400)

    @pytest.mark.asyncio
    async def test_refresh_token(self, authenticated_client: CFMSTestClient):
        old_token = authenticated_client.token
        assert old_token is not None

        response = await authenticated_client.refresh_token()
        data = assert_success(response)

        assert "token" in data
        new_token = authenticated_client.token
        assert new_token is not None
        assert new_token != old_token

    @pytest.mark.asyncio
    async def test_authentication_required(self, client: CFMSTestClient):
        response = await client.send_request("list_users", include_auth=False)
        assert_error(response, 401)

    @pytest.mark.asyncio
    async def test_invalid_token(self, client: CFMSTestClient, admin_credentials: dict):
        # Login first to set up session structure
        await client.login(admin_credentials["username"], admin_credentials["password"])

        response = await client.send_request(
            "list_users",
            username=admin_credentials["username"],
            token="invalid_token_xyz_12345",
        )
        assert_error(response, 401)
