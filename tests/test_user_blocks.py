import time

import pytest

from tests.test_client import CFMSTestClient
from tests.utils import assert_error, assert_success


class TestUserBlocksAndStatus:
    @pytest.mark.asyncio
    async def test_update_user_status(
        self, authenticated_client: CFMSTestClient, user_factory
    ):
        # Create a user
        test_user = await user_factory()
        username = test_user["username"]

        # Disable user
        disable_resp = await authenticated_client.update_user_status(
            username, "disabled"
        )
        assert_success(disable_resp)

        # Try to login as the disabled user
        user_client = CFMSTestClient()
        await user_client.connect()
        login_resp = await user_client.login(username, test_user["password"])
        # Should be forbidden or unauthorized, or 4003 (disabled specific code)
        assert login_resp["code"] in [401, 403, 4003], (
            f"Expected 401, 403, or 4003, got {login_resp['code']}"
        )

        await user_client.disconnect()

        # Re-enable user
        enable_resp = await authenticated_client.update_user_status(username, "active")
        assert_success(enable_resp)

        # Try to login again
        user_client2 = CFMSTestClient()
        await user_client2.connect()
        login_resp2 = await user_client2.login(username, test_user["password"])
        assert_success(login_resp2)
        await user_client2.disconnect()

    @pytest.mark.asyncio
    async def test_block_user_from_directory(
        self, authenticated_client: CFMSTestClient, user_factory
    ):
        # Admin creates a folder
        dir_resp = await authenticated_client.create_directory(
            f"BlockedFolder_{int(time.time())}"
        )
        folder_id = assert_success(dir_resp)["id"]

        # Create a user
        test_user = await user_factory()
        username = test_user["username"]

        # User tries to access folder
        user_client = CFMSTestClient()
        await user_client.connect()
        await user_client.login(username, test_user["password"])

        list_resp = await user_client.list_directory(folder_id)
        assert_success(list_resp)

        # Admin blocks the user from the folder
        block_resp = await authenticated_client.block_user(
            username, "directory", ["read", "write"], target_id=folder_id
        )
        assert_success(block_resp)

        # User tries to access folder again
        list_resp_blocked = await user_client.list_directory(folder_id)
        assert_error(list_resp_blocked, 403)  # Should be Forbidden

        await user_client.disconnect()
