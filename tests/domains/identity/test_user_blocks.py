import time

import pytest

from tests.support.client import CFMSTestClient
from tests.support.utils import assert_error, assert_success


class TestUserBlocksAndStatus:
    @pytest.mark.asyncio
    async def test_update_user_status(
        self, authenticated_client: CFMSTestClient, user_factory
    ):
        # Create a user
        test_user = await user_factory()
        username = test_user["username"]

        # Disable user
        reason = "Repeated policy violations"
        disable_resp = await authenticated_client.update_user_status(
            username, "disabled", reason
        )
        assert_success(disable_resp)
        disabled_user_info = assert_success(
            await authenticated_client.get_user_info(username)
        )
        assert disabled_user_info["status"] == 1

        # Try to login as the disabled user
        user_client = CFMSTestClient()
        await user_client.connect()
        login_resp = await user_client.login(username, test_user["password"])
        assert login_resp["code"] == 4003
        assert login_resp["data"] == {"reason": reason}

        await user_client.disconnect()

        # Re-enable user
        enable_resp = await authenticated_client.update_user_status(username, "active")
        assert_success(enable_resp)
        active_user_info = assert_success(
            await authenticated_client.get_user_info(username)
        )
        assert active_user_info["status"] == 0

        # Try to login again
        user_client2 = CFMSTestClient()
        await user_client2.connect()
        login_resp2 = await user_client2.login(username, test_user["password"])
        assert_success(login_resp2)
        await user_client2.disconnect()

        # A reason is optional and is represented as null in the login response.
        assert_success(
            await authenticated_client.update_user_status(username, "disabled")
        )
        user_client3 = CFMSTestClient()
        await user_client3.connect()
        login_resp3 = await user_client3.login(username, test_user["password"])
        assert login_resp3["code"] == 4003
        assert login_resp3["data"] == {"reason": None}
        await user_client3.disconnect()
        assert_success(
            await authenticated_client.update_user_status(username, "active")
        )

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

    @pytest.mark.asyncio
    async def test_list_user_blocks_with_cursor(
        self, authenticated_client: CFMSTestClient, user_factory
    ):
        test_user = await user_factory()
        username = test_user["username"]

        first_block = assert_success(
            await authenticated_client.block_user(username, "all", ["read"])
        )
        second_block = assert_success(
            await authenticated_client.block_user(username, "all", ["write"])
        )

        first_page_response = await authenticated_client.send_request(
            "list_user_blocks", {"username": username, "page_size": 1}
        )
        first_page = assert_success(first_page_response)
        second_page_response = await authenticated_client.send_request(
            "list_user_blocks",
            {
                "username": username,
                "page_size": 1,
                "cursor": first_page["next_cursor"],
            },
        )
        second_page = assert_success(second_page_response)

        assert len(first_page["items"]) == 1
        assert len(second_page["items"]) == 1
        assert first_page["items"][0]["block_id"] != second_page["items"][0]["block_id"]

        await authenticated_client.send_request(
            "unblock_user", {"block_id": first_block["block_id"]}
        )
        await authenticated_client.send_request(
            "unblock_user", {"block_id": second_block["block_id"]}
        )
