import pytest

from tests.support.client import CFMSTestClient
from tests.support.utils import assert_error, assert_success


class TestUserBlocksAndStatus:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("reason_data", "expected_reason"),
        [
            pytest.param(
                {"reason": "Repeated policy violations"},
                "Repeated policy violations",
                id="reason",
            ),
            pytest.param({}, None, id="omitted-reason"),
            pytest.param({"reason": None}, None, id="null-reason"),
        ],
    )
    async def test_disabled_user_cannot_login(
        self,
        authenticated_client: CFMSTestClient,
        client: CFMSTestClient,
        test_user,
        reason_data,
        expected_reason,
    ):
        username = test_user["username"]

        response = await authenticated_client.update_user_status(
            username, "disabled", **reason_data
        )

        assert_success(response)
        info = assert_success(await authenticated_client.get_user_info(username))
        assert info["status"] == 1
        error = assert_error(await client.login(username, test_user["password"]), 4003)
        assert error["data"] == {"reason": expected_reason}

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("reason_data", "expected_reason"),
        [
            pytest.param(
                {"reason": "Corrected policy violation details"},
                "Corrected policy violation details",
                id="replace",
            ),
            pytest.param({"reason": None}, None, id="clear"),
            pytest.param({}, "Initial reason", id="preserve"),
        ],
    )
    async def test_disabled_user_reason_is_updated_without_reenabling(
        self,
        authenticated_client: CFMSTestClient,
        client: CFMSTestClient,
        test_user,
        reason_data,
        expected_reason,
    ):
        username = test_user["username"]
        assert_success(
            await authenticated_client.update_user_status(
                username, "disabled", "Initial reason"
            )
        )

        response = await authenticated_client.update_user_status(
            username, "disabled", **reason_data
        )

        assert assert_success(response)["reason"] == expected_reason
        error = assert_error(await client.login(username, test_user["password"]), 4003)
        assert error["data"] == {"reason": expected_reason}

    @pytest.mark.asyncio
    async def test_reenabled_user_can_login(
        self,
        authenticated_client: CFMSTestClient,
        client: CFMSTestClient,
        test_user,
    ):
        username = test_user["username"]
        assert_success(
            await authenticated_client.update_user_status(
                username, "disabled", "Initial reason"
            )
        )

        response = await authenticated_client.update_user_status(username, "active")

        assert_success(response)
        info = assert_success(await authenticated_client.get_user_info(username))
        assert info["status"] == 0
        assert_success(await client.login(username, test_user["password"]))

    @pytest.mark.asyncio
    async def test_block_user_from_directory(
        self,
        authenticated_client: CFMSTestClient,
        user_client: CFMSTestClient,
        test_user,
        directory_factory,
    ):
        directory = await directory_factory()
        assert_success(await user_client.list_directory(directory["folder_id"]))

        response = await authenticated_client.block_user(
            test_user["username"],
            "directory",
            ["read", "write"],
            target_id=directory["folder_id"],
        )

        assert_success(response)
        assert_error(await user_client.list_directory(directory["folder_id"]), 403)

    @pytest.mark.asyncio
    async def test_list_user_blocks_with_cursor(
        self,
        authenticated_client: CFMSTestClient,
        test_user,
    ):
        username = test_user["username"]
        first = assert_success(
            await authenticated_client.block_user(
                username, "all", ["read"], reason="initial reason"
            )
        )
        second = assert_success(
            await authenticated_client.block_user(username, "all", ["write"])
        )

        first_page = assert_success(
            await authenticated_client.send_request(
                "list_user_blocks", {"username": username, "page_size": 1}
            )
        )
        second_page = assert_success(
            await authenticated_client.send_request(
                "list_user_blocks",
                {
                    "username": username,
                    "page_size": 1,
                    "cursor": first_page["next_cursor"],
                },
            )
        )

        assert len(first_page["items"]) == len(second_page["items"]) == 1
        items = first_page["items"] + second_page["items"]
        assert {item["block_id"] for item in items} == {
            first["block_id"],
            second["block_id"],
        }
        assert (
            next(item for item in items if item["block_id"] == first["block_id"])[
                "reason"
            ]
            == "initial reason"
        )
        assert first_page["has_more"] is True
        assert second_page["has_more"] is False

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "reason",
        [
            pytest.param("corrected reason", id="replace"),
            pytest.param(None, id="clear"),
        ],
    )
    async def test_user_block_reason_update_is_persisted_and_audited(
        self,
        authenticated_client: CFMSTestClient,
        test_user,
        reason,
    ):
        block = assert_success(
            await authenticated_client.block_user(
                test_user["username"], "all", ["read"], reason="initial reason"
            )
        )

        response = await authenticated_client.update_user_block(
            block["block_id"], reason
        )

        assert assert_success(response)["reason"] == reason
        page = assert_success(
            await authenticated_client.send_request(
                "list_user_blocks", {"username": test_user["username"]}
            )
        )
        assert page["items"][0]["block_id"] == block["block_id"]
        assert page["items"][0]["reason"] == reason
        entries = assert_success(
            await authenticated_client.view_audit_logs(filters=["update_user_block"])
        )["items"]
        entry = next(item for item in entries if item["target"] == block["block_id"])
        assert entry["data"]["reason_change"] == {
            "previous": "initial reason",
            "current": reason,
        }
