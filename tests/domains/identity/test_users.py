import pytest

from include.config.constants import (
    PAGINATION_DEFAULT_PAGE_SIZE,
    PAGINATION_MAX_PAGE_SIZE,
)
from tests.support.client import CFMSTestClient
from tests.support.utils import assert_error, assert_success


class TestUserOperations:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("action", "username_field"),
        [
            ("get_user_info", "username"),
            ("get_user_avatar", "username"),
            ("get_2fa_status", "target"),
        ],
    )
    async def test_cross_user_lookup_does_not_disclose_user_existence(
        self,
        action: str,
        username_field: str,
        low_privilege_client: CFMSTestClient,
        test_user: dict,
    ):
        existing_response = await low_privilege_client.send_request(
            action,
            {username_field: test_user["username"]},
        )
        missing_response = await low_privilege_client.send_request(
            action,
            {username_field: "nonexistent_user_xyz_12345"},
        )

        for response in (existing_response, missing_response):
            assert response["code"] == 403
            assert response["data"] == {}
        assert existing_response["message"] == missing_response["message"]

    @pytest.mark.asyncio
    async def test_invalid_login_does_not_disclose_user_existence(
        self,
        unauthenticated_client: CFMSTestClient,
        test_user: dict,
    ):
        existing_response = await unauthenticated_client.login(
            test_user["username"], "incorrect-password"
        )
        missing_response = await unauthenticated_client.login(
            "nonexistent_user_xyz_12345", "incorrect-password"
        )

        for response in (existing_response, missing_response):
            assert response["code"] == 401
            assert response["message"] == "Invalid credentials"
            assert response["data"] == {}

    @pytest.mark.asyncio
    async def test_password_change_does_not_disclose_user_existence(
        self,
        unauthenticated_client: CFMSTestClient,
        test_user: dict,
    ):
        responses = []
        for username in (
            test_user["username"],
            "nonexistent_user_xyz_12345",
        ):
            responses.append(
                await unauthenticated_client.send_request(
                    "set_passwd",
                    {
                        "username": username,
                        "old_passwd": "incorrect-password",
                        "new_passwd": "UpdatedPassword456!",
                        "bypass_passwd_requirements": True,
                    },
                )
            )

        for response in responses:
            assert response["code"] == 401
            assert response["message"] == "Invalid credentials"
            assert response["data"] == {}

    @pytest.mark.asyncio
    async def test_password_reset_authorizes_before_disclosing_target_existence(
        self,
        low_privilege_client: CFMSTestClient,
        test_user: dict,
    ):
        responses = []
        for username in (
            test_user["username"],
            "nonexistent_user_xyz_12345",
        ):
            responses.append(
                await low_privilege_client.send_request(
                    "set_passwd",
                    {
                        "username": username,
                        "new_passwd": "UpdatedPassword456!",
                    },
                )
            )

        for response in responses:
            assert response["code"] == 403
            assert (
                response["message"] == "You do not have permission to set user password"
            )
            assert response["data"] == {}

    @pytest.mark.asyncio
    async def test_super_password_reset_reports_missing_target(
        self,
        authenticated_client: CFMSTestClient,
    ):
        response = await authenticated_client.send_request(
            "set_passwd",
            {
                "username": "nonexistent_user_xyz_12345",
                "new_passwd": "UpdatedPassword456!",
            },
        )

        assert response["code"] == 404
        assert response["message"] == "User does not exist"
        assert response["data"] == {}

    @pytest.mark.asyncio
    async def test_low_privilege_user_can_get_own_identity_security_state(
        self,
        low_privilege_client: CFMSTestClient,
    ):
        user_info = await low_privilege_client.get_user_info(
            low_privilege_client.username
        )
        two_factor_status = await low_privilege_client.get_2fa_status()

        assert_success(user_info)
        assert_success(two_factor_status)

    @pytest.mark.asyncio
    async def test_self_password_change_is_throttled_and_can_recover(
        self,
        authenticated_client: CFMSTestClient,
        unauthenticated_client: CFMSTestClient,
        user_factory,
    ):
        user = await user_factory()
        username = user["username"]
        new_password = "UpdatedPassword456!"
        assert_success(
            await authenticated_client.change_user_permissions(username, ["set_passwd"])
        )

        failed = await unauthenticated_client.send_request(
            "set_passwd",
            {
                "username": username,
                "old_passwd": "wrong-password",
                "new_passwd": new_password,
            },
        )
        assert_error(failed, 401)
        assert_success(await unauthenticated_client.login(username, user["password"]))

        changed = await unauthenticated_client.send_request(
            "set_passwd",
            {
                "username": username,
                "old_passwd": user["password"],
                "new_passwd": new_password,
            },
        )
        assert_success(changed)
        assert_error(await unauthenticated_client.refresh_token(), 401)
        assert_error(
            await unauthenticated_client.login(username, user["password"]), 401
        )
        assert_success(await unauthenticated_client.login(username, new_password))

    @pytest.mark.asyncio
    async def test_list_users(self, authenticated_client: CFMSTestClient):
        response = await authenticated_client.list_users()
        data = assert_success(response)

        assert "users" in data
        assert isinstance(data["users"], list)
        assert data["offset"] == 0
        assert data["count"] == PAGINATION_DEFAULT_PAGE_SIZE
        assert data["total"] >= len(data["users"])
        assert data["has_more"] == (len(data["users"]) < data["total"])

        usernames = [user.get("username") for user in data["users"]]
        assert "admin" in usernames

    @pytest.mark.asyncio
    async def test_list_users_with_pagination(
        self, authenticated_client: CFMSTestClient, user_factory
    ):
        for suffix in range(3):
            await user_factory(username=f"page_user_{suffix}")

        first_response = await authenticated_client.list_users(count=2, offset=0)
        first_page = assert_success(first_response)
        second_response = await authenticated_client.list_users(count=2, offset=2)
        second_page = assert_success(second_response)

        assert first_page["offset"] == 0
        assert first_page["count"] == 2
        assert len(first_page["users"]) == 2
        assert second_page["offset"] == 2
        assert second_page["count"] == 2
        assert len(second_page["users"]) == 2
        assert first_page["total"] == second_page["total"]
        assert first_page["has_more"] == (2 < first_page["total"])
        assert second_page["has_more"] == (4 < second_page["total"])

        first_usernames = [user["username"] for user in first_page["users"]]
        second_usernames = [user["username"] for user in second_page["users"]]
        assert first_usernames == sorted(first_usernames)
        assert second_usernames == sorted(second_usernames)
        assert set(first_usernames).isdisjoint(second_usernames)

    @pytest.mark.asyncio
    async def test_list_users_rejects_invalid_pagination(
        self, authenticated_client: CFMSTestClient
    ):
        assert_error(await authenticated_client.list_users(count=0), 400)
        assert_error(
            await authenticated_client.list_users(count=PAGINATION_MAX_PAGE_SIZE + 1),
            400,
        )
        assert_error(await authenticated_client.list_users(offset=-1), 400)

    @pytest.mark.asyncio
    async def test_create_user(
        self, authenticated_client: CFMSTestClient, user_factory
    ):
        created_user = await user_factory()
        assert created_user["username"]

    @pytest.mark.asyncio
    async def test_get_user_info(
        self, authenticated_client: CFMSTestClient, test_user: dict
    ):
        response = await authenticated_client.get_user_info(test_user["username"])
        data = assert_success(response)
        assert data["username"] == test_user["username"]
        assert data["status"] == 0

    @pytest.mark.asyncio
    async def test_get_nonexistent_user_info(
        self, authenticated_client: CFMSTestClient
    ):
        response = await authenticated_client.get_user_info(
            "nonexistent_user_xyz_12345"
        )
        code = response.get("code")
        assert code in [400, 404], f"Expected 400 or 404, got {code}"

    @pytest.mark.asyncio
    async def test_delete_user(
        self, authenticated_client: CFMSTestClient, user_factory
    ):
        test_user = await user_factory()
        username = test_user["username"]

        delete_response = await authenticated_client.delete_user(username)
        assert_success(delete_response)

        info_response = await authenticated_client.get_user_info(username)
        assert info_response.get("code") != 200

    @pytest.mark.asyncio
    async def test_create_user_with_duplicate_username(
        self, authenticated_client: CFMSTestClient, test_user: dict
    ):
        response = await authenticated_client.create_user(
            username=test_user["username"], password="AnotherPassword123!"
        )
        assert response.get("code") in [400, 409]

    @pytest.mark.asyncio
    async def test_create_user_with_empty_username(
        self, authenticated_client: CFMSTestClient
    ):
        response = await authenticated_client.create_user(
            username="", password="TestPassword123!"
        )
        assert_error(response, 400)

    @pytest.mark.asyncio
    async def test_get_admin_user_info(self, authenticated_client: CFMSTestClient):
        response = await authenticated_client.get_user_info("admin")
        data = assert_success(response)
        assert data["username"] == "admin"

    @pytest.mark.asyncio
    async def test_change_user_permissions(
        self, authenticated_client: CFMSTestClient, test_user: dict
    ):
        response = await authenticated_client.change_user_permissions(
            test_user["username"], ["list_users"]
        )
        assert_success(response)

        info_response = await authenticated_client.get_user_info(test_user["username"])
        data = assert_success(info_response)
        assert "list_users" in data["permissions"]

    @pytest.mark.asyncio
    async def test_get_user_info_splits_own_and_inherited_permissions(
        self, authenticated_client: CFMSTestClient, user_factory, group_factory
    ):
        test_group = await group_factory(
            permissions=[{"permission": "list_groups", "start_time": 0}]
        )
        test_user = await user_factory()

        permissions_response = await authenticated_client.change_user_permissions(
            test_user["username"], ["list_users"]
        )
        assert_success(permissions_response)

        groups_response = await authenticated_client.send_request(
            "change_user_groups",
            {
                "username": test_user["username"],
                "groups": [test_group["group_name"]],
            },
        )
        assert_success(groups_response)

        info_response = await authenticated_client.get_user_info(test_user["username"])
        data = assert_success(info_response)

        assert "list_users" in data["own_permissions"]
        assert "list_groups" in data["inherited_permissions"]
        assert "list_users" in data["permissions"]
        assert "list_groups" in data["permissions"]

    @pytest.mark.asyncio
    async def test_change_user_permissions_requires_set_user_permissions(
        self,
        authenticated_client: CFMSTestClient,
        unauthenticated_client: CFMSTestClient,
        user_factory,
    ):
        operator_user = await user_factory()
        target_user = await user_factory()

        login_response = await unauthenticated_client.login(
            operator_user["username"], operator_user["password"]
        )
        assert_success(login_response)

        response = await unauthenticated_client.change_user_permissions(
            target_user["username"], ["list_users"]
        )
        error = assert_error(response, 403)
        assert error["message"] == "You do not have permission to set user permissions"

        info_response = await authenticated_client.get_user_info(
            target_user["username"]
        )
        data = assert_success(info_response)
        assert "list_users" not in data["permissions"]


class TestUserWithoutAuth:
    @pytest.mark.asyncio
    async def test_list_users_without_auth(self, client: CFMSTestClient):
        response = await client.send_request("list_users", {}, include_auth=False)
        assert_error(response, 401)

    @pytest.mark.asyncio
    async def test_create_user_without_auth(self, client: CFMSTestClient):
        response = await client.send_request(
            "create_user",
            {"username": "testuser", "password": "TestPassword123!"},
            include_auth=False,
        )
        assert_error(response, 401)

    @pytest.mark.asyncio
    async def test_get_user_info_without_auth(self, client: CFMSTestClient):
        response = await client.send_request(
            "get_user_info", {"username": "admin"}, include_auth=False
        )
        assert_error(response, 401)

    @pytest.mark.asyncio
    async def test_change_user_permissions_without_auth(self, client: CFMSTestClient):
        response = await client.send_request(
            "change_user_permissions",
            {"username": "admin", "permissions": []},
            include_auth=False,
        )
        assert_error(response, 401)
