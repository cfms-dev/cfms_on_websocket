import pytest

from include.config.constants import (
    PAGINATION_DEFAULT_PAGE_SIZE,
    PAGINATION_MAX_PAGE_SIZE,
)
from tests.support.client import CFMSTestClient
from tests.support.utils import assert_error, assert_success, permission_entry

pytestmark = pytest.mark.integration


class TestUserOperations:
    @pytest.mark.asyncio
    async def test_rename_user_requires_authentication(self, unauthenticated_client):
        response = await unauthenticated_client.send_request(
            "core.user.rename",
            {
                "user_id": "00000000-0000-4000-8000-000000000001",
                "nickname": "unauthorized",
            },
            include_auth=False,
        )
        assert_error(response, 401)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("action", "selector_field"),
        [
            ("core.user.info.get", "username"),
            ("core.user.info.get", "user_id"),
            ("core.user.avatar.get", "user_id"),
            ("core.user.authentication.totp.status.get", "user_id"),
        ],
    )
    async def test_cross_user_lookup_does_not_disclose_user_existence(
        self,
        action: str,
        selector_field: str,
        low_privilege_client: CFMSTestClient,
        test_user: dict,
    ):
        existing_response = await low_privilege_client.send_request(
            action,
            {selector_field: test_user[selector_field]},
        )
        missing_response = await low_privilege_client.send_request(
            action,
            {
                selector_field: "nonexistent_user_xyz_12345"
                if selector_field == "username"
                else "00000000-0000-4000-8000-000000000001"
            },
        )

        for response in (existing_response, missing_response):
            assert response["code"] == 403
            assert response["data"] == {}

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
            assert response["data"] == {}

    @pytest.mark.asyncio
    async def test_password_change_requires_authentication(
        self, unauthenticated_client: CFMSTestClient, test_user: dict
    ):
        for user_id in (test_user["user_id"], "00000000-0000-4000-8000-000000000001"):
            response = await unauthenticated_client.send_request(
                "core.user.password.set",
                {"user_id": user_id, "new_passwd": "UpdatedPassword456!"},
            )
            assert_error(response, 401)
            assert response["data"] == {}

    @pytest.mark.asyncio
    async def test_password_reset_authorizes_before_disclosing_target_existence(
        self,
        low_privilege_client: CFMSTestClient,
        test_user: dict,
    ):
        responses = []
        for user_id in (
            test_user["user_id"],
            "00000000-0000-4000-8000-000000000001",
        ):
            responses.append(
                await low_privilege_client.send_request(
                    "core.user.password.set",
                    {
                        "user_id": user_id,
                        "new_passwd": "UpdatedPassword456!",
                    },
                )
            )

        for response in responses:
            assert response["code"] == 403
            assert response["data"] == {}

    @pytest.mark.asyncio
    async def test_super_password_reset_reports_missing_target(
        self,
        authenticated_client: CFMSTestClient,
    ):
        assert_success(await authenticated_client.elevate_token())
        response = await authenticated_client.send_request(
            "core.user.password.set",
            {
                "user_id": "00000000-0000-4000-8000-000000000001",
                "new_passwd": "UpdatedPassword456!",
            },
        )

        assert response["code"] == 404
        assert response["data"] == {}

    @pytest.mark.asyncio
    async def test_low_privilege_user_can_get_own_identity_security_state(
        self,
        low_privilege_client: CFMSTestClient,
    ):
        user_info = await low_privilege_client.get_user_info(
            username=low_privilege_client.username
        )
        totp_status = await low_privilege_client.get_totp_status()

        assert_success(user_info)
        assert_success(totp_status)

    @pytest.mark.asyncio
    async def test_self_password_change_requires_escalation_and_rotates_tokens(
        self,
        authenticated_client: CFMSTestClient,
        unauthenticated_client: CFMSTestClient,
        user_factory,
    ):
        user = await user_factory(
            permissions=[permission_entry("configure_auth_methods")]
        )
        username = user["username"]
        new_password = "UpdatedPassword456!"
        assert_success(await unauthenticated_client.login(username, user["password"]))
        assert_error(
            await unauthenticated_client.send_request(
                "core.user.password.set", {"new_passwd": new_password}
            ),
            403,
        )
        assert_success(await unauthenticated_client.elevate_token())
        assert_success(
            await unauthenticated_client.send_request(
                "core.user.password.set", {"new_passwd": new_password}
            )
        )
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
        admin = next(user for user in data["users"] if user["username"] == "admin")
        assert set(admin) >= {
            "permissions",
            "effective_permissions",
            "effective_own_permissions",
            "effective_inherited_permissions",
        }
        assert all(isinstance(entry, dict) for entry in admin["permissions"])

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
        permissions = [permission_entry("list_users", granted=False)]
        created_user = await user_factory(permissions=permissions)
        assert created_user["username"]

        data = assert_success(
            await authenticated_client.get_user_info(username=created_user["username"])
        )
        assert data["permissions"] == permissions
        assert data["effective_permissions"] == []

    @pytest.mark.asyncio
    async def test_get_user_info(
        self, authenticated_client: CFMSTestClient, test_user: dict
    ):
        response = await authenticated_client.get_user_info(
            username=test_user["username"]
        )
        data = assert_success(response)
        assert data["username"] == test_user["username"]
        assert data["status"] == 0

    @pytest.mark.asyncio
    async def test_get_nonexistent_user_info(
        self, authenticated_client: CFMSTestClient
    ):
        response = await authenticated_client.get_user_info(
            username="nonexistent_user_xyz_12345"
        )
        assert_error(response, 404)

    @pytest.mark.asyncio
    async def test_delete_user(
        self, authenticated_client: CFMSTestClient, user_factory
    ):
        test_user = await user_factory()
        username = test_user["username"]

        delete_response = await authenticated_client.delete_user(test_user["user_id"])
        assert_success(delete_response)

        info_response = await authenticated_client.get_user_info(username=username)
        assert_error(info_response, 404)

    @pytest.mark.asyncio
    async def test_create_user_with_duplicate_username(
        self, authenticated_client: CFMSTestClient, test_user: dict
    ):
        response = await authenticated_client.create_user(
            username=test_user["username"], password="AnotherPassword123!"
        )
        assert_error(response, 400)

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
        response = await authenticated_client.get_user_info(username="admin")
        data = assert_success(response)
        assert data["username"] == "admin"

    @pytest.mark.asyncio
    async def test_change_user_permissions(
        self, authenticated_client: CFMSTestClient, test_user: dict
    ):
        permissions = [permission_entry("list_users")]
        response = await authenticated_client.change_user_permissions(
            test_user["user_id"], permissions
        )
        assert_success(response)

        info_response = await authenticated_client.get_user_info(
            username=test_user["username"]
        )
        data = assert_success(info_response)
        assert data["permissions"] == permissions
        assert data["effective_permissions"] == ["list_users"]
        assert data["effective_own_permissions"] == ["list_users"]

        replacement = [permission_entry("get_user_info", granted=False)]
        assert_success(
            await authenticated_client.change_user_permissions(
                test_user["user_id"], replacement
            )
        )
        replaced = assert_success(
            await authenticated_client.get_user_info(username=test_user["username"])
        )
        assert replaced["permissions"] == replacement
        assert replaced["effective_permissions"] == []

    @pytest.mark.asyncio
    async def test_get_user_info_splits_own_and_inherited_permissions(
        self, authenticated_client: CFMSTestClient, user_factory, group_factory
    ):
        test_group = await group_factory(permissions=[permission_entry("list_groups")])
        test_user = await user_factory()

        permissions_response = await authenticated_client.change_user_permissions(
            test_user["user_id"], [permission_entry("list_users")]
        )
        assert_success(permissions_response)

        groups_response = await authenticated_client.send_request(
            "core.user.group.change",
            {
                "user_id": test_user["user_id"],
                "groups": [test_group["group_name"]],
            },
        )
        assert_success(groups_response)

        info_response = await authenticated_client.get_user_info(
            username=test_user["username"]
        )
        data = assert_success(info_response)

        assert data["effective_own_permissions"] == ["list_users"]
        assert data["effective_inherited_permissions"] == ["list_groups"]
        assert data["effective_permissions"] == ["list_groups", "list_users"]
        assert "own_permissions" not in data
        assert "inherited_permissions" not in data

    @pytest.mark.asyncio
    async def test_user_revocation_overrides_group_grant(
        self, authenticated_client: CFMSTestClient, user_factory, group_factory
    ):
        group = await group_factory(permissions=[permission_entry("list_users")])
        user = await user_factory(
            groups=[{"group_name": group["group_name"], "start_time": 0.0}]
        )
        permissions = [
            permission_entry("list_users", granted=False),
            permission_entry("create_user"),
            permission_entry(
                "create_user",
                granted=False,
                start_time=32503680000.0,
            ),
            permission_entry(
                "create_user",
                granted=False,
                start_time=0.0,
                end_time=1.0,
            ),
        ]

        assert_success(
            await authenticated_client.change_user_permissions(
                user["user_id"], permissions
            )
        )
        data = assert_success(
            await authenticated_client.get_user_info(username=user["username"])
        )

        assert data["permissions"] == permissions
        assert data["effective_own_permissions"] == ["create_user"]
        assert data["effective_inherited_permissions"] == ["list_users"]
        assert data["effective_permissions"] == ["create_user"]

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
            target_user["user_id"], [permission_entry("list_users")]
        )
        assert_error(response, 403)

        info_response = await authenticated_client.get_user_info(
            username=target_user["username"]
        )
        data = assert_success(info_response)
        assert "list_users" not in data["effective_permissions"]


class TestUserWithoutAuth:
    @pytest.mark.asyncio
    async def test_list_users_without_auth(self, client: CFMSTestClient):
        response = await client.send_request("core.user.list", {}, include_auth=False)
        assert_error(response, 401)

    @pytest.mark.asyncio
    async def test_create_user_without_auth(self, client: CFMSTestClient):
        response = await client.send_request(
            "core.user.create",
            {"username": "testuser", "password": "TestPassword123!"},
            include_auth=False,
        )
        assert_error(response, 401)

    @pytest.mark.asyncio
    async def test_get_user_info_without_auth(self, client: CFMSTestClient):
        response = await client.send_request(
            "core.user.info.get", {"username": "admin"}, include_auth=False
        )
        assert_error(response, 401)

    @pytest.mark.asyncio
    async def test_change_user_permissions_without_auth(self, client: CFMSTestClient):
        response = await client.send_request(
            "core.user.permission.change",
            {"user_id": "00000000-0000-4000-8000-000000000001", "permissions": []},
            include_auth=False,
        )
        assert_error(response, 401)
