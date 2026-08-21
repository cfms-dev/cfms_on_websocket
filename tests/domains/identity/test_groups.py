import pytest

from tests.support.client import CFMSTestClient
from tests.support.utils import assert_error, assert_success, permission_entry


class TestGroupOperations:
    @pytest.mark.asyncio
    async def test_list_groups(self, authenticated_client: CFMSTestClient):
        response = await authenticated_client.list_groups()
        data = assert_success(response)

        assert "groups" in data
        assert isinstance(data["groups"], list)
        assert data["offset"] == 0
        assert data["total"] >= len(data["groups"])
        assert data["has_more"] == (len(data["groups"]) < data["total"])

        group_names = [group.get("name") for group in data["groups"]]
        assert "sysop" in group_names
        sysop = next(group for group in data["groups"] if group["name"] == "sysop")
        assert "effective_permissions" in sysop
        assert all(isinstance(entry, dict) for entry in sysop["permissions"])

    @pytest.mark.asyncio
    async def test_list_groups_with_pagination(
        self, authenticated_client: CFMSTestClient, group_factory
    ):
        await group_factory("page_group_a")
        await group_factory("page_group_b")

        first_response = await authenticated_client.list_groups(count=1, offset=0)
        second_response = await authenticated_client.list_groups(count=1, offset=1)
        first_page = assert_success(first_response)
        second_page = assert_success(second_response)

        assert first_page["count"] == 1
        assert second_page["offset"] == 1
        assert len(first_page["groups"]) == 1
        assert len(second_page["groups"]) == 1
        assert first_page["groups"][0]["name"] != second_page["groups"][0]["name"]

    @pytest.mark.asyncio
    async def test_create_group(
        self, authenticated_client: CFMSTestClient, group_factory
    ):
        permissions = [permission_entry("list_users", granted=False)]
        test_group = await group_factory(permissions=permissions)
        assert test_group["group_name"]

        data = assert_success(
            await authenticated_client.get_group_info(test_group["group_name"])
        )
        assert data["permissions"] == permissions
        assert data["effective_permissions"] == []

    @pytest.mark.asyncio
    async def test_get_group_info(
        self, authenticated_client: CFMSTestClient, test_group: dict
    ):
        response = await authenticated_client.get_group_info(test_group["group_name"])
        data = assert_success(response)
        assert isinstance(data.get("permissions"), list)
        assert isinstance(data.get("effective_permissions"), list)

    @pytest.mark.asyncio
    async def test_change_group_permissions_replaces_structured_entries(
        self, authenticated_client: CFMSTestClient, group_factory
    ):
        group = await group_factory(permissions=[permission_entry("list_users")])
        replacement = [permission_entry("create_user", granted=False)]

        assert_success(
            await authenticated_client.change_group_permissions(
                group["group_name"], replacement
            )
        )
        data = assert_success(
            await authenticated_client.get_group_info(group["group_name"])
        )

        assert data["permissions"] == replacement
        assert data["effective_permissions"] == []

    @pytest.mark.asyncio
    async def test_group_revocation_overrides_user_and_other_group_grants(
        self,
        authenticated_client: CFMSTestClient,
        group_factory,
        user_factory,
    ):
        granting_group = await group_factory(
            permissions=[permission_entry("list_users")]
        )
        revoking_group = await group_factory(
            permissions=[permission_entry("list_users", granted=False)]
        )
        user = await user_factory(
            permissions=[permission_entry("list_users")],
            groups=[
                {"group_name": granting_group["group_name"], "start_time": 0.0},
                {"group_name": revoking_group["group_name"], "start_time": 0.0},
            ],
        )

        data = assert_success(
            await authenticated_client.get_user_info(user["username"])
        )
        assert data["effective_own_permissions"] == ["list_users"]
        assert data["effective_inherited_permissions"] == []
        assert data["effective_permissions"] == []

    @pytest.mark.asyncio
    async def test_change_group_permissions_rejects_legacy_string_entries(
        self, authenticated_client: CFMSTestClient, test_group: dict
    ):
        response = await authenticated_client.send_request(
            "change_group_permissions",
            {"group_name": test_group["group_name"], "permissions": ["list_users"]},
        )

        assert_error(response, 400)

    @pytest.mark.asyncio
    async def test_get_nonexistent_group_info(
        self, authenticated_client: CFMSTestClient
    ):
        response = await authenticated_client.get_group_info(
            "nonexistent_group_xyz_12345"
        )
        assert response.get("code") in [400, 404]

    @pytest.mark.asyncio
    async def test_delete_group(
        self, authenticated_client: CFMSTestClient, group_factory
    ):
        test_group = await group_factory("group_to_delete")
        group_name = test_group["group_name"]

        delete_response = await authenticated_client.send_request(
            "delete_group", {"group_name": group_name}
        )
        assert_success(delete_response)

        info_response = await authenticated_client.get_group_info(group_name)
        assert info_response.get("code") != 200

    @pytest.mark.asyncio
    async def test_create_group_with_duplicate_name(
        self, authenticated_client: CFMSTestClient, test_group: dict
    ):
        response = await authenticated_client.create_group(
            group_name=test_group["group_name"], permissions=[]
        )
        assert response.get("code") in [400, 409]

    @pytest.mark.asyncio
    async def test_create_group_with_empty_name(
        self, authenticated_client: CFMSTestClient
    ):
        response = await authenticated_client.create_group(
            group_name="", permissions=[]
        )
        assert_error(response, 400)

    @pytest.mark.asyncio
    async def test_get_admin_group_info(self, authenticated_client: CFMSTestClient):
        response = await authenticated_client.get_group_info("sysop")
        data = assert_success(response)
        assert isinstance(data.get("permissions"), list)


class TestGroupWithoutAuth:
    @pytest.mark.asyncio
    async def test_list_groups_without_auth(self, client: CFMSTestClient):
        response = await client.send_request("list_groups", {}, include_auth=False)
        assert_error(response, 401)

    @pytest.mark.asyncio
    async def test_create_group_without_auth(self, client: CFMSTestClient):
        response = await client.send_request(
            "create_group",
            {"group_name": "testgroup", "permissions": []},
            include_auth=False,
        )
        assert_error(response, 401)
