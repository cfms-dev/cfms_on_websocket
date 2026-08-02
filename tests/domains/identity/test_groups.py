import pytest

from tests.support.client import CFMSTestClient
from tests.support.utils import assert_error, assert_success


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
        test_group = await group_factory()
        assert test_group["group_name"]

    @pytest.mark.asyncio
    async def test_get_group_info(
        self, authenticated_client: CFMSTestClient, test_group: dict
    ):
        response = await authenticated_client.get_group_info(test_group["group_name"])
        data = assert_success(response)
        assert isinstance(data.get("permissions"), list)

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
