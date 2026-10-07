"""
Tests for directory management operations.
"""

import pytest

from tests.support.client import CFMSTestClient
from tests.support.utils import assert_error, assert_success, permission_entry


class TestDirectoryOperations:
    """Test directory operations."""

    @pytest.mark.asyncio
    async def test_list_directory_root(self, authenticated_client: CFMSTestClient):
        """Test listing the root directory."""
        response = await authenticated_client.list_directory()

        assert response["code"] == 200
        assert "data" in response
        assert response["data"]["parent_id"] is None

    @pytest.mark.asyncio
    async def test_parent_id_hidden_without_parent_read_access(
        self,
        authenticated_client: CFMSTestClient,
        test_user,
        user_client,
        directory_factory,
    ):
        parent = await directory_factory()
        child = await directory_factory(parent_id=parent["folder_id"])
        restricted_rule = {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {
                            "rights": {
                                "match": "all",
                                "require": ["super_list_directory"],
                            }
                        }
                    ],
                }
            ]
        }
        assert_success(
            await authenticated_client.send_request(
                "set_directory_rules",
                {
                    "directory_id": parent["folder_id"],
                    "access_rules": restricted_rule,
                    "inherit_parent": False,
                },
            )
        )
        assert_success(
            await authenticated_client.grant_access(
                entity_type="user",
                entity_identifier=test_user["username"],
                target_type="directory",
                target_identifier=child["folder_id"],
                access_types=["read"],
                start_time=0,
            )
        )

        listing = assert_success(await user_client.list_directory(child["folder_id"]))
        info = assert_success(
            await user_client.send_request(
                "get_directory_info", {"directory_id": child["folder_id"]}
            )
        )

        assert listing["parent_id"] is None
        assert info["parent_id"] is None

    @pytest.mark.asyncio
    async def test_super_list_directory_keeps_parent_id_visible(
        self,
        authenticated_client: CFMSTestClient,
        test_user,
        user_client,
        directory_factory,
    ):
        parent = await directory_factory()
        child = await directory_factory(parent_id=parent["folder_id"])
        assert_success(
            await authenticated_client.send_request(
                "set_directory_rules",
                {
                    "directory_id": parent["folder_id"],
                    "access_rules": {
                        "read": [
                            {
                                "match": "all",
                                "match_groups": [
                                    {"groups": {"match": "all", "require": ["sysop"]}}
                                ],
                            }
                        ]
                    },
                    "inherit_parent": False,
                },
            )
        )
        assert_success(
            await authenticated_client.change_user_permissions(
                test_user["username"], [permission_entry("super_list_directory")]
            )
        )

        listing = assert_success(await user_client.list_directory(child["folder_id"]))

        assert listing["parent_id"] == parent["folder_id"]

    @pytest.mark.asyncio
    async def test_create_directory(
        self, authenticated_client: CFMSTestClient, directory_factory
    ):
        parent = await directory_factory()

        data = assert_success(
            await authenticated_client.create_directory(
                "Test Directory", parent_id=parent["folder_id"]
            )
        )

        info = assert_success(
            await authenticated_client.send_request(
                "get_directory_info", {"directory_id": data["id"]}
            )
        )
        assert info["name"] == "Test Directory"
        assert info["parent_id"] == parent["folder_id"]

    @pytest.mark.asyncio
    async def test_create_directory_with_empty_name(
        self, authenticated_client: CFMSTestClient
    ):
        """Test creating a directory with an empty name."""
        response = await authenticated_client.create_directory("")

        # Should fail validation
        assert response["code"] == 400

    @pytest.mark.asyncio
    async def test_create_directory_exists_ok_returns_existing_directory(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
    ):
        parent = await directory_factory()
        existing = await directory_factory(
            "Existing Directory", parent_id=parent["folder_id"]
        )

        response = await authenticated_client.send_request(
            "create_directory",
            {
                "name": existing["name"],
                "parent_id": parent["folder_id"],
                "exists_ok": True,
            },
        )

        assert assert_success(response)["id"] == existing["folder_id"]
        listing = assert_success(
            await authenticated_client.list_directory(parent["folder_id"])
        )
        assert [item["id"] for item in listing["items"]] == [existing["folder_id"]]

    @pytest.mark.asyncio
    async def test_create_directory_exists_ok_rejects_existing_document(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        document_factory,
    ):
        parent = await directory_factory()
        document = await document_factory(
            "Existing Document", folder_id=parent["folder_id"]
        )

        response = await authenticated_client.send_request(
            "create_directory",
            {
                "name": document["title"],
                "parent_id": parent["folder_id"],
                "exists_ok": True,
            },
        )

        error = assert_error(response, 409)
        assert error["data"]["duplicate_id"] == document["document_id"]

    @pytest.mark.asyncio
    async def test_name_conflict_does_not_disclose_unreadable_directory(
        self,
        authenticated_client: CFMSTestClient,
        test_user,
        user_client,
        directory_factory,
    ):
        parent = await directory_factory()
        winner = await directory_factory(
            "Hidden Name Winner", parent_id=parent["folder_id"]
        )
        assert_success(
            await authenticated_client.send_request(
                "set_directory_rules",
                {
                    "directory_id": winner["folder_id"],
                    "inherit_parent": False,
                    "access_rules": {
                        "read": [
                            {
                                "match": "all",
                                "match_groups": [
                                    {"groups": {"match": "all", "require": ["sysop"]}}
                                ],
                            }
                        ]
                    },
                },
            )
        )
        assert_success(
            await authenticated_client.change_user_permissions(
                test_user["username"],
                [
                    permission_entry("create_directory"),
                    permission_entry("super_create_directory"),
                ],
            )
        )
        assert_success(
            await authenticated_client.grant_access(
                entity_type="user",
                entity_identifier=test_user["username"],
                target_type="directory",
                target_identifier=parent["folder_id"],
                access_types=["read", "write"],
                start_time=0,
            )
        )
        assert_success(await user_client.list_directory(parent["folder_id"]))
        assert_error(
            await user_client.send_request(
                "get_directory_info", {"directory_id": winner["folder_id"]}
            ),
            403,
        )

        response = await user_client.send_request(
            "create_directory",
            {
                "name": winner["name"],
                "parent_id": parent["folder_id"],
                "exists_ok": True,
            },
        )

        error = assert_error(response, 409)
        assert error["data"]["id"] is None
        assert "duplicate_id" not in error["data"]

    @pytest.mark.asyncio
    async def test_directory_move_conflict_preserves_parent_and_reports_winner(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        document_factory,
    ):
        source = await directory_factory()
        target = await directory_factory()
        moving = await directory_factory("Moving Folder", parent_id=source["folder_id"])
        winner = await document_factory(moving["name"], folder_id=target["folder_id"])

        response = await authenticated_client.move_directory(
            moving["folder_id"], target["folder_id"]
        )

        error = assert_error(response, 409)
        assert error["data"]["duplicate_id"] == winner["document_id"]
        info = assert_success(
            await authenticated_client.send_request(
                "get_directory_info", {"directory_id": moving["folder_id"]}
            )
        )
        assert info["parent_id"] == source["folder_id"]

    @pytest.mark.asyncio
    async def test_directory_rename_conflict_preserves_name_and_reports_winner(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        document_factory,
    ):
        parent = await directory_factory()
        moving = await directory_factory("Moving Folder", parent_id=parent["folder_id"])
        winner = await document_factory("Rename Winner", folder_id=parent["folder_id"])

        response = await authenticated_client.send_request(
            "rename_directory",
            {"folder_id": moving["folder_id"], "new_name": winner["title"]},
        )

        error = assert_error(response, 409)
        assert error["data"]["duplicate_id"] == winner["document_id"]
        info = assert_success(
            await authenticated_client.send_request(
                "get_directory_info", {"directory_id": moving["folder_id"]}
            )
        )
        assert info["name"] == moving["name"]

    @pytest.mark.asyncio
    async def test_delete_directory(
        self, authenticated_client: CFMSTestClient, directory_factory
    ):
        directory = await directory_factory()

        response = await authenticated_client.delete_directory(directory["folder_id"])

        assert_success(response)
        assert_error(
            await authenticated_client.list_directory(directory["folder_id"]), 404
        )

    @pytest.mark.asyncio
    async def test_delete_nonexistent_directory(
        self, authenticated_client: CFMSTestClient
    ):
        response = await authenticated_client.delete_directory("nonexistent_folder_id")

        assert_error(response, 404)

    @pytest.mark.asyncio
    async def test_list_directory_contents(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        document_factory,
    ):
        parent = await directory_factory()
        child = await directory_factory("Listed Child", parent_id=parent["folder_id"])
        document = await document_factory(
            "Listed Document", folder_id=parent["folder_id"]
        )

        data = assert_success(
            await authenticated_client.list_directory(parent["folder_id"])
        )

        assert {item["id"]: item["type"] for item in data["items"]} == {
            child["folder_id"]: "directory",
            document["document_id"]: "document",
        }

    @pytest.mark.asyncio
    async def test_list_directory_cursor_returns_each_child_once(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
    ):
        parent = await directory_factory()
        first_child = await directory_factory(
            "Cursor Child A", parent_id=parent["folder_id"]
        )
        second_child = await directory_factory(
            "Cursor Child B", parent_id=parent["folder_id"]
        )

        first_page = assert_success(
            await authenticated_client.list_directory(parent["folder_id"], page_size=1)
        )
        second_page = assert_success(
            await authenticated_client.list_directory(
                parent["folder_id"], page_size=1, cursor=first_page["next_cursor"]
            )
        )

        assert [item["id"] for item in first_page["items"]] == [
            first_child["folder_id"]
        ]
        assert [item["id"] for item in second_page["items"]] == [
            second_child["folder_id"]
        ]
        assert first_page["has_more"] is True
        assert second_page["has_more"] is False
        assert second_page["next_cursor"] is None

    @pytest.mark.asyncio
    async def test_get_directory_info_counts_active_direct_children(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        document_factory,
    ):
        parent = await directory_factory()
        await directory_factory(parent_id=parent["folder_id"])
        await document_factory("Active Document", folder_id=parent["folder_id"])
        await document_factory(
            "Inactive Document", upload_file=None, folder_id=parent["folder_id"]
        )

        info = assert_success(
            await authenticated_client.send_request(
                "get_directory_info", {"directory_id": parent["folder_id"]}
            )
        )

        assert info["directory_id"] == parent["folder_id"]
        assert info["count_of_child"] == 2
        assert info["parent_id"] == "/"
        assert info["name"] == parent["name"]
        assert "created_time" in info
        assert "access_rules" in info
        assert "info_code" in info


class TestDirectoryMove:
    """Test directory move operations."""

    @pytest.mark.asyncio
    async def test_move_directory_to_root(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
    ):
        parent = await directory_factory()
        child = await directory_factory(parent_id=parent["folder_id"])

        response = await authenticated_client.move_directory(child["folder_id"], None)

        assert_success(response)
        info = assert_success(
            await authenticated_client.send_request(
                "get_directory_info", {"directory_id": child["folder_id"]}
            )
        )
        assert info["parent_id"] == "/"
        parent_listing = assert_success(
            await authenticated_client.list_directory(parent["folder_id"])
        )
        assert parent_listing["items"] == []

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "target_depth",
        [
            pytest.param(0, id="self"),
            pytest.param(1, id="child"),
            pytest.param(2, id="grandchild"),
        ],
    )
    async def test_move_directory_into_its_subtree_is_rejected(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
        target_depth,
    ):
        parent = await directory_factory()
        target = parent
        for _ in range(target_depth):
            target = await directory_factory(parent_id=target["folder_id"])

        response = await authenticated_client.move_directory(
            parent["folder_id"], target["folder_id"]
        )

        error = assert_error(response, 400)
        assert "subdirectory" in error["message"].lower()
        info = assert_success(
            await authenticated_client.send_request(
                "get_directory_info", {"directory_id": parent["folder_id"]}
            )
        )
        assert info["parent_id"] == "/"

    @pytest.mark.asyncio
    async def test_move_directory_to_sibling(
        self,
        authenticated_client: CFMSTestClient,
        directory_factory,
    ):
        parent = await directory_factory()
        first = await directory_factory(parent_id=parent["folder_id"])
        second = await directory_factory(parent_id=parent["folder_id"])

        response = await authenticated_client.move_directory(
            second["folder_id"], first["folder_id"]
        )

        assert_success(response)
        info = assert_success(
            await authenticated_client.send_request(
                "get_directory_info", {"directory_id": second["folder_id"]}
            )
        )
        assert info["parent_id"] == first["folder_id"]
        listing = assert_success(
            await authenticated_client.list_directory(first["folder_id"])
        )
        assert [item["id"] for item in listing["items"]] == [second["folder_id"]]


class TestDirectoryWithoutAuth:
    """Test that directory operations require authentication."""

    @pytest.mark.asyncio
    async def test_list_directory_without_auth(self, client: CFMSTestClient):
        """Test that listing directories requires authentication."""
        response = await client.send_request(
            "list_directory", {"folder_id": None}, include_auth=False
        )

        assert response["code"] == 401

    @pytest.mark.asyncio
    async def test_create_directory_without_auth(self, client: CFMSTestClient):
        """Test that creating a directory requires authentication."""
        response = await client.send_request(
            "create_directory", {"name": "Test"}, include_auth=False
        )

        assert response["code"] == 401
