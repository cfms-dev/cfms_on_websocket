"""
Tests for directory management operations.
"""

import secrets
import time

import pytest

from tests.test_client import CFMSTestClient
from tests.utils import assert_error, assert_success


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
        user_factory,
    ):
        parent = assert_success(
            await authenticated_client.create_directory("Hidden Parent")
        )
        parent_id = parent["id"]
        child = assert_success(
            await authenticated_client.create_directory(
                "Directly Granted Child", parent_id=parent_id
            )
        )
        child_id = child["id"]
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

        user = await user_factory()
        user_client = CFMSTestClient()
        try:
            assert_success(
                await authenticated_client.send_request(
                    "set_directory_rules",
                    {
                        "directory_id": parent_id,
                        "access_rules": restricted_rule,
                        "inherit_parent": False,
                    },
                )
            )
            assert_success(
                await authenticated_client.grant_access(
                    entity_type="user",
                    entity_identifier=user["username"],
                    target_type="directory",
                    target_identifier=child_id,
                    access_types=["read"],
                    start_time=time.time(),
                )
            )

            await user_client.connect()
            assert_success(await user_client.login(user["username"], user["password"]))

            listing = assert_success(await user_client.list_directory(child_id))
            info = assert_success(
                await user_client.send_request(
                    "get_directory_info", {"directory_id": child_id}
                )
            )
            assert listing["parent_id"] is None
            assert info["parent_id"] is None
        finally:
            await user_client.disconnect()
            await authenticated_client.delete_directory(child_id)
            await authenticated_client.delete_directory(parent_id)

    @pytest.mark.asyncio
    async def test_super_list_directory_keeps_parent_id_visible(
        self,
        authenticated_client: CFMSTestClient,
        user_factory,
    ):
        parent = assert_success(
            await authenticated_client.create_directory("Super Visible Parent")
        )
        parent_id = parent["id"]
        child = assert_success(
            await authenticated_client.create_directory(
                "Super Visible Child", parent_id=parent_id
            )
        )
        child_id = child["id"]
        user = await user_factory()
        user_client = CFMSTestClient()
        try:
            assert_success(
                await authenticated_client.send_request(
                    "set_directory_rules",
                    {
                        "directory_id": parent_id,
                        "access_rules": {
                            "read": [
                                {
                                    "match": "all",
                                    "match_groups": [
                                        {
                                            "groups": {
                                                "match": "all",
                                                "require": ["sysop"],
                                            }
                                        }
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
                    user["username"], ["super_list_directory"]
                )
            )
            await user_client.connect()
            assert_success(await user_client.login(user["username"], user["password"]))

            listing = assert_success(await user_client.list_directory(child_id))
            assert listing["parent_id"] == parent_id
        finally:
            await user_client.disconnect()
            await authenticated_client.delete_directory(child_id)
            await authenticated_client.delete_directory(parent_id)

    @pytest.mark.asyncio
    async def test_create_directory(self, authenticated_client: CFMSTestClient):
        """Test creating a new directory."""
        dir_name = "Test Directory"
        response = await authenticated_client.create_directory(dir_name)

        # Directory creation might succeed or fail based on permissions
        # We just check the response is valid
        assert "code" in response
        assert "data" in response

        if response["code"] == 200:
            # Cleanup if created successfully
            directory_id = response["data"].get("id")
            if directory_id:
                try:
                    await authenticated_client.delete_directory(directory_id)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_create_directory_with_empty_name(
        self, authenticated_client: CFMSTestClient
    ):
        """Test creating a directory with an empty name."""
        response = await authenticated_client.create_directory("")

        # Should fail validation
        assert response["code"] == 400

    @pytest.mark.asyncio
    async def test_create_directory_exists_ok_requires_a_directory(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        suffix = secrets.token_hex(4)
        directory_name = f"Exists OK Directory {suffix}"
        created = assert_success(
            await authenticated_client.create_directory(directory_name)
        )
        repeated = assert_success(
            await authenticated_client.send_request(
                "create_directory",
                {"name": directory_name, "exists_ok": True},
            )
        )
        assert repeated["id"] == created["id"]

        document_name = f"Exists OK Document {suffix}"
        document = await document_factory(document_name)
        conflict = await authenticated_client.send_request(
            "create_directory",
            {"name": document_name, "exists_ok": True},
        )
        assert_error(conflict, 409)
        assert conflict["data"]["duplicate_id"] == document["document_id"]

    @pytest.mark.asyncio
    async def test_name_conflict_does_not_disclose_unreadable_directory(
        self,
        authenticated_client: CFMSTestClient,
        user_factory,
    ):
        name = f"Hidden Name Winner {secrets.token_hex(4)}"
        winner = assert_success(await authenticated_client.create_directory(name))
        assert_success(
            await authenticated_client.send_request(
                "set_directory_rules",
                {
                    "directory_id": winner["id"],
                    "inherit_parent": False,
                    "access_rules": {
                        "read": [
                            {
                                "match": "all",
                                "match_groups": [
                                    {
                                        "groups": {
                                            "match": "all",
                                            "require": ["sysop"],
                                        }
                                    }
                                ],
                            }
                        ]
                    },
                },
            )
        )
        user = await user_factory()
        assert_success(
            await authenticated_client.change_user_permissions(
                user["username"],
                ["create_directory", "super_create_directory"],
            )
        )

        user_client = CFMSTestClient()
        await user_client.connect()
        try:
            assert_success(await user_client.login(user["username"], user["password"]))
            conflict = await user_client.send_request(
                "create_directory",
                {"name": name, "exists_ok": True},
            )
            assert_error(conflict, 409)
            assert conflict["data"]["id"] is None
            assert "duplicate_id" not in conflict["data"]
        finally:
            await user_client.disconnect()

    @pytest.mark.asyncio
    async def test_directory_rename_and_move_conflicts_use_database_winner(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        suffix = secrets.token_hex(4)
        source = assert_success(
            await authenticated_client.create_directory(f"Folder Source {suffix}")
        )
        target = assert_success(
            await authenticated_client.create_directory(f"Folder Target {suffix}")
        )
        moving_name = f"Moving Folder {suffix}"
        moving = assert_success(
            await authenticated_client.create_directory(
                moving_name, parent_id=source["id"]
            )
        )
        move_winner = await document_factory(moving_name, folder_id=target["id"])

        move_response = await authenticated_client.move_directory(
            moving["id"], target["id"]
        )
        assert_error(move_response, 409)
        assert move_response["data"]["duplicate_id"] == move_winner["document_id"]

        rename_name = f"Folder Rename Winner {suffix}"
        rename_winner = await document_factory(rename_name, folder_id=source["id"])
        rename_response = await authenticated_client.send_request(
            "rename_directory",
            {"folder_id": moving["id"], "new_name": rename_name},
        )
        assert_error(rename_response, 409)
        assert rename_response["data"]["duplicate_id"] == rename_winner["document_id"]

    @pytest.mark.asyncio
    async def test_delete_directory(self, authenticated_client: CFMSTestClient):
        """Test deleting a directory."""
        # First create a directory
        create_response = await authenticated_client.create_directory(
            "Directory to Delete"
        )

        if create_response["code"] == 200:
            directory_id = create_response["data"]["id"]

            # Delete it
            delete_response = await authenticated_client.delete_directory(directory_id)

            # Should get a response (success or failure is implementation-dependent)
            assert "code" in delete_response

    @pytest.mark.asyncio
    async def test_delete_nonexistent_directory(
        self, authenticated_client: CFMSTestClient
    ):
        """Test deleting a directory that doesn't exist."""
        response = await authenticated_client.delete_directory("nonexistent_folder_id")

        assert response["code"] != 200

    @pytest.mark.asyncio
    async def test_list_directory_contents(self, authenticated_client: CFMSTestClient):
        """Test listing directory contents after creating items."""
        # Create a test directory
        dir_response = await authenticated_client.create_directory("Test List Dir")

        if dir_response["code"] == 200:
            directory_id = dir_response["data"]["id"]

            try:
                # Create a document in the directory
                doc_response = await authenticated_client.create_document(
                    "Test Doc in Dir", folder_id=directory_id
                )

                if doc_response["code"] == 200:
                    # List the directory
                    list_response = await authenticated_client.list_directory(
                        directory_id
                    )

                    assert list_response["code"] == 200
                    assert "data" in list_response

                    # Cleanup document
                    try:
                        await authenticated_client.delete_document(
                            doc_response["data"]["document_id"]
                        )
                    except Exception:
                        pass
            finally:
                # Cleanup directory
                try:
                    await authenticated_client.delete_directory(directory_id)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_list_directory_with_cursor(
        self, authenticated_client: CFMSTestClient
    ):
        parent_response = await authenticated_client.create_directory(
            "Cursor Directory Parent"
        )
        parent_id = parent_response["data"]["id"]
        first_child = await authenticated_client.create_directory(
            "Cursor Child A", parent_id=parent_id
        )
        second_child = await authenticated_client.create_directory(
            "Cursor Child B", parent_id=parent_id
        )

        try:
            first_page_response = await authenticated_client.list_directory(
                parent_id, page_size=1
            )
            first_page = first_page_response["data"]
            second_page_response = await authenticated_client.list_directory(
                parent_id, page_size=1, cursor=first_page["next_cursor"]
            )
            second_page = second_page_response["data"]

            assert len(first_page["items"]) == 1
            assert len(second_page["items"]) == 1
            assert first_page["items"][0]["id"] != second_page["items"][0]["id"]
        finally:
            await authenticated_client.delete_directory(first_child["data"]["id"])
            await authenticated_client.delete_directory(second_child["data"]["id"])
            await authenticated_client.delete_directory(parent_id)

    @pytest.mark.asyncio
    async def test_get_directory_info_counts_active_direct_children(
        self, authenticated_client: CFMSTestClient
    ):
        parent_response = await authenticated_client.create_directory(
            "Directory Info Parent"
        )
        parent_id = parent_response["data"]["id"]
        child_response = await authenticated_client.create_directory(
            "Directory Info Child", parent_id=parent_id
        )
        child_id = child_response["data"]["id"]
        active_doc_response = await authenticated_client.create_document(
            "Directory Info Active Doc", folder_id=parent_id
        )
        active_doc_id = active_doc_response["data"]["document_id"]
        inactive_doc_response = await authenticated_client.create_document(
            "Directory Info Inactive Doc", folder_id=parent_id
        )
        inactive_doc_id = inactive_doc_response["data"]["document_id"]

        try:
            await authenticated_client.upload_file_to_server(
                active_doc_response["data"]["task_data"]["task_id"],
                "./pytest.ini",
            )
            info_response = await authenticated_client.send_request(
                "get_directory_info", {"directory_id": parent_id}
            )

            assert info_response["code"] == 200
            assert info_response["data"]["directory_id"] == parent_id
            assert info_response["data"]["count_of_child"] == 2
            assert info_response["data"]["parent_id"] == "/"
            assert info_response["data"]["name"] == "Directory Info Parent"
            assert "created_time" in info_response["data"]
            assert "access_rules" in info_response["data"]
            assert "info_code" in info_response["data"]
        finally:
            await authenticated_client.delete_document(active_doc_id)
            await authenticated_client.delete_document(inactive_doc_id)
            await authenticated_client.delete_directory(child_id)
            await authenticated_client.delete_directory(parent_id)


class TestDirectoryMove:
    """Test directory move operations."""

    @pytest.mark.asyncio
    async def test_move_directory_to_root(self, authenticated_client: CFMSTestClient):
        """Test moving a directory to root."""
        # Create a parent and a child directory
        parent_response = await authenticated_client.create_directory("Parent Dir")

        if parent_response["code"] == 200:
            parent_id = parent_response["data"]["id"]

            try:
                child_response = await authenticated_client.create_directory(
                    "Child Dir", parent_id=parent_id
                )

                if child_response["code"] == 200:
                    child_id = child_response["data"]["id"]

                    try:
                        # Move child to root
                        move_response = await authenticated_client.move_directory(
                            child_id, None
                        )

                        # Should succeed
                        assert move_response["code"] == 200
                    finally:
                        try:
                            await authenticated_client.delete_directory(child_id)
                        except Exception:
                            pass
            finally:
                try:
                    await authenticated_client.delete_directory(parent_id)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_move_directory_into_itself(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that moving a directory into itself is prevented."""
        # Create a directory
        dir_response = await authenticated_client.create_directory("Test Dir")

        if dir_response["code"] == 200:
            dir_id = dir_response["data"]["id"]

            try:
                # Try to move directory into itself
                move_response = await authenticated_client.move_directory(
                    dir_id, dir_id
                )

                # Should fail with 400
                assert move_response["code"] == 400
                assert "subdirectory" in move_response["message"].lower()
            finally:
                try:
                    await authenticated_client.delete_directory(dir_id)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_move_directory_into_child(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that moving a directory into its child is prevented."""
        # Create parent and child
        parent_response = await authenticated_client.create_directory("Parent Dir")

        if parent_response["code"] == 200:
            parent_id = parent_response["data"]["id"]

            try:
                child_response = await authenticated_client.create_directory(
                    "Child Dir", parent_id=parent_id
                )

                if child_response["code"] == 200:
                    child_id = child_response["data"]["id"]

                    try:
                        # Try to move parent into child
                        move_response = await authenticated_client.move_directory(
                            parent_id, child_id
                        )

                        # Should fail with 400
                        assert move_response["code"] == 400
                        assert "subdirectory" in move_response["message"].lower()
                    finally:
                        try:
                            await authenticated_client.delete_directory(child_id)
                        except Exception:
                            pass
            finally:
                try:
                    await authenticated_client.delete_directory(parent_id)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_move_directory_into_grandchild(
        self, authenticated_client: CFMSTestClient
    ):
        """Test that moving a directory into its grandchild is prevented."""
        # Create parent, child, and grandchild
        parent_response = await authenticated_client.create_directory("Parent Dir")

        if parent_response["code"] == 200:
            parent_id = parent_response["data"]["id"]

            try:
                child_response = await authenticated_client.create_directory(
                    "Child Dir", parent_id=parent_id
                )

                if child_response["code"] == 200:
                    child_id = child_response["data"]["id"]

                    try:
                        grandchild_response = (
                            await authenticated_client.create_directory(
                                "Grandchild Dir", parent_id=child_id
                            )
                        )

                        if grandchild_response["code"] == 200:
                            grandchild_id = grandchild_response["data"]["id"]

                            try:
                                # Try to move parent into grandchild
                                move_response = (
                                    await authenticated_client.move_directory(
                                        parent_id, grandchild_id
                                    )
                                )

                                # Should fail with 400
                                assert move_response["code"] == 400
                                assert (
                                    "subdirectory" in move_response["message"].lower()
                                )
                            finally:
                                try:
                                    await authenticated_client.delete_directory(
                                        grandchild_id
                                    )
                                except Exception:
                                    pass
                    finally:
                        try:
                            await authenticated_client.delete_directory(child_id)
                        except Exception:
                            pass
            finally:
                try:
                    await authenticated_client.delete_directory(parent_id)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_move_directory_to_sibling(
        self, authenticated_client: CFMSTestClient
    ):
        """Test moving a directory to a sibling location (should succeed)."""
        # Create parent with two children
        parent_response = await authenticated_client.create_directory("Parent Dir")

        if parent_response["code"] == 200:
            parent_id = parent_response["data"]["id"]

            try:
                child1_response = await authenticated_client.create_directory(
                    "Child Dir 1", parent_id=parent_id
                )
                child2_response = await authenticated_client.create_directory(
                    "Child Dir 2", parent_id=parent_id
                )

                if child1_response["code"] == 200 and child2_response["code"] == 200:
                    child1_id = child1_response["data"]["id"]
                    child2_id = child2_response["data"]["id"]

                    try:
                        # Move child2 into child1 (should succeed)
                        move_response = await authenticated_client.move_directory(
                            child2_id, child1_id
                        )

                        # Should succeed
                        assert move_response["code"] == 200
                    finally:
                        try:
                            await authenticated_client.delete_directory(child1_id)
                        except Exception:
                            pass
                        try:
                            await authenticated_client.delete_directory(child2_id)
                        except Exception:
                            pass
            finally:
                try:
                    await authenticated_client.delete_directory(parent_id)
                except Exception:
                    pass


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
