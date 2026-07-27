import secrets

import pytest

from tests.test_client import CFMSTestClient
from tests.utils import assert_error, assert_success


def _documents(data: dict):
    return [item for item in data["items"] if item["type"] == "document"]


def _folders(data: dict):
    return [item for item in data["items"] if item["type"] == "directory"]


class TestRecycleBin:
    @pytest.mark.asyncio
    async def test_document_recycle_bin(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        # Create a parent directory
        dir_resp = await authenticated_client.create_directory("RecycleBinFolder")
        folder_id = assert_success(dir_resp)["id"]

        # Create a document inside the folder using factory to ensure it has an active revision
        doc_data = await document_factory("Recycle Bin Test Doc", folder_id=folder_id)
        doc_id = doc_data["document_id"]

        # Soft delete the document
        del_resp = await authenticated_client.delete_document(doc_id)
        assert_success(del_resp)

        # The document should no longer show up in normal list_directory
        list_dir = await authenticated_client.list_directory(folder_id)
        dir_data = assert_success(list_dir)
        assert not any(d["id"] == doc_id for d in _documents(dir_data))

        # Get list of deleted items in the folder
        list_deleted = await authenticated_client.list_deleted_items(
            folder_id=folder_id
        )
        deleted_data = assert_success(list_deleted)

        # We should find the document here
        assert any(d["id"] == doc_id for d in _documents(deleted_data))

        # Restore the document
        restore_resp = await authenticated_client.restore_document(doc_id)
        assert_success(restore_resp)

        # It should be back in the directory
        list_dir2 = await authenticated_client.list_directory(folder_id)
        dir_data2 = assert_success(list_dir2)
        assert any(d["id"] == doc_id for d in _documents(dir_data2))

        # Delete the document again to test purge
        await authenticated_client.delete_document(doc_id)

        # Purge it permanently
        purge_resp = await authenticated_client.purge_document(doc_id)
        assert_success(purge_resp)

        # Should not be in deleted items anymore
        list_deleted2 = await authenticated_client.list_deleted_items(
            folder_id=folder_id
        )
        deleted_data2 = assert_success(list_deleted2)
        assert not any(d["id"] == doc_id for d in _documents(deleted_data2))

    @pytest.mark.asyncio
    async def test_document_restore_conflict_preserves_deleted_document(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        name = f"Restore Conflict {secrets.token_hex(4)}"
        document = await document_factory(name)
        document_id = document["document_id"]
        assert_success(await authenticated_client.delete_document(document_id))
        winner = assert_success(await authenticated_client.create_directory(name))

        restore = await authenticated_client.restore_document(document_id)

        assert_error(restore, 409)
        assert restore["data"]["duplicate_id"] == winner["id"]
        deleted = assert_success(
            await authenticated_client.list_deleted_items(folder_id="/")
        )
        assert any(item["id"] == document_id for item in _documents(deleted))

    @pytest.mark.asyncio
    async def test_directory_recycle_bin(self, authenticated_client: CFMSTestClient):
        # Create a parent directory
        parent_resp = await authenticated_client.create_directory("ParentForRecycleBin")
        parent_id = assert_success(parent_resp)["id"]

        # Create a child directory
        child_resp = await authenticated_client.create_directory(
            "ChildRecycleBin", parent_id
        )
        child_id = assert_success(child_resp)["id"]

        # Soft delete the child directory
        del_resp = await authenticated_client.delete_directory(child_id)
        assert_success(del_resp)

        # Normal list_directory shouldn't show it
        list_dir = await authenticated_client.list_directory(parent_id)
        dir_data = assert_success(list_dir)
        assert not any(d["id"] == child_id for d in _folders(dir_data))

        # Get list of deleted items in the parent
        list_deleted = await authenticated_client.list_deleted_items(
            folder_id=parent_id
        )
        deleted_data = assert_success(list_deleted)
        assert any(d["id"] == child_id for d in _folders(deleted_data))

        # Restore the directory
        restore_resp = await authenticated_client.restore_directory(child_id)
        assert_success(restore_resp)

        list_dir2 = await authenticated_client.list_directory(parent_id)
        dir_data2 = assert_success(list_dir2)
        assert any(d["id"] == child_id for d in _folders(dir_data2))

        # Soft delete again
        await authenticated_client.delete_directory(child_id)

        # Purge the directory
        purge_resp = await authenticated_client.purge_directory(child_id)
        assert_success(purge_resp)

        list_deleted2 = await authenticated_client.list_deleted_items(
            folder_id=parent_id
        )
        deleted_data2 = assert_success(list_deleted2)
        assert not any(d["id"] == child_id for d in _folders(deleted_data2))

    @pytest.mark.asyncio
    async def test_directory_restore_conflict_preserves_deleted_directory(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        name = f"Directory Restore Conflict {secrets.token_hex(4)}"
        directory = assert_success(await authenticated_client.create_directory(name))
        directory_id = directory["id"]
        assert_success(await authenticated_client.delete_directory(directory_id))
        winner = await document_factory(name)

        restore = await authenticated_client.restore_directory(directory_id)

        assert_error(restore, 409)
        assert restore["data"]["duplicate_id"] == winner["document_id"]
        deleted = assert_success(
            await authenticated_client.list_deleted_items(folder_id="/")
        )
        assert any(item["id"] == directory_id for item in _folders(deleted))

    @pytest.mark.asyncio
    async def test_list_deleted_items_with_cursor(
        self, authenticated_client: CFMSTestClient
    ):
        parent_resp = await authenticated_client.create_directory(
            "RecycleBinCursorParent"
        )
        parent_id = assert_success(parent_resp)["id"]

        first_child_resp = await authenticated_client.create_directory(
            "RecycleBinCursorA", parent_id
        )
        first_child_id = assert_success(first_child_resp)["id"]
        second_child_resp = await authenticated_client.create_directory(
            "RecycleBinCursorB", parent_id
        )
        second_child_id = assert_success(second_child_resp)["id"]

        await authenticated_client.delete_directory(first_child_id)
        await authenticated_client.delete_directory(second_child_id)

        try:
            first_page_response = await authenticated_client.list_deleted_items(
                folder_id=parent_id, page_size=1
            )
            first_page = assert_success(first_page_response)

            second_page_response = await authenticated_client.list_deleted_items(
                folder_id=parent_id,
                page_size=1,
                cursor=first_page["next_cursor"],
            )
            second_page = assert_success(second_page_response)

            assert len(first_page["items"]) == 1
            assert len(second_page["items"]) == 1
            assert first_page["has_more"] is True
            assert first_page["next_cursor"] is not None
            assert first_page["items"][0]["id"] != second_page["items"][0]["id"]
        finally:
            await authenticated_client.purge_directory(first_child_id)
            await authenticated_client.purge_directory(second_child_id)
            await authenticated_client.delete_directory(parent_id)

    @pytest.mark.asyncio
    async def test_restore_directory_to_different_parent(
        self, authenticated_client: CFMSTestClient
    ):
        source_resp = await authenticated_client.create_directory("RecycleBinSource")
        source_id = assert_success(source_resp)["id"]

        target_resp = await authenticated_client.create_directory("RecycleBinTarget")
        target_id = assert_success(target_resp)["id"]

        child_resp = await authenticated_client.create_directory(
            "RecycleBinChild", source_id
        )
        child_id = assert_success(child_resp)["id"]

        await authenticated_client.delete_directory(child_id)

        restore_resp = await authenticated_client.restore_directory(
            child_id, target_parent_id=target_id
        )
        restore_data = assert_success(restore_resp)
        assert restore_data["parent_id"] == target_id
        assert restore_data["name"] == "RecycleBinChild"

        source_listing = assert_success(
            await authenticated_client.list_directory(source_id)
        )
        target_listing = assert_success(
            await authenticated_client.list_directory(target_id)
        )

        assert not any(d["id"] == child_id for d in _folders(source_listing))
        assert any(d["id"] == child_id for d in _folders(target_listing))

    @pytest.mark.asyncio
    async def test_restore_directory_with_new_name(
        self, authenticated_client: CFMSTestClient
    ):
        parent_resp = await authenticated_client.create_directory("RecycleBinRename")
        parent_id = assert_success(parent_resp)["id"]

        child_resp = await authenticated_client.create_directory(
            "RecycleBinOriginalName", parent_id
        )
        child_id = assert_success(child_resp)["id"]

        await authenticated_client.delete_directory(child_id)

        restore_resp = await authenticated_client.restore_directory(
            child_id, new_name="RecycleBinRenamed"
        )
        restore_data = assert_success(restore_resp)
        assert restore_data["parent_id"] == parent_id
        assert restore_data["name"] == "RecycleBinRenamed"

        listing = assert_success(await authenticated_client.list_directory(parent_id))
        restored_folder = next(d for d in _folders(listing) if d["id"] == child_id)
        assert restored_folder["name"] == "RecycleBinRenamed"

    @pytest.mark.asyncio
    async def test_recycle_bin_missing_directory_errors(
        self, authenticated_client: CFMSTestClient
    ):
        missing_id = "missing-directory-id-12345"

        restore_resp = await authenticated_client.restore_directory(missing_id)
        assert_error(restore_resp, 404)

        purge_resp = await authenticated_client.purge_directory(missing_id)
        assert_error(purge_resp, 404)

    @pytest.mark.asyncio
    async def test_recycle_bin_already_purged_directory_errors(
        self, authenticated_client: CFMSTestClient
    ):
        parent_resp = await authenticated_client.create_directory("RecycleBinPurge")
        parent_id = assert_success(parent_resp)["id"]

        child_resp = await authenticated_client.create_directory(
            "RecycleBinToPurge", parent_id
        )
        child_id = assert_success(child_resp)["id"]

        await authenticated_client.delete_directory(child_id)
        assert_success(await authenticated_client.purge_directory(child_id))

        restore_resp = await authenticated_client.restore_directory(child_id)
        assert_error(restore_resp, 404)

        purge_resp = await authenticated_client.purge_directory(child_id)
        assert_error(purge_resp, 404)

    @pytest.mark.asyncio
    async def test_purge_directory_rejects_pagination_fields(
        self, authenticated_client: CFMSTestClient
    ):
        parent_resp = await authenticated_client.create_directory(
            "RecycleBinPurgeSchema"
        )
        parent_id = assert_success(parent_resp)["id"]
        child_resp = await authenticated_client.create_directory(
            "RecycleBinPurgeSchemaChild", parent_id
        )
        child_id = assert_success(child_resp)["id"]
        await authenticated_client.delete_directory(child_id)

        try:
            assert_error(
                await authenticated_client.send_request(
                    "purge_directory",
                    {"folder_id": child_id, "page_size": 1},
                ),
                400,
            )
            assert_error(
                await authenticated_client.send_request(
                    "purge_directory",
                    {"folder_id": child_id, "cursor": "unused"},
                ),
                400,
            )
            assert_success(await authenticated_client.purge_directory(child_id))
        finally:
            try:
                await authenticated_client.delete_directory(parent_id)
                await authenticated_client.purge_directory(parent_id)
            except Exception:
                pass
