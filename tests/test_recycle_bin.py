import pytest

from tests.test_client import CFMSTestClient
from tests.utils import assert_success


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
        assert not any(d["id"] == doc_id for d in dir_data["documents"])

        # Get list of deleted items in the folder
        list_deleted = await authenticated_client.list_deleted_items(
            folder_id=folder_id
        )
        deleted_data = assert_success(list_deleted)

        # We should find the document here
        assert any(d["id"] == doc_id for d in deleted_data["documents"])

        # Restore the document
        restore_resp = await authenticated_client.restore_document(doc_id)
        assert_success(restore_resp)

        # It should be back in the directory
        list_dir2 = await authenticated_client.list_directory(folder_id)
        dir_data2 = assert_success(list_dir2)
        assert any(d["id"] == doc_id for d in dir_data2["documents"])

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
        assert not any(d["id"] == doc_id for d in deleted_data2["documents"])

        # Now it shouldn't even be in the deleted items
        list_deleted2 = await authenticated_client.list_deleted_items(
            folder_id=folder_id
        )
        deleted_data2 = assert_success(list_deleted2)
        assert not any(d["id"] == doc_id for d in deleted_data2["documents"])

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
        assert not any(d["id"] == child_id for d in dir_data["folders"])

        # Get list of deleted items in the parent
        list_deleted = await authenticated_client.list_deleted_items(
            folder_id=parent_id
        )
        deleted_data = assert_success(list_deleted)
        assert any(d["id"] == child_id for d in deleted_data["folders"])

        # Restore the directory
        restore_resp = await authenticated_client.restore_directory(child_id)
        assert_success(restore_resp)

        list_dir2 = await authenticated_client.list_directory(parent_id)
        dir_data2 = assert_success(list_dir2)
        assert any(d["id"] == child_id for d in dir_data2["folders"])

        # Soft delete again
        await authenticated_client.delete_directory(child_id)

        # Purge the directory
        purge_resp = await authenticated_client.purge_directory(child_id)
        assert_success(purge_resp)

        list_deleted2 = await authenticated_client.list_deleted_items(
            folder_id=parent_id
        )
        deleted_data2 = assert_success(list_deleted2)
        assert not any(d["id"] == child_id for d in deleted_data2["folders"])
