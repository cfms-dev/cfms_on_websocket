import pytest

from tests.test_client import CFMSTestClient
from tests.utils import assert_error, assert_success


class TestRevisionOperations:
    @pytest.mark.asyncio
    async def test_list_revisions(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        doc = await document_factory("Revisions Test Doc")
        doc_id = doc["document_id"]

        # When created (and uploaded), there's 1 revision.
        response = await authenticated_client.list_revisions(doc_id)
        data = assert_success(response)

        assert "items" in data
        assert len(data["items"]) == 1
        assert data["items"][0]["is_current"] is True

        # Now let's upload a second revision
        upload_resp = await authenticated_client.upload_document(doc_id)
        upload_data = assert_success(upload_resp)
        task_id = upload_data["task_data"]["task_id"]

        await authenticated_client.upload_file_to_server(task_id, "./pytest.ini")

        # Now there should be 2 revisions
        response2 = await authenticated_client.list_revisions(doc_id)
        data2 = assert_success(response2)

        assert len(data2["items"]) == 2

        current_revs = [r for r in data2["items"] if r["is_current"]]
        assert len(current_revs) == 1

        first_page_response = await authenticated_client.list_revisions(
            doc_id, page_size=1
        )
        first_page = assert_success(first_page_response)
        second_page_response = await authenticated_client.list_revisions(
            doc_id, page_size=1, cursor=first_page["next_cursor"]
        )
        second_page = assert_success(second_page_response)
        assert len(first_page["items"]) == 1
        assert len(second_page["items"]) == 1
        assert first_page["items"][0]["id"] != second_page["items"][0]["id"]

    @pytest.mark.asyncio
    async def test_get_revision(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        doc = await document_factory("Revision Details Doc")
        doc_id = doc["document_id"]

        list_resp = await authenticated_client.list_revisions(doc_id)
        data = assert_success(list_resp)
        rev_id = data["items"][0]["id"]

        # Request get_revision
        get_resp = await authenticated_client.get_revision(rev_id)
        rev_data = assert_success(get_resp)

        assert "task_data" in rev_data
        assert "task_id" in rev_data["task_data"]

    @pytest.mark.asyncio
    async def test_set_document_revision(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        doc = await document_factory("Set Revision Doc")
        doc_id = doc["document_id"]

        # First revision ID
        list_resp = await authenticated_client.list_revisions(doc_id)
        rev1_id = assert_success(list_resp)["items"][0]["id"]

        # Upload second revision
        upload_resp = await authenticated_client.upload_document(doc_id)
        task_id = assert_success(upload_resp)["task_data"]["task_id"]
        await authenticated_client.upload_file_to_server(task_id, "./pytest.ini")

        list_resp2 = await authenticated_client.list_revisions(doc_id)
        data2 = assert_success(list_resp2)
        rev2 = next(r for r in data2["items"] if r["is_current"])
        rev2_id = rev2["id"]

        assert rev1_id != rev2_id

        # Roll back to revision 1
        set_resp = await authenticated_client.set_document_revision(doc_id, rev1_id)
        assert_success(set_resp)

        list_resp3 = await authenticated_client.list_revisions(doc_id)
        data3 = assert_success(list_resp3)
        check_rev1 = next(r for r in data3["items"] if r["id"] == rev1_id)
        assert check_rev1["is_current"] is True

    @pytest.mark.asyncio
    async def test_delete_revision(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        doc = await document_factory("Delete Revision Doc")
        doc_id = doc["document_id"]

        # Upload second revision
        upload_resp = await authenticated_client.upload_document(doc_id)
        task_id = assert_success(upload_resp)["task_data"]["task_id"]
        await authenticated_client.upload_file_to_server(task_id, "./pytest.ini")

        list_resp = await authenticated_client.list_revisions(doc_id)
        data = assert_success(list_resp)
        # Find the non-current revision
        rev_to_delete = next(r for r in data["items"] if not r["is_current"])
        rev_id = rev_to_delete["id"]

        del_resp = await authenticated_client.delete_revision(rev_id)
        assert_success(del_resp)

        list_resp2 = await authenticated_client.list_revisions(doc_id)
        data2 = assert_success(list_resp2)
        assert len(data2["items"]) == 1
        assert data2["items"][0]["id"] != rev_id

    @pytest.mark.asyncio
    async def test_list_revisions_missing_doc(
        self, authenticated_client: CFMSTestClient
    ):
        resp = await authenticated_client.list_revisions("invalid-doc-id-12345")
        assert_error(resp, 404)
