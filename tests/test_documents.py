import pytest

from tests.test_client import CFMSTestClient
from tests.utils import assert_error, assert_success


class TestDocumentOperations:
    @pytest.mark.asyncio
    async def test_create_document(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        test_doc = await document_factory("Test Document")
        assert "document_id" in test_doc
        assert len(test_doc["document_id"]) > 0

    @pytest.mark.asyncio
    async def test_get_document(
        self, authenticated_client: CFMSTestClient, test_document: dict
    ):
        response = await authenticated_client.get_document(test_document["document_id"])
        assert_success(response)

    @pytest.mark.asyncio
    async def test_get_nonexistent_document(self, authenticated_client: CFMSTestClient):
        response = await authenticated_client.get_document("nonexistent_doc_id_xyz_123")
        assert response.get("code") in [400, 404]

    @pytest.mark.asyncio
    async def test_get_document_info(
        self, authenticated_client: CFMSTestClient, test_document: dict
    ):
        response = await authenticated_client.get_document_info(
            test_document["document_id"]
        )
        data = assert_success(response)
        assert isinstance(data, dict)

    @pytest.mark.asyncio
    async def test_rename_document(
        self, authenticated_client: CFMSTestClient, test_document: dict
    ):
        new_title = "Renamed Test Document XYZ"
        response = await authenticated_client.rename_document(
            test_document["document_id"], new_title
        )
        assert_success(response)

        info_response = await authenticated_client.get_document_info(
            test_document["document_id"]
        )
        data = assert_success(info_response)
        assert data["title"] == new_title

    @pytest.mark.asyncio
    async def test_delete_document(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        test_doc = await document_factory("Document to Delete")
        document_id = test_doc["document_id"]

        delete_response = await authenticated_client.delete_document(document_id)
        assert_success(delete_response)

        get_response = await authenticated_client.get_document(document_id)
        assert get_response.get("code") != 200

    @pytest.mark.asyncio
    async def test_create_document_with_empty_title(
        self, authenticated_client: CFMSTestClient
    ):
        response = await authenticated_client.create_document("")
        assert_error(response, 400)

    @pytest.mark.asyncio
    async def test_create_multiple_documents(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        document_ids = []
        num_documents = 3

        for i in range(num_documents):
            test_doc = await document_factory(f"Test Document {i}")
            document_ids.append(test_doc["document_id"])

        for doc_id in document_ids:
            response = await authenticated_client.get_document_info(doc_id)
            assert_success(response)


class TestDocumentWithoutAuth:
    @pytest.mark.asyncio
    async def test_create_document_without_auth(self, client: CFMSTestClient):
        response = await client.send_request(
            "create_document", {"title": "Test Document"}, include_auth=False
        )
        assert_error(response, 401)

    @pytest.mark.asyncio
    async def test_get_document_without_auth(self, client: CFMSTestClient):
        response = await client.send_request(
            "get_document", {"document_id": "test_doc_id"}, include_auth=False
        )
        assert_error(response, 401)
