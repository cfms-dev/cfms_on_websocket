import secrets
import time

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
    async def test_document_metadata_tags(
        self, authenticated_client: CFMSTestClient, test_document: dict
    ):
        document_id = test_document["document_id"]

        info_response = await authenticated_client.get_document_info(document_id)
        info = assert_success(info_response)
        assert info["metadata"] == {
            "tags": [],
            "creator": "admin",
            "last_modified_by": "admin",
        }

        set_response = await authenticated_client.set_document_metadata_tags(
            document_id,
            ["secret", "finance", "secret", " topic "],
        )
        data = assert_success(set_response)
        assert data["tags"] == ["secret", "finance", "topic"]

        info_response = await authenticated_client.get_document_info(document_id)
        info = assert_success(info_response)
        assert info["metadata"]["tags"] == ["secret", "finance", "topic"]
        assert info["metadata"]["creator"] == "admin"
        assert info["metadata"]["last_modified_by"] == "admin"

    @pytest.mark.asyncio
    async def test_set_document_metadata_tags_requires_permission(
        self,
        authenticated_client: CFMSTestClient,
        test_document: dict,
        server_process,
    ):
        username = f"metadata_user_{secrets.token_hex(4)}"
        password = "TestPassword123!"
        document_id = test_document["document_id"]

        response = await authenticated_client.create_user(
            username=username,
            password=password,
            nickname="Metadata User",
        )
        assert_success(response)

        try:
            grant_response = await authenticated_client.grant_access(
                entity_type="user",
                entity_identifier=username,
                target_type="document",
                target_identifier=document_id,
                access_types=["write"],
                start_time=time.time(),
            )
            assert_success(grant_response)

            client = CFMSTestClient()
            await client.connect()
            try:
                login_response = await client.login(username, password)
                assert_success(login_response)

                set_response = await client.set_document_metadata_tags(
                    document_id, ["blocked"]
                )
                assert_error(set_response, 403)
            finally:
                await client.disconnect()
        finally:
            await authenticated_client.delete_user(username)

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
