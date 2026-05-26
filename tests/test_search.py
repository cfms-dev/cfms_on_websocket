import pytest

from tests.test_client import CFMSTestClient
from tests.utils import assert_success


class TestSearch:
    @pytest.mark.asyncio
    async def test_search_documents(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        # Create some test documents
        doc1 = await document_factory("UniqueSearchableDocumentOne")
        doc2 = await document_factory("UniqueSearchableDocumentTwo")
        doc3 = await document_factory("UnrelatedDocThree")

        # Search for "Searchable"
        response = await authenticated_client.search(
            query="Searchable", search_documents=True, search_directories=False
        )
        data = assert_success(response)

        assert "documents" in data
        assert "directories" in data
        assert len(data["directories"]) == 0

        doc_ids = [doc["id"] for doc in data["documents"]]
        assert doc1["document_id"] in doc_ids
        assert doc2["document_id"] in doc_ids
        assert doc3["document_id"] not in doc_ids

    @pytest.mark.asyncio
    async def test_search_directories(self, authenticated_client: CFMSTestClient):
        # Create some test directories
        dir1_response = await authenticated_client.create_directory(
            "UniqueSearchableFolderOne"
        )
        dir1 = assert_success(dir1_response)
        dir2_response = await authenticated_client.create_directory(
            "UniqueSearchableFolderTwo"
        )
        dir2 = assert_success(dir2_response)
        dir3_response = await authenticated_client.create_directory(
            "UnrelatedFolderThree"
        )
        dir3 = assert_success(dir3_response)

        # Search for "Searchable"
        response = await authenticated_client.search(
            query="Searchable", search_documents=False, search_directories=True
        )
        data = assert_success(response)

        assert "documents" in data
        assert "directories" in data
        assert len(data["documents"]) == 0

        dir_ids = [d["id"] for d in data["directories"]]
        assert dir1["id"] in dir_ids
        assert dir2["id"] in dir_ids
        assert dir3["id"] not in dir_ids

    @pytest.mark.asyncio
    async def test_search_both(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        doc = await document_factory("SharedSearchTermDoc")
        dir_response = await authenticated_client.create_directory(
            "SharedSearchTermFolder"
        )
        folder = assert_success(dir_response)

        response = await authenticated_client.search(
            query="SharedSearchTerm", search_documents=True, search_directories=True
        )
        data = assert_success(response)

        doc_ids = [d["id"] for d in data["documents"]]
        dir_ids = [d["id"] for d in data["directories"]]

        assert doc["document_id"] in doc_ids
        assert folder["id"] in dir_ids

    @pytest.mark.asyncio
    async def test_search_with_limit(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        for i in range(5):
            await document_factory(f"LimitTestDoc_{i}")

        response = await authenticated_client.search(
            query="LimitTestDoc",
            limit=3,
            search_documents=True,
            search_directories=False,
        )
        data = assert_success(response)

        assert len(data["documents"]) == 3

    @pytest.mark.asyncio
    async def test_search_no_results(self, authenticated_client: CFMSTestClient):
        response = await authenticated_client.search(
            query="NonExistentObscureTermThatWillNeverBeFound",
            search_documents=True,
            search_directories=True,
        )
        data = assert_success(response)

        assert len(data["documents"]) == 0
        assert len(data["directories"]) == 0

    @pytest.mark.asyncio
    async def test_search_sorting(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        # We need docs with the same name root to sort by created_time
        # Since document_factory makes the document, its created_time will be sequential.
        doc1 = await document_factory("SortTestDoc A")
        doc2 = await document_factory("SortTestDoc B")
        doc3 = await document_factory("SortTestDoc C")

        # Sort desc by name
        response_desc = await authenticated_client.search(
            query="SortTestDoc",
            sort_by="name",
            sort_order="desc",
            search_documents=True,
            search_directories=False,
        )
        data_desc = assert_success(response_desc)
        names_desc = [doc["name"] for doc in data_desc["documents"]]
        assert names_desc == sorted(names_desc, reverse=True)

        # Sort asc by name
        response_asc = await authenticated_client.search(
            query="SortTestDoc",
            sort_by="name",
            sort_order="asc",
            search_documents=True,
            search_directories=False,
        )
        data_asc = assert_success(response_asc)
        names_asc = [doc["name"] for doc in data_asc["documents"]]
        assert names_asc == sorted(names_asc)
