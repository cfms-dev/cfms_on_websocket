import pytest

from tests.support.client import CFMSTestClient
from tests.support.utils import assert_error, assert_success

_SEARCH_USER_GROUPS = [{"group_name": "user", "start_time": 0}]


def _documents(data: dict):
    return [item for item in data["items"] if item["type"] == "document"]


def _directories(data: dict):
    return [item for item in data["items"] if item["type"] == "directory"]


class TestSearch:
    @pytest.mark.asyncio
    async def test_search_requires_authentication(self, client: CFMSTestClient):
        response = await client.send_request(
            "search", {"query": "AuthenticationRequired"}, include_auth=False
        )

        assert_error(response, 401)

    @pytest.mark.asyncio
    async def test_search_requires_search_permission(
        self,
        unauthenticated_client: CFMSTestClient,
        user_factory,
    ):
        test_user = await user_factory()
        assert_success(
            await unauthenticated_client.login(
                test_user["username"], test_user["password"]
            )
        )

        response = await unauthenticated_client.search(query="PermissionRequired")

        error = assert_error(response, 403)
        assert error["message"] == "User does not have permission to perform search"

    @pytest.mark.asyncio
    async def test_search_honors_inherited_search_permission(
        self,
        unauthenticated_client: CFMSTestClient,
        user_factory,
    ):
        test_user = await user_factory(groups=_SEARCH_USER_GROUPS)
        assert_success(
            await unauthenticated_client.login(
                test_user["username"], test_user["password"]
            )
        )

        response = await unauthenticated_client.search(
            query="InheritedSearchPermission"
        )

        data = assert_success(response)
        assert data["items"] == []

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

        assert "items" in data
        assert len(_directories(data)) == 0

        doc_ids = [doc["id"] for doc in _documents(data)]
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

        assert "items" in data
        assert len(_documents(data)) == 0

        dir_ids = [d["id"] for d in _directories(data)]
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

        doc_ids = [d["id"] for d in _documents(data)]
        dir_ids = [d["id"] for d in _directories(data)]

        assert doc["document_id"] in doc_ids
        assert folder["id"] in dir_ids

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        ("literal_fragment", "near_miss_fragment"),
        [
            pytest.param(
                "LiteralPercent%SearchToken",
                "LiteralPercentXSearchToken",
                id="percent",
            ),
            pytest.param(
                "LiteralUnderscore_SearchToken",
                "LiteralUnderscoreXSearchToken",
                id="underscore",
            ),
            pytest.param(
                "LiteralSlash/SearchToken",
                "LiteralSlashXSearchToken",
                id="escape-character",
            ),
            pytest.param(
                "LiteralQuote' OR 1=1 --SearchToken",
                "UnrelatedSqlSearchToken",
                id="sql-like-text",
            ),
        ],
    )
    async def test_search_treats_pattern_characters_as_literals(
        self,
        authenticated_client: CFMSTestClient,
        document_factory,
        literal_fragment: str,
        near_miss_fragment: str,
    ):
        matching_document = await document_factory(
            f"Document {literal_fragment} Result"
        )
        near_miss_document = await document_factory(
            f"Document {near_miss_fragment} Result"
        )
        matching_directory = assert_success(
            await authenticated_client.create_directory(
                f"Directory {literal_fragment} Result"
            )
        )
        near_miss_directory = assert_success(
            await authenticated_client.create_directory(
                f"Directory {near_miss_fragment} Result"
            )
        )

        response = await authenticated_client.search(query=literal_fragment.swapcase())
        data = assert_success(response)

        document_ids = {item["id"] for item in _documents(data)}
        directory_ids = {item["id"] for item in _directories(data)}
        assert document_ids == {matching_document["document_id"]}
        assert directory_ids == {matching_directory["id"]}
        assert near_miss_document["document_id"] not in document_ids
        assert near_miss_directory["id"] not in directory_ids

    @pytest.mark.asyncio
    async def test_search_with_cursor_pagination(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        for i in range(5):
            await document_factory(f"CursorTestDoc_{i}")

        first_response = await authenticated_client.search(
            query="CursorTestDoc",
            page_size=3,
            search_documents=True,
            search_directories=False,
        )
        first_page = assert_success(first_response)
        second_response = await authenticated_client.search(
            query="CursorTestDoc",
            page_size=3,
            cursor=first_page["next_cursor"],
            search_documents=True,
            search_directories=False,
        )
        second_page = assert_success(second_response)

        assert len(first_page["items"]) == 3
        assert first_page["has_more"] is True
        assert second_page["has_more"] is False
        first_ids = {item["id"] for item in first_page["items"]}
        second_ids = {item["id"] for item in second_page["items"]}
        assert first_ids.isdisjoint(second_ids)

    @pytest.mark.asyncio
    async def test_search_no_results(self, authenticated_client: CFMSTestClient):
        response = await authenticated_client.search(
            query="NonExistentObscureTermThatWillNeverBeFound",
            search_documents=True,
            search_directories=True,
        )
        data = assert_success(response)

        assert len(data["items"]) == 0

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
        names_desc = [doc["name"] for doc in _documents(data_desc)]
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
        names_asc = [doc["name"] for doc in _documents(data_asc)]
        assert names_asc == sorted(names_asc)

    @pytest.mark.asyncio
    async def test_search_with_no_targets_returns_empty_results(
        self, authenticated_client: CFMSTestClient, document_factory
    ):
        await document_factory("NoTargetSearchDocument")
        await authenticated_client.create_directory("NoTargetSearchFolder")

        response = await authenticated_client.search(
            query="NoTargetSearch",
            search_documents=False,
            search_directories=False,
        )
        data = assert_success(response)

        assert data["items"] == []
        assert data["has_more"] is False

    @pytest.mark.asyncio
    async def test_search_rejects_whitespace_query(
        self, authenticated_client: CFMSTestClient
    ):
        response = await authenticated_client.search(query="   ")
        assert_error(response, 400)

    @pytest.mark.asyncio
    @pytest.mark.parametrize(
        "payload",
        [
            {"query": "SortValidation", "sort_by": "invalid-field"},
            {"query": "SortValidation", "sort_order": "sideways"},
        ],
    )
    async def test_search_rejects_invalid_sort_parameters(
        self, authenticated_client: CFMSTestClient, payload: dict
    ):
        response = await authenticated_client.search(**payload)
        assert_error(response, 400)
