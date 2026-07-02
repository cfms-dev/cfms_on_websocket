import os
import time

import pytest

from tests.test_client import CFMSTestClient
from tests.utils import assert_error, assert_success


def _documents(data: dict):
    return [item for item in data["items"] if item["type"] == "document"]


def _directories(data: dict):
    return [item for item in data["items"] if item["type"] == "directory"]


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
    async def test_search_filters_hidden_candidates_before_pagination(
        self,
        authenticated_client: CFMSTestClient,
        unauthenticated_client: CFMSTestClient,
        user_factory,
    ):
        test_user = await user_factory()
        login_response = await unauthenticated_client.login(
            test_user["username"], test_user["password"]
        )
        assert_success(login_response)

        query = "SearchScanBudget"
        hidden_folder_ids = []
        visible_folder_id = None
        access_rules = {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {"groups": {"match": "all", "require": ["sysop"]}}
                    ],
                }
            ]
        }
        try:
            for index in range(256):
                response = await authenticated_client.send_request(
                    "create_directory",
                    {
                        "name": f"{query}Hidden{index:03d}",
                        "access_rules": access_rules,
                    },
                )
                hidden_folder_ids.append(assert_success(response)["id"])

            visible_response = await authenticated_client.create_directory(
                f"{query}Visible"
            )
            visible_folder_id = assert_success(visible_response)["id"]

            first_response = await unauthenticated_client.search(
                query=query,
                page_size=1,
                search_documents=False,
                search_directories=True,
            )
            first_page = assert_success(first_response)

            assert [item["id"] for item in first_page["items"]] == [visible_folder_id]
            assert first_page["has_more"] is False
            assert first_page["next_cursor"] is None
        finally:
            for folder_id in hidden_folder_ids + (
                [visible_folder_id] if visible_folder_id else []
            ):
                try:
                    await authenticated_client.delete_directory(folder_id)
                    await authenticated_client.purge_directory(folder_id)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_search_visible_query_honors_oae_direct_grant(
        self,
        authenticated_client: CFMSTestClient,
        unauthenticated_client: CFMSTestClient,
        user_factory,
    ):
        test_user = await user_factory()
        login_response = await unauthenticated_client.login(
            test_user["username"], test_user["password"]
        )
        assert_success(login_response)

        query = "SearchOAEVisible"
        folder_id = None
        access_rules = {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {"groups": {"match": "all", "require": ["sysop"]}}
                    ],
                }
            ]
        }
        try:
            create_response = await authenticated_client.send_request(
                "create_directory",
                {"name": query, "access_rules": access_rules},
            )
            folder_id = assert_success(create_response)["id"]
            grant_response = await authenticated_client.grant_access(
                "user",
                test_user["username"],
                "directory",
                folder_id,
                ["read"],
                time.time() - 1,
            )
            assert_success(grant_response)

            response = await unauthenticated_client.search(
                query=query,
                search_documents=False,
                search_directories=True,
            )
            data = assert_success(response)

            assert [item["id"] for item in data["items"]] == [folder_id]
        finally:
            if folder_id:
                try:
                    await authenticated_client.delete_directory(folder_id)
                    await authenticated_client.purge_directory(folder_id)
                except Exception:
                    pass

    @pytest.mark.asyncio
    async def test_search_visible_query_honors_compiled_rule_match_modes(
        self,
        authenticated_client: CFMSTestClient,
        unauthenticated_client: CFMSTestClient,
        user_factory,
    ):
        original_cwd = os.getcwd()
        try:
            os.chdir("src")
            from include.database.models.documents import Folder
            from include.database.models.identity import User
            from include.database.session import Session
            from include.domains.access.authorization.evaluation import (
                check_access_for_object,
            )
            from include.domains.access.authorization.searchable_tree import (
                load_folder_access_context,
            )
            from include.domains.documents.queries.listing import (
                fetch_visible_search_candidate_rows,
            )
        finally:
            os.chdir(original_cwd)

        test_user = await user_factory()
        permissions_response = await authenticated_client.change_user_permissions(
            test_user["username"], ["list_users"]
        )
        assert_success(permissions_response)
        login_response = await unauthenticated_client.login(
            test_user["username"], test_user["password"]
        )
        assert_success(login_response)

        query = "SearchCompiledRules"
        visible_folder_id = None
        hidden_folder_id = None
        visible_rules = {
            "read": [
                {
                    "match": "any",
                    "match_groups": [
                        {
                            "match": "any",
                            "rights": {
                                "match": "any",
                                "require": ["debugging", "list_users"],
                            },
                            "groups": {
                                "match": "all",
                                "require": ["missing_group"],
                            },
                        }
                    ],
                },
                {
                    "match": "all",
                    "match_groups": [
                        {"rights": {"match": "all", "require": ["list_users"]}}
                    ],
                },
            ]
        }
        hidden_rules = {
            "read": [
                {
                    "match": "any",
                    "match_groups": [
                        {
                            "rights": {
                                "match": "any",
                                "require": ["list_users"],
                            }
                        }
                    ],
                },
                {
                    "match": "all",
                    "match_groups": [
                        {"groups": {"match": "all", "require": ["sysop"]}}
                    ],
                },
            ]
        }
        try:
            visible_response = await authenticated_client.send_request(
                "create_directory",
                {"name": f"{query}Visible", "access_rules": visible_rules},
            )
            visible_folder_id = assert_success(visible_response)["id"]
            hidden_response = await authenticated_client.send_request(
                "create_directory",
                {"name": f"{query}Hidden", "access_rules": hidden_rules},
            )
            hidden_folder_id = assert_success(hidden_response)["id"]

            response = await unauthenticated_client.search(
                query=query,
                search_documents=False,
                search_directories=True,
            )
            data = assert_success(response)

            assert [item["id"] for item in data["items"]] == [visible_folder_id]

            with Session() as session:
                user = User.get_existing(session, test_user["username"])
                folders = (
                    session.query(Folder)
                    .filter(Folder.id.in_([visible_folder_id, hidden_folder_id]))
                    .all()
                )
                ancestors, oaes = load_folder_access_context(session, folders)
                python_visible_ids = {
                    folder.id
                    for folder in folders
                    if check_access_for_object(
                        folder,
                        user,
                        "read",
                        ancestors,
                        oaes,
                        recursive=True,
                    )
                }
                sql_visible_ids = {
                    item["id"]
                    for item in fetch_visible_search_candidate_rows(
                        session,
                        user=user,
                        now=time.time(),
                        query=query,
                        sort_by="name",
                        sort_order="asc",
                        search_documents=False,
                        search_directories=True,
                        last_key=None,
                        limit=10,
                    )
                }

            assert sql_visible_ids == python_visible_ids == {visible_folder_id}
        finally:
            for folder_id in [visible_folder_id, hidden_folder_id]:
                if folder_id:
                    try:
                        await authenticated_client.delete_directory(folder_id)
                        await authenticated_client.purge_directory(folder_id)
                    except Exception:
                        pass

    @pytest.mark.asyncio
    async def test_search_visible_query_honors_inherit_false_boundary(
        self,
        authenticated_client: CFMSTestClient,
        unauthenticated_client: CFMSTestClient,
        user_factory,
    ):
        test_user = await user_factory()
        login_response = await unauthenticated_client.login(
            test_user["username"], test_user["password"]
        )
        assert_success(login_response)

        query = "SearchInheritBoundary"
        parent_id = None
        child_id = None
        access_rules = {
            "read": [
                {
                    "match": "all",
                    "match_groups": [
                        {"groups": {"match": "all", "require": ["sysop"]}}
                    ],
                }
            ]
        }
        try:
            parent_response = await authenticated_client.send_request(
                "create_directory",
                {"name": f"{query}Parent", "access_rules": access_rules},
            )
            parent_id = assert_success(parent_response)["id"]
            child_response = await authenticated_client.send_request(
                "create_directory",
                {
                    "name": f"{query}Child",
                    "parent_id": parent_id,
                    "inherit_parent": False,
                },
            )
            child_id = assert_success(child_response)["id"]

            response = await unauthenticated_client.search(
                query=f"{query}Child",
                search_documents=False,
                search_directories=True,
            )
            data = assert_success(response)

            assert [item["id"] for item in data["items"]] == [child_id]
        finally:
            for folder_id in [child_id, parent_id]:
                if folder_id:
                    try:
                        await authenticated_client.delete_directory(folder_id)
                        await authenticated_client.purge_directory(folder_id)
                    except Exception:
                        pass

    @pytest.mark.asyncio
    async def test_search_visible_query_honors_read_block(
        self,
        authenticated_client: CFMSTestClient,
        unauthenticated_client: CFMSTestClient,
        user_factory,
    ):
        test_user = await user_factory()
        login_response = await unauthenticated_client.login(
            test_user["username"], test_user["password"]
        )
        assert_success(login_response)

        query = "SearchBlockedTarget"
        folder_id = None
        try:
            create_response = await authenticated_client.create_directory(query)
            folder_id = assert_success(create_response)["id"]
            block_response = await authenticated_client.block_user(
                test_user["username"], "directory", ["read"], folder_id
            )
            assert_success(block_response)

            response = await unauthenticated_client.search(
                query=query,
                search_documents=False,
                search_directories=True,
            )
            data = assert_success(response)

            assert data["items"] == []
            assert data["has_more"] is False
            assert data["next_cursor"] is None
        finally:
            if folder_id:
                try:
                    await authenticated_client.delete_directory(folder_id)
                    await authenticated_client.purge_directory(folder_id)
                except Exception:
                    pass

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
