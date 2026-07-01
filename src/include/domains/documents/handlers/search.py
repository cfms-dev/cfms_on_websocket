"""
Search handlers for documents and directories.

Provides functionality to search for documents and directories by name,
with permission filtering, result limiting, and sorting capabilities.
"""

__all__ = ["RequestSearchHandler"]

import time
from functools import cmp_to_key
from typing import Any, Dict, List

from include.config.settings import global_config
from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.authorization.evaluation import check_access_for_object
from include.domains.access.authorization.grants import (
    batch_prefetch_granted_ids,
    prefetch_user_blocks,
)
from include.domains.access.authorization.searchable_tree import (
    search_documents_with_access,
    search_folders_with_access,
)
from include.domains.access.permissions import Permissions
from include.domains.pagination import (
    CURSOR_PAGINATION_SCHEMA,
    CursorError,
    decode_cursor,
    get_page_size,
    make_cursor_response,
)
from include.exceptions.misc import NoActiveRevisionsError
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler, Result


class RequestSearchHandler(RequestHandler):
    """
    Handles the "search" action for finding documents and directories by name.

    Features:
    1. Accepts a search query (name) as the main parameter
    2. Returns matching objects with their ID and parent directory ID
    3. Filters results based on user read permissions
    4. Supports limiting the maximum number of search results
    5. Supports sorting by multiple criteria (time, size, name, etc.)
    """

    schema = {
        "type": "object",
        "properties": {
            "query": {"type": "string", "minLength": 1},
            **CURSOR_PAGINATION_SCHEMA,
            "sort_by": {
                "type": "string",
                "enum": ["name", "created_time", "size", "last_modified"],
            },
            "sort_order": {"type": "string", "enum": ["asc", "desc"]},
            "search_documents": {"type": "boolean"},
            "search_directories": {"type": "boolean"},
        },
        "required": ["query"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        """
        Handle the search request.

        Args:
            handler: The connection handler containing request data

        Returns:
            Tuple containing status code, query, and username for audit logging
        """
        query: str = handler.data["query"].strip()
        if not query:
            handler.conclude_request(
                400, {}, "Query must not be empty or whitespace only"
            )
            return Result(code=400, target=query, username=handler.username)

        page_size = get_page_size(handler.data)
        cursor = handler.data.get("cursor")
        sort_by: str = handler.data.get("sort_by", "name")
        sort_order: str = handler.data.get("sort_order", "asc")
        search_documents: bool = handler.data.get("search_documents", True)
        search_directories: bool = handler.data.get("search_directories", True)
        filters = {
            "query": query,
            "sort_by": sort_by,
            "sort_order": sort_order,
            "search_documents": search_documents,
            "search_directories": search_directories,
        }
        sort = f"{sort_by}:{sort_order}"
        try:
            last_key = decode_cursor(
                cursor,
                action="search",
                sort=sort,
                filters=filters,
                value_types=[(int, float, str), int, str],
            )
        except CursorError as exc:
            handler.conclude_request(400, {}, str(exc))
            return Result(code=400, target=query, username=handler.username)

        with Session() as session:
            user = User.get_existing(session, handler.username)

            now = time.time()

            results: Dict[str, List[Dict[str, Any]]] = {
                "documents": [],
                "directories": [],
            }

            # Preload block entries
            is_globally_blocked, blocked_ids = prefetch_user_blocks(
                session, user, "read", now
            )

            # Search documents
            if search_documents and (
                not is_globally_blocked
                or Permissions.SUPER_LIST_DIRECTORY in user.all_permissions
            ):
                documents, doc_ancestors, doc_oaes = search_documents_with_access(
                    session, query, now
                )

                doc_ids = [doc.id for doc in documents]
                explicitly_granted_doc_ids = batch_prefetch_granted_ids(
                    session, user, doc_ids, "document", "read", now
                )

                for document in documents:
                    if not document.active:
                        continue
                    if (
                        document.id in blocked_ids
                        and Permissions.SUPER_LIST_DIRECTORY not in user.all_permissions
                    ):  # This is because people who have `super_list_directory` can still see blocked documents via `list_directory`.
                        continue
                    if document.id in explicitly_granted_doc_ids:
                        pass
                    else:
                        if not check_access_for_object(
                            document,
                            user,
                            "read",
                            doc_ancestors,
                            doc_oaes,
                            recursive=global_config["access"][
                                "enable_access_recursive_check"
                            ],
                        ):
                            continue

                    try:
                        latest_revision = document.get_latest_revision()
                        size = latest_revision.file.size if latest_revision.file else 0
                        last_modified = latest_revision.created_time
                    except (NoActiveRevisionsError, AttributeError):
                        size = 0
                        last_modified = document.created_time

                    results["documents"].append(
                        {
                            "id": document.id,
                            "name": document.title,
                            "parent_id": document.folder_id,
                            "created_time": document.created_time,
                            "last_modified": last_modified,
                            "size": size,
                            "type": "document",
                        }
                    )

            # Search directories
            if search_directories and (
                not is_globally_blocked
                or Permissions.SUPER_LIST_DIRECTORY in user.all_permissions
            ):
                directories, dir_ancestors, dir_oaes = search_folders_with_access(
                    session, query, now
                )

                dir_ids = [d.id for d in directories]
                explicitly_granted_dir_ids = batch_prefetch_granted_ids(
                    session, user, dir_ids, "directory", "read", now
                )

                for directory in directories:
                    if (
                        directory.id in blocked_ids
                        and Permissions.SUPER_LIST_DIRECTORY not in user.all_permissions
                    ):
                        continue

                    if directory.id in explicitly_granted_dir_ids:
                        pass
                    else:
                        if not check_access_for_object(
                            directory,
                            user,
                            "read",
                            dir_ancestors,
                            dir_oaes,
                            recursive=global_config["access"][
                                "enable_access_recursive_check"
                            ],
                        ):
                            continue

                    results["directories"].append(
                        {
                            "id": directory.id,
                            "name": directory.name,
                            "parent_id": directory.parent_id,
                            "created_time": directory.created_time,
                            "type": "directory",
                        }
                    )

            # Sort results
            all_results = results["documents"] + results["directories"]

            def primary_value(item: dict[str, Any]):
                if sort_by == "name":
                    return item["name"].lower()
                if sort_by == "size":
                    return item.get("size", 0)
                if sort_by == "last_modified":
                    return item.get("last_modified", item["created_time"])
                return item["created_time"]

            def cursor_key(item: dict[str, Any]) -> list[Any]:
                type_rank = 0 if item["type"] == "directory" else 1
                return [primary_value(item), type_rank, item["id"]]

            def compare_keys(left: list[Any], right: list[Any]) -> int:
                if left[0] != right[0]:
                    if sort_order == "desc":
                        return -1 if left[0] > right[0] else 1
                    return -1 if left[0] < right[0] else 1
                if left[1] != right[1]:
                    return -1 if left[1] < right[1] else 1
                if left[2] != right[2]:
                    return -1 if left[2] < right[2] else 1
                return 0

            all_results.sort(
                key=cmp_to_key(
                    lambda left, right: compare_keys(
                        cursor_key(left), cursor_key(right)
                    )
                )
            )
            if last_key is not None:
                all_results = [
                    item
                    for item in all_results
                    if compare_keys(cursor_key(item), last_key) > 0
                ]

            response_data = make_cursor_response(
                all_results[: page_size + 1],
                page_size=page_size,
                action="search",
                sort=sort,
                filters=filters,
                cursor_key=cursor_key,
            )
            response_data["query"] = query

            handler.conclude_request(
                200,
                response_data,
                f"Search completed successfully. Found {len(response_data['items'])} result(s).",
            )
            return Result(code=0, target=query, username=handler.username)
