"""
Search handlers for documents and directories.

Provides functionality to search for documents and directories by name,
with permission filtering, result limiting, and sorting capabilities.
"""

__all__ = ["RequestSearchHandler"]

import time
from typing import Any

from sqlalchemy.orm import joinedload

from include.config.constants import QUERY_CHUNK_SIZE
from include.config.settings import global_config
from include.database.models.documents import Document, Folder
from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.authorization.evaluation import check_access_for_object
from include.domains.access.authorization.grants import (
    batch_prefetch_granted_ids,
    prefetch_user_blocks,
)
from include.domains.access.authorization.searchable_tree import (
    load_document_access_context,
    load_folder_access_context,
)
from include.domains.access.permissions import Permissions
from include.domains.documents.queries.listing import (
    fetch_search_candidate_rows,
    search_cursor_key,
)
from include.domains.pagination import (
    CURSOR_PAGINATION_SCHEMA,
    CursorError,
    decode_cursor,
    get_page_size,
    make_cursor_response,
)
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
            all_results: list[dict[str, Any]] = []

            # Preload block entries
            is_globally_blocked, blocked_ids = prefetch_user_blocks(
                session, user, "read", now
            )

            can_search = (
                not is_globally_blocked
                or Permissions.SUPER_LIST_DIRECTORY in user.all_permissions
            )
            candidate_limit = min(QUERY_CHUNK_SIZE, max(page_size * 4, 64))
            scan_key = last_key

            while (
                can_search
                and (search_documents or search_directories)
                and len(all_results) < page_size + 1
            ):
                candidate_rows = fetch_search_candidate_rows(
                    session,
                    query=query,
                    sort_by=sort_by,
                    sort_order=sort_order,
                    search_documents=search_documents,
                    search_directories=search_directories,
                    last_key=scan_key,
                    limit=candidate_limit,
                )
                if not candidate_rows:
                    break

                scan_key = search_cursor_key(candidate_rows[-1], sort_by)
                doc_ids = [
                    row["id"] for row in candidate_rows if row["type"] == "document"
                ]
                dir_ids = [
                    row["id"] for row in candidate_rows if row["type"] == "directory"
                ]

                documents_by_id = (
                    {
                        document.id: document
                        for document in session.query(Document)
                        .options(joinedload(Document.access_rules))
                        .filter(Document.id.in_(doc_ids))
                        .all()
                    }
                    if doc_ids
                    else {}
                )
                directories_by_id = (
                    {
                        directory.id: directory
                        for directory in session.query(Folder)
                        .options(joinedload(Folder.access_rules))
                        .filter(Folder.id.in_(dir_ids))
                        .all()
                    }
                    if dir_ids
                    else {}
                )

                doc_ancestors, doc_oaes = load_document_access_context(
                    session, list(documents_by_id.values()), now
                )
                dir_ancestors, dir_oaes = load_folder_access_context(
                    session, list(directories_by_id.values()), now
                )
                explicitly_granted_doc_ids = batch_prefetch_granted_ids(
                    session, user, doc_ids, "document", "read", now
                )
                explicitly_granted_dir_ids = batch_prefetch_granted_ids(
                    session, user, dir_ids, "directory", "read", now
                )

                for row in candidate_rows:
                    if (
                        row["id"] in blocked_ids
                        and Permissions.SUPER_LIST_DIRECTORY not in user.all_permissions
                    ):
                        continue

                    if row["type"] == "document":
                        document = documents_by_id.get(row["id"])
                        if document is None:
                            continue
                        if row["id"] not in explicitly_granted_doc_ids:
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

                        all_results.append(
                            {
                                "id": row["id"],
                                "name": row["name"],
                                "parent_id": row["parent_id"],
                                "created_time": row["created_time"],
                                "last_modified": row["last_modified"],
                                "size": row.get("size") or 0,
                                "type": "document",
                            }
                        )
                    else:
                        directory = directories_by_id.get(row["id"])
                        if directory is None:
                            continue
                        if row["id"] not in explicitly_granted_dir_ids:
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

                        all_results.append(
                            {
                                "id": row["id"],
                                "name": row["name"],
                                "parent_id": row["parent_id"],
                                "created_time": row["created_time"],
                                "type": "directory",
                            }
                        )

                    if len(all_results) >= page_size + 1:
                        break

                if len(candidate_rows) < candidate_limit:
                    break

            response_data = make_cursor_response(
                all_results,
                page_size=page_size,
                action="search",
                sort=sort,
                filters=filters,
                cursor_key=lambda item: search_cursor_key(item, sort_by),
            )
            response_data["query"] = query

            handler.conclude_request(
                200,
                response_data,
                f"Search completed successfully. Found {len(response_data['items'])} result(s).",
            )
            return Result(code=0, target=query, username=handler.username)
