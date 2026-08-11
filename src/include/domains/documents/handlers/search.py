"""
Search handlers for documents and directories.

Provides functionality to search for documents and directories by name,
with permission filtering, result limiting, and sorting capabilities.
"""

__all__ = ["RequestSearchHandler"]

import time
from typing import Annotated, Literal

from pydantic import StringConstraints

from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.documents.queries.listing import (
    fetch_visible_search_candidate_rows,
    search_cursor_key,
)
from include.domains.pagination import (
    CursorError,
    PaginationCursor,
    PaginationCursorToken,
    PaginationPageSize,
    get_page_size,
    make_cursor_response,
)
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import (
    REQUEST_UNSET,
    Omittable,
    RequestDataModel,
    RequestHandler,
    Result,
)

_NonEmptyString = Annotated[str, StringConstraints(min_length=1)]


class _SearchRequest(RequestDataModel):
    query: _NonEmptyString
    page_size: Omittable[PaginationPageSize] = REQUEST_UNSET
    cursor: PaginationCursorToken | None = None
    sort_by: Omittable[Literal["name", "created_time", "size", "last_modified"]] = (
        REQUEST_UNSET
    )
    sort_order: Omittable[Literal["asc", "desc"]] = REQUEST_UNSET
    search_documents: Omittable[bool] = REQUEST_UNSET
    search_directories: Omittable[bool] = REQUEST_UNSET


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

    request_model = _SearchRequest

    require_auth = True
    rate_limit_cost = 3

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
            decoded_cursor = PaginationCursor.decode(
                cursor,
                action="search",
                sort=sort,
                filters=filters,
                value_types=[(int, float, str), int, str],
            )
            last_key = None if decoded_cursor is None else decoded_cursor.last
        except CursorError as exc:
            handler.conclude_request(400, {}, str(exc))
            return Result(code=400, target=query, username=handler.username)

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.SEARCH not in user.all_permissions:
                handler.conclude_request(
                    403, {}, "User does not have permission to perform search"
                )
                return Result(code=403, target=query, username=handler.username)

            now = time.time()
            all_results = fetch_visible_search_candidate_rows(
                session,
                user=user,
                now=now,
                query=query,
                sort_by=sort_by,
                sort_order=sort_order,
                search_documents=search_documents,
                search_directories=search_directories,
                last_key=last_key,
                limit=page_size + 1,
            )

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
