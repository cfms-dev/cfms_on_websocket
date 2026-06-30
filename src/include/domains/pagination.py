__all__ = [
    "CURSOR_PAGINATION_SCHEMA",
    "OFFSET_PAGINATION_SCHEMA",
    "CursorError",
    "decode_cursor",
    "encode_cursor",
    "get_page_size",
    "get_offset_pagination",
    "make_cursor_response",
    "require_cursor_length",
]

import base64
import hashlib
import json
from typing import Any, Callable, Iterable, Sequence, TypeVar

from include.config.constants import (
    PAGINATION_DEFAULT_PAGE_SIZE,
    PAGINATION_MAX_PAGE_SIZE,
)

CURSOR_PAGINATION_SCHEMA = {
    "page_size": {
        "type": "integer",
        "minimum": 1,
        "maximum": PAGINATION_MAX_PAGE_SIZE,
    },
    "cursor": {"anyOf": [{"type": "string"}, {"type": "null"}]},
}

OFFSET_PAGINATION_SCHEMA = {
    "offset": {"type": "integer", "minimum": 0},
    "count": {
        "type": "integer",
        "minimum": 1,
        "maximum": PAGINATION_MAX_PAGE_SIZE,
    },
}

T = TypeVar("T")


class CursorError(ValueError):
    pass


def _filters_hash(filters: dict[str, Any]) -> str:
    encoded = json.dumps(filters, sort_keys=True, separators=(",", ":")).encode()
    return hashlib.sha256(encoded).hexdigest()


def _b64_encode(payload: dict[str, Any]) -> str:
    raw = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _b64_decode(token: str) -> dict[str, Any]:
    try:
        padding = "=" * (-len(token) % 4)
        raw = base64.urlsafe_b64decode((token + padding).encode())
        payload = json.loads(raw)
    except Exception as exc:
        raise CursorError("Invalid cursor") from exc

    if not isinstance(payload, dict):
        raise CursorError("Invalid cursor")
    return payload


def encode_cursor(
    *,
    action: str,
    sort: str,
    filters: dict[str, Any],
    last: Sequence[Any],
) -> str:
    return _b64_encode(
        {
            "v": 1,
            "action": action,
            "sort": sort,
            "filters": _filters_hash(filters),
            "last": list(last),
        }
    )


def decode_cursor(
    cursor: str | None,
    *,
    action: str,
    sort: str,
    filters: dict[str, Any],
) -> list[Any] | None:
    if cursor is None:
        return None

    payload = _b64_decode(cursor)
    if (
        payload.get("v") != 1
        or payload.get("action") != action
        or payload.get("sort") != sort
        or payload.get("filters") != _filters_hash(filters)
    ):
        raise CursorError("Cursor does not match this request")

    last = payload.get("last")
    if not isinstance(last, list):
        raise CursorError("Invalid cursor")
    return last


def get_page_size(data: dict[str, Any]) -> int:
    return data.get("page_size", PAGINATION_DEFAULT_PAGE_SIZE)


def get_offset_pagination(data: dict[str, Any]) -> tuple[int, int]:
    return (
        data.get("offset", 0),
        data.get("count", PAGINATION_DEFAULT_PAGE_SIZE),
    )


def require_cursor_length(last: list[Any] | None, length: int) -> None:
    if last is not None and len(last) != length:
        raise CursorError("Invalid cursor")


def make_cursor_response(
    items: Iterable[T],
    *,
    page_size: int,
    action: str,
    sort: str,
    filters: dict[str, Any],
    cursor_key: Callable[[T], Sequence[Any]],
) -> dict[str, Any]:
    page_items = list(items)
    has_more = len(page_items) > page_size
    page_items = page_items[:page_size]
    next_cursor = None
    if has_more and page_items:
        next_cursor = encode_cursor(
            action=action,
            sort=sort,
            filters=filters,
            last=cursor_key(page_items[-1]),
        )

    return {
        "items": page_items,
        "page_size": page_size,
        "next_cursor": next_cursor,
        "has_more": has_more,
    }
