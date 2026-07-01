__all__ = [
    "CURSOR_PAGINATION_SCHEMA",
    "OFFSET_PAGINATION_SCHEMA",
    "PAGINATION_CURSOR_MAX_LENGTH",
    "CursorError",
    "decode_cursor",
    "encode_cursor",
    "get_page_size",
    "get_offset_pagination",
    "make_cursor_response",
    "require_cursor_length",
    "require_cursor_types",
]

import base64
import hashlib
import hmac
import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from include.config.constants import (
    PAGINATION_DEFAULT_PAGE_SIZE,
    PAGINATION_MAX_PAGE_SIZE,
)
from include.config.settings import global_config

PAGINATION_CURSOR_MAX_LENGTH = 2048

CURSOR_PAGINATION_SCHEMA = {
    "page_size": {
        "type": "integer",
        "minimum": 1,
        "maximum": PAGINATION_MAX_PAGE_SIZE,
    },
    "cursor": {
        "anyOf": [
            {"type": "string", "maxLength": PAGINATION_CURSOR_MAX_LENGTH},
            {"type": "null"},
        ]
    },
}

# Offset pagination schema is used for endpoints that support offset-based
# pagination. It defines the structure of the request parameters for offset
# and count, which are used to retrieve a specific subset of results from a
# larger dataset.
#
# The schema enforces that the offset is a non-negative integer and that
# the count is a positive integer within the maximum page size limit.
#
# NOTE: Currently the maximum offset is hard-coded to 2^15 - 1 (32767).
# If the actual data exceeds this limit, the excess portion will be inaccessible.
OFFSET_PAGINATION_SCHEMA = {
    "offset": {"type": "integer", "minimum": 0, "maximum": 2**15 - 1},
    "count": {
        "type": "integer",
        "minimum": 1,
        "maximum": PAGINATION_MAX_PAGE_SIZE,
    },
}

CursorValueType = type | tuple[type, ...]


class CursorError(ValueError):
    pass


def _filters_hash(filters: dict[str, Any]) -> str:
    encoded = _canonical_json(filters)
    return hashlib.sha256(encoded).hexdigest()


def _canonical_json(payload: Any) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()


def _cursor_secret() -> bytes:
    return str(global_config["server"]["secret_key"]).encode()


def _sign_payload(payload: dict[str, Any]) -> str:
    return hmac.new(
        _cursor_secret(), _canonical_json(payload), hashlib.sha256
    ).hexdigest()


def _b64_encode(payload: dict[str, Any]) -> str:
    raw = _canonical_json(payload)
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
    payload = {
        "v": 2,
        "a": action,
        "s": sort,
        "f": _filters_hash(filters),
        "k": list(last),
    }
    payload["sig"] = _sign_payload(payload)
    return _b64_encode(payload)


def decode_cursor(
    cursor: str | None,
    *,
    action: str,
    sort: str,
    filters: dict[str, Any],
    value_types: Sequence[CursorValueType] | None = None,
) -> list[Any] | None:
    if cursor is None:
        return None

    if len(cursor) > PAGINATION_CURSOR_MAX_LENGTH:
        raise CursorError("Invalid cursor")

    payload = _b64_decode(cursor)
    signature = payload.get("sig")
    if not isinstance(signature, str):
        raise CursorError("Invalid cursor")

    unsigned_payload = {k: v for k, v in payload.items() if k != "sig"}
    if not hmac.compare_digest(signature, _sign_payload(unsigned_payload)):
        raise CursorError("Invalid cursor")

    if (
        payload.get("v") != 2
        or payload.get("a") != action
        or payload.get("s") != sort
        or payload.get("f") != _filters_hash(filters)
    ):
        raise CursorError("Cursor does not match this request")

    last = payload.get("k")
    if not isinstance(last, list):
        raise CursorError("Invalid cursor")
    if value_types is not None:
        require_cursor_types(last, value_types)
    return last


def _strip_internal_pagination_fields(item: Any) -> Any:
    if isinstance(item, Mapping):
        return {
            key: value for key, value in item.items() if not str(key).startswith("_")
        }
    return item


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


def _matches_cursor_type(value: Any, expected: CursorValueType) -> bool:
    if isinstance(expected, tuple):
        return any(_matches_cursor_type(value, option) for option in expected)
    if expected in (int, float):
        return isinstance(value, expected) and not isinstance(value, bool)
    return isinstance(value, expected)


def require_cursor_types(
    last: list[Any] | None, value_types: Sequence[CursorValueType]
) -> None:
    if last is None:
        return

    if len(last) != len(value_types):
        raise CursorError("Invalid cursor")

    for value, expected in zip(last, value_types):
        if not _matches_cursor_type(value, expected):
            raise CursorError("Invalid cursor")


def make_cursor_response[T](
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
        "items": [_strip_internal_pagination_fields(item) for item in page_items],
        "page_size": page_size,
        "next_cursor": next_cursor,
        "has_more": has_more,
    }
