__all__ = [
    "CURSOR_PAGINATION_SCHEMA",
    "OFFSET_PAGINATION_SCHEMA",
    "PAGINATION_CURSOR_MAX_LENGTH",
    "PaginationCursorToken",
    "PaginationOffset",
    "PaginationPageSize",
    "CursorError",
    "PaginationCursor",
    "get_offset_pagination",
    "get_page_size",
    "make_cursor_response",
    "require_cursor_types",
]

import base64
import hashlib
import json
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Annotated, Any

from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import Field, StringConstraints

from include.config.constants import (
    PAGINATION_DEFAULT_PAGE_SIZE,
    PAGINATION_MAX_PAGE_SIZE,
)
from include.config.settings import global_config
from include.types import JsonInteger

PAGINATION_CURSOR_MAX_LENGTH = 2048
_CURSOR_AAD = "pagination-cursor-v2"
_CURSOR_KDF_INFO = b"cfms-pagination-cursor-fernet-v2"

PaginationPageSize = Annotated[
    JsonInteger,
    Field(ge=1, le=PAGINATION_MAX_PAGE_SIZE),
]
PaginationCursorToken = Annotated[
    str,
    StringConstraints(max_length=PAGINATION_CURSOR_MAX_LENGTH),
]
PaginationOffset = Annotated[JsonInteger, Field(ge=0, le=2**15 - 1)]

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


def _cursor_key() -> bytes:
    key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=_CURSOR_KDF_INFO,
    ).derive(_cursor_secret())
    return base64.urlsafe_b64encode(key)


def _cursor_fernet() -> Fernet:
    return Fernet(_cursor_key())


@dataclass(frozen=True, slots=True)
class PaginationCursor:
    action: str
    sort: str
    filters: dict[str, Any]
    last: list[Any]

    def encode(self) -> str:
        payload = {
            "aad": _CURSOR_AAD,
            "a": self.action,
            "s": self.sort,
            "f": _filters_hash(self.filters),
            "k": self.last,
        }
        return _cursor_fernet().encrypt(_canonical_json(payload)).decode()

    @classmethod
    def decode(
        cls,
        token: str | None,
        *,
        action: str,
        sort: str,
        filters: dict[str, Any],
        ttl: int | None = None,
        value_types: Sequence[CursorValueType] | None = None,
    ) -> PaginationCursor | None:
        if token is None:
            return None

        if len(token) > PAGINATION_CURSOR_MAX_LENGTH:
            raise CursorError("Invalid cursor")

        try:
            raw_payload = _cursor_fernet().decrypt(token, ttl=ttl)
            cursor_data = json.loads(raw_payload)
        except (
            InvalidToken,
            json.JSONDecodeError,
            TypeError,
            ValueError,
        ) as exc:
            raise CursorError("Invalid cursor") from exc

        if not isinstance(cursor_data, dict):
            raise CursorError("Invalid cursor")

        if cursor_data.get("aad") != _CURSOR_AAD:
            raise CursorError("Invalid cursor")

        if cursor_data.get("a") != action or cursor_data.get("s") != sort:
            raise CursorError("Cursor does not match this request")
        if cursor_data.get("f") != _filters_hash(filters):
            raise CursorError("Cursor does not match this request")

        last = cursor_data.get("k")
        if not isinstance(last, list):
            raise CursorError("Invalid cursor")
        if value_types is not None:
            require_cursor_types(last, value_types)

        return cls(
            action=action,
            sort=sort,
            filters=filters,
            last=last,
        )


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
        next_cursor = PaginationCursor(
            action=action,
            sort=sort,
            filters=filters,
            last=list(cursor_key(page_items[-1])),
        ).encode()

    return {
        "items": [_strip_internal_pagination_fields(item) for item in page_items],
        "page_size": page_size,
        "next_cursor": next_cursor,
        "has_more": has_more,
    }
