import math
import re
import time
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy import delete, update
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from include.database.models.operations import SystemStateEntry

__all__ = [
    "StoredSystemState",
    "create_system_state",
    "delete_system_state",
    "read_system_state",
    "update_system_state",
]

_OWNER_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")
_STATE_KEY_PATTERN = re.compile(r"^[a-z][a-z0-9_.-]*$")


@dataclass(frozen=True, slots=True)
class StoredSystemState:
    """Detached snapshot of one versioned runtime state document."""

    owner: str
    state_key: str
    schema_version: int
    revision: int
    payload: dict[str, Any]
    updated_at: float


def _validate_identity(owner: str, state_key: str) -> None:
    if not isinstance(owner, str) or not 1 <= len(owner) <= 255:
        raise ValueError("System state owner must contain 1 to 255 characters")
    if _OWNER_PATTERN.fullmatch(owner) is None:
        raise ValueError("Invalid system state owner")
    if not isinstance(state_key, str) or not 1 <= len(state_key) <= 128:
        raise ValueError("System state key must contain 1 to 128 characters")
    if _STATE_KEY_PATTERN.fullmatch(state_key) is None:
        raise ValueError("Invalid system state key")


def _validate_positive_integer(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"{name} must be a positive integer")


def _validate_json_value(value: Any) -> None:
    if value is None or isinstance(value, bool | int | str):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("System state payload cannot contain non-finite numbers")
        return
    if isinstance(value, list):
        for item in value:
            _validate_json_value(item)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise TypeError("System state payload object keys must be strings")
            _validate_json_value(item)
        return
    raise TypeError(f"Unsupported system state payload value: {type(value).__name__}")


def _copy_payload(payload: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise TypeError("System state payload must be a JSON object")
    _validate_json_value(payload)
    return deepcopy(payload)


def _snapshot(entry: SystemStateEntry) -> StoredSystemState:
    return StoredSystemState(
        owner=entry.owner,
        state_key=entry.state_key,
        schema_version=entry.schema_version,
        revision=entry.revision,
        payload=deepcopy(entry.payload),
        updated_at=entry.updated_at,
    )


def read_system_state(
    session: Session, owner: str, state_key: str
) -> StoredSystemState | None:
    """Read a detached state snapshot through a caller-owned session."""
    _validate_identity(owner, state_key)
    entry = session.get(SystemStateEntry, (owner, state_key))
    return None if entry is None else _snapshot(entry)


def create_system_state(
    session: Session,
    owner: str,
    state_key: str,
    *,
    schema_version: int,
    payload: dict[str, Any],
) -> bool:
    """Atomically insert an absent state without committing the caller's session."""
    _validate_identity(owner, state_key)
    _validate_positive_integer(schema_version, "schema_version")
    stored_payload = _copy_payload(payload)
    values = {
        "owner": owner,
        "state_key": state_key,
        "schema_version": schema_version,
        "revision": 1,
        "payload": stored_payload,
        "updated_at": time.time(),
    }
    dialect = session.get_bind().dialect.name
    match dialect:
        case "sqlite":
            statement = sqlite_insert(SystemStateEntry).values(**values)
            statement = statement.on_conflict_do_nothing(
                index_elements=["owner", "state_key"]
            )
        case "postgresql":
            statement = postgresql_insert(SystemStateEntry).values(**values)
            statement = statement.on_conflict_do_nothing(
                index_elements=["owner", "state_key"]
            )
        case "mysql":
            statement = mysql_insert(SystemStateEntry).values(**values)
            statement = statement.prefix_with("IGNORE")
        case _:
            raise ValueError(f"Unsupported system state database dialect: {dialect}")
    result = cast(CursorResult[Any], session.execute(statement))
    return result.rowcount == 1


def update_system_state(
    session: Session,
    owner: str,
    state_key: str,
    *,
    expected_revision: int,
    schema_version: int,
    payload: dict[str, Any],
) -> bool:
    """Replace the expected revision without committing the caller's session."""
    _validate_identity(owner, state_key)
    _validate_positive_integer(expected_revision, "expected_revision")
    _validate_positive_integer(schema_version, "schema_version")
    stored_payload = _copy_payload(payload)
    result = cast(
        CursorResult[Any],
        session.execute(
            update(SystemStateEntry)
            .where(
                SystemStateEntry.owner == owner,
                SystemStateEntry.state_key == state_key,
                SystemStateEntry.revision == expected_revision,
            )
            .values(
                schema_version=schema_version,
                revision=expected_revision + 1,
                payload=stored_payload,
                updated_at=time.time(),
            )
            .execution_options(synchronize_session=False)
        ),
    )
    return result.rowcount == 1


def delete_system_state(
    session: Session,
    owner: str,
    state_key: str,
    *,
    expected_revision: int,
) -> bool:
    """Delete the expected revision without committing the caller's session."""
    _validate_identity(owner, state_key)
    _validate_positive_integer(expected_revision, "expected_revision")
    result = cast(
        CursorResult[Any],
        session.execute(
            delete(SystemStateEntry)
            .where(
                SystemStateEntry.owner == owner,
                SystemStateEntry.state_key == state_key,
                SystemStateEntry.revision == expected_revision,
            )
            .execution_options(synchronize_session=False)
        ),
    )
    return result.rowcount == 1
