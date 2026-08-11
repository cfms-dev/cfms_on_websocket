import time
from typing import Annotated, Any, cast

from pydantic import ConfigDict, JsonValue, StringConstraints, validate_call
from pydantic.dataclasses import dataclass
from sqlalchemy import delete, update
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from include.database.models.operations import SystemStateEntry
from include.types import PositiveInt

__all__ = [
    "StoredSystemState",
    "create_system_state",
    "delete_system_state",
    "read_system_state",
    "update_system_state",
]

_SYSTEM_STATE_CONFIG = ConfigDict(
    strict=True,
    allow_inf_nan=False,
    arbitrary_types_allowed=True,
)
_SystemStateOwner = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=255,
        pattern=r"^[a-z][a-z0-9_]*$",
    ),
]
_SystemStateKey = Annotated[
    str,
    StringConstraints(
        min_length=1,
        max_length=128,
        pattern=r"^[a-z][a-z0-9_.-]*$",
    ),
]
_SystemStatePayload = dict[str, JsonValue]


@dataclass(frozen=True, slots=True, config=_SYSTEM_STATE_CONFIG)
class StoredSystemState:
    """Detached snapshot of one versioned runtime state document."""

    owner: _SystemStateOwner
    state_key: _SystemStateKey
    schema_version: PositiveInt
    revision: PositiveInt
    payload: _SystemStatePayload
    updated_at: float


def _snapshot(entry: SystemStateEntry) -> StoredSystemState:
    return StoredSystemState(
        owner=entry.owner,
        state_key=entry.state_key,
        schema_version=entry.schema_version,
        revision=entry.revision,
        payload=entry.payload,
        updated_at=entry.updated_at,
    )


@validate_call(config=_SYSTEM_STATE_CONFIG)
def read_system_state(
    session: Session,
    owner: _SystemStateOwner,
    state_key: _SystemStateKey,
) -> StoredSystemState | None:
    """Read a detached state snapshot through a caller-owned session."""
    entry = session.get(SystemStateEntry, (owner, state_key))
    return None if entry is None else _snapshot(entry)


@validate_call(config=_SYSTEM_STATE_CONFIG)
def create_system_state(
    session: Session,
    owner: _SystemStateOwner,
    state_key: _SystemStateKey,
    *,
    schema_version: PositiveInt,
    payload: _SystemStatePayload,
) -> bool:
    """Atomically insert an absent state without committing the caller's session."""
    values = {
        "owner": owner,
        "state_key": state_key,
        "schema_version": schema_version,
        "revision": 1,
        "payload": payload,
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


@validate_call(config=_SYSTEM_STATE_CONFIG)
def update_system_state(
    session: Session,
    owner: _SystemStateOwner,
    state_key: _SystemStateKey,
    *,
    expected_revision: PositiveInt,
    schema_version: PositiveInt,
    payload: _SystemStatePayload,
) -> bool:
    """Replace the expected revision without committing the caller's session."""
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
                payload=payload,
                updated_at=time.time(),
            )
            .execution_options(synchronize_session=False)
        ),
    )
    return result.rowcount == 1


@validate_call(config=_SYSTEM_STATE_CONFIG)
def delete_system_state(
    session: Session,
    owner: _SystemStateOwner,
    state_key: _SystemStateKey,
    *,
    expected_revision: PositiveInt,
) -> bool:
    """Delete the expected revision without committing the caller's session."""
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
