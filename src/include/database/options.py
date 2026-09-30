import time
from typing import Annotated, Any, cast

from pydantic import ConfigDict, Field, JsonValue, StringConstraints, validate_call
from pydantic.dataclasses import dataclass
from sqlalchemy import select, update
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import CursorResult
lazy from sqlalchemy.orm import Session

from include.database.models.operations import OptionEntry
lazy from include.types import PositiveInt

OPTION_VALIDATION_CONFIG = ConfigDict(
    strict=True, allow_inf_nan=False, arbitrary_types_allowed=True
)
type OptionOwner = Annotated[
    str,
    StringConstraints(min_length=1, max_length=255, pattern=r"^[a-z][a-z0-9_]*$"),
]
type OptionKey = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_.-]*$"),
]
type OptionPayload = dict[str, JsonValue]
type OptionSchemaVersion = Annotated[int, Field(gt=0, le=2**31 - 1)]


@dataclass(frozen=True, slots=True, config=OPTION_VALIDATION_CONFIG)
class StoredOption:
    owner: OptionOwner
    option_key: OptionKey
    schema_version: OptionSchemaVersion
    revision: PositiveInt
    payload: OptionPayload
    updated_at: float


@validate_call(config=OPTION_VALIDATION_CONFIG)
def read_option(
    session: Session, owner: OptionOwner, option_key: OptionKey
) -> StoredOption | None:
    row = (
        session.execute(
            select(
                OptionEntry.owner,
                OptionEntry.option_key,
                OptionEntry.schema_version,
                OptionEntry.revision,
                OptionEntry.payload,
                OptionEntry.updated_at,
            ).where(OptionEntry.owner == owner, OptionEntry.option_key == option_key)
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else StoredOption(**row)


@validate_call(config=OPTION_VALIDATION_CONFIG)
def create_option(
    session: Session,
    owner: OptionOwner,
    option_key: OptionKey,
    *,
    schema_version: OptionSchemaVersion,
    payload: OptionPayload,
) -> bool:
    values = {
        "owner": owner,
        "option_key": option_key,
        "schema_version": schema_version,
        "revision": 1,
        "payload": payload,
        "updated_at": time.time(),
    }
    dialect = session.get_bind().dialect.name
    match dialect:
        case "sqlite":
            statement = sqlite_insert(OptionEntry).values(**values)
            statement = statement.on_conflict_do_nothing(
                index_elements=["owner", "option_key"]
            )
        case "postgresql":
            statement = postgresql_insert(OptionEntry).values(**values)
            statement = statement.on_conflict_do_nothing(
                index_elements=["owner", "option_key"]
            )
        case "mysql":
            statement = mysql_insert(OptionEntry).values(**values).prefix_with("IGNORE")
        case _:
            raise ValueError(f"Unsupported options database dialect: {dialect}")
    return cast(CursorResult[Any], session.execute(statement)).rowcount == 1


@validate_call(config=OPTION_VALIDATION_CONFIG)
def update_option(
    session: Session,
    owner: OptionOwner,
    option_key: OptionKey,
    *,
    expected_revision: PositiveInt,
    schema_version: OptionSchemaVersion,
    payload: OptionPayload,
) -> bool:
    result = session.execute(
        update(OptionEntry)
        .where(
            OptionEntry.owner == owner,
            OptionEntry.option_key == option_key,
            OptionEntry.revision == expected_revision,
        )
        .values(
            schema_version=schema_version,
            revision=expected_revision + 1,
            payload=payload,
            updated_at=time.time(),
        )
        .execution_options(synchronize_session=False)
    )
    return cast(CursorResult[Any], result).rowcount == 1
