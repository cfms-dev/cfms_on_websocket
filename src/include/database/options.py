import time
from dataclasses import field
from json import dumps as json_dumps
from json import loads as json_loads
from typing import Annotated, Any, Literal, cast

from pydantic import (
    ConfigDict,
    Field,
    JsonValue,
    StringConstraints,
    TypeAdapter,
    validate_call,
)
from pydantic.dataclasses import dataclass
from sqlalchemy import select, update
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import CursorResult
lazy from sqlalchemy.orm import Session

from include.config._policy import OptionNamespace
from include.database.models.operations import OptionEntry
lazy from include.types import PositiveInt

OPTION_VALIDATION_CONFIG = ConfigDict(
    strict=True, allow_inf_nan=False, arbitrary_types_allowed=True
)
type OptionOwner = Annotated[
    str, StringConstraints(min_length=1, max_length=255, pattern=r"^[a-z][a-z0-9_]*$")
]
type OptionKey = Annotated[
    str,
    StringConstraints(min_length=1, max_length=128, pattern=r"^[a-z][a-z0-9_.-]*$"),
]
type OptionValue = JsonValue
type OptionValueType = Literal["str", "int", "float", "bool", "null", "json"]
type OptionSchemaVersion = Annotated[int, Field(gt=0, le=2**31 - 1)]

_VALUE_ADAPTER = TypeAdapter(OptionValue, config=OPTION_VALIDATION_CONFIG)


def encode_option_value(value: OptionValue) -> tuple[OptionValueType, str]:
    value = _VALUE_ADAPTER.validate_python(value, strict=True)
    match value:
        case str():
            return "str", value
        case bool():
            return "bool", "1" if value else "0"
        case int():
            return "int", str(value)
        case float():
            return "float", repr(value)
        case None:
            return "null", ""
        case dict() | list():
            return "json", json_dumps(
                value, ensure_ascii=False, allow_nan=False, separators=(",", ":")
            )
    raise ValueError("Unsupported option value")


def decode_option_value(value_type: OptionValueType, option_value: str) -> OptionValue:
    try:
        match value_type:
            case "str":
                value = option_value
            case "int":
                value = int(option_value)
                if str(value) != option_value:
                    raise ValueError("Noncanonical integer")
            case "float":
                value = float(option_value)
                if repr(value) != option_value:
                    raise ValueError("Noncanonical float")
            case "bool":
                if option_value not in ("0", "1"):
                    raise ValueError("Invalid boolean")
                value = option_value == "1"
            case "null":
                if option_value:
                    raise ValueError("Invalid null")
                value = None
            case "json":
                value = json_loads(option_value)
                match value:
                    case dict() | list():
                        pass
                    case _:
                        raise ValueError(
                            "Structured option must contain an object or array"
                        )
            case _:
                raise ValueError("Unknown option value type")
        return _VALUE_ADAPTER.validate_python(value, strict=True)
    except ValueError:
        raise ValueError(
            f"Invalid stored option value for type {value_type!r}"
        ) from None


@dataclass(frozen=True, slots=True, config=OPTION_VALIDATION_CONFIG)
class StoredOption:
    namespace: OptionNamespace
    owner: OptionOwner
    option_key: OptionKey
    schema_version: OptionSchemaVersion
    revision: PositiveInt
    value_type: OptionValueType
    option_value: str = field(repr=False)
    updated_at: float
    value: OptionValue = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self, "value", decode_option_value(self.value_type, self.option_value)
        )


@validate_call(config=OPTION_VALIDATION_CONFIG)
def read_option(
    session: Session, namespace: OptionNamespace, option_key: OptionKey
) -> StoredOption | None:
    row = (
        session.execute(
            select(
                OptionEntry.namespace,
                OptionEntry.owner,
                OptionEntry.option_key,
                OptionEntry.schema_version,
                OptionEntry.revision,
                OptionEntry.value_type,
                OptionEntry.option_value,
                OptionEntry.updated_at,
            ).where(
                OptionEntry.namespace == namespace, OptionEntry.option_key == option_key
            )
        )
        .mappings()
        .one_or_none()
    )
    return None if row is None else StoredOption(**row)


@validate_call(config=OPTION_VALIDATION_CONFIG)
def create_option(
    session: Session,
    namespace: OptionNamespace,
    option_key: OptionKey,
    *,
    schema_version: OptionSchemaVersion,
    value: OptionValue,
    owner: OptionOwner = "core",
) -> bool:
    value_type, option_value = encode_option_value(value)
    values = {
        "namespace": namespace,
        "owner": owner,
        "option_key": option_key,
        "schema_version": schema_version,
        "revision": 1,
        "value_type": value_type,
        "option_value": option_value,
        "updated_at": time.time(),
    }
    dialect = session.get_bind().dialect.name
    match dialect:
        case "sqlite":
            statement = sqlite_insert(OptionEntry).values(**values)
            statement = statement.on_conflict_do_nothing(
                index_elements=["namespace", "option_key"]
            )
        case "postgresql":
            statement = postgresql_insert(OptionEntry).values(**values)
            statement = statement.on_conflict_do_nothing(
                index_elements=["namespace", "option_key"]
            )
        case "mysql":
            statement = mysql_insert(OptionEntry).values(**values).prefix_with("IGNORE")
        case _:
            raise ValueError(f"Unsupported options database dialect: {dialect}")
    result = cast(
        CursorResult[Any],
        session.execute(statement, execution_options={"preserve_rowcount": True}),
    )
    return result.rowcount == 1


@validate_call(config=OPTION_VALIDATION_CONFIG)
def update_option(
    session: Session,
    namespace: OptionNamespace,
    option_key: OptionKey,
    *,
    expected_revision: PositiveInt,
    schema_version: OptionSchemaVersion,
    value: OptionValue,
) -> bool:
    value_type, option_value = encode_option_value(value)
    result = session.execute(
        update(OptionEntry)
        .where(
            OptionEntry.namespace == namespace,
            OptionEntry.option_key == option_key,
            OptionEntry.revision == expected_revision,
        )
        .values(
            schema_version=schema_version,
            revision=expected_revision + 1,
            value_type=value_type,
            option_value=option_value,
            updated_at=time.time(),
        )
        .execution_options(synchronize_session=False)
    )
    return cast(CursorResult[Any], result).rowcount == 1
