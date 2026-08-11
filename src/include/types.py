__all__ = [
    "NonEmptyString",
    "NonNegativeInt",
    "PositiveFloat",
    "PositiveInt",
    "JsonInteger",
    "StrictBool",
    "StrictFloat",
    "StrictInt",
    "StrictStr",
    "UnitRatio",
]

from typing import Annotated, Any

from annotated_types import Gt, Le
from pydantic import (
    BeforeValidator,
    NonNegativeInt,
    PositiveFloat,
    PositiveInt,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    StringConstraints,
)


def _normalize_json_integer(value: Any) -> Any:
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


JsonInteger = Annotated[int, BeforeValidator(_normalize_json_integer)]

NonEmptyString = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True,
        min_length=1,
    ),
]

UnitRatio = Annotated[
    float,
    Gt(0),
    Le(1),
]
