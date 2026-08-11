__all__ = [
    "NonEmptyString",
    "NonNegativeInt",
    "PositiveFloat",
    "PositiveInt",
    "StrictBool",
    "StrictFloat",
    "StrictInt",
    "StrictStr",
    "UnitRatio",
]

from typing import Annotated

from annotated_types import Gt, Le
from pydantic import (
    NonNegativeInt,
    PositiveFloat,
    PositiveInt,
    StrictBool,
    StrictFloat,
    StrictInt,
    StrictStr,
    StringConstraints,
)

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
