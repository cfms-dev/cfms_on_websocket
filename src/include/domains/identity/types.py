__all__ = ["RequestUsername"]

from typing import Annotated

from pydantic import StringConstraints

from include.config.constants import USERNAME_MAX_LENGTH

RequestUsername = Annotated[
    str,
    StringConstraints(min_length=1, max_length=USERNAME_MAX_LENGTH),
]
