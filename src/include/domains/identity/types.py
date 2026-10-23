__all__ = ["RequestUserID", "RequestUsername"]

import uuid
from typing import Annotated

from pydantic import Field, StringConstraints

from include.config.constants import USERNAME_MAX_LENGTH

RequestUsername = Annotated[
    str,
    StringConstraints(min_length=1, max_length=USERNAME_MAX_LENGTH),
]

RequestUserID = Annotated[uuid.UUID, Field(strict=False)]
