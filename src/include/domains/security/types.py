__all__ = ["TwoFactorToken"]

from typing import Annotated

from pydantic import StringConstraints

TwoFactorToken = Annotated[str, StringConstraints(min_length=1, max_length=64)]
