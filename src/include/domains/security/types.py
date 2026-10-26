__all__ = ["TotpToken"]

from typing import Annotated

from pydantic import StringConstraints

TotpToken = Annotated[str, StringConstraints(min_length=1, max_length=64)]
