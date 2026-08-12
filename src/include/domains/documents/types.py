__all__ = ["RevisionID"]

from typing import Annotated

from pydantic import StringConstraints

RevisionID = Annotated[str, StringConstraints(min_length=1, max_length=64)]
