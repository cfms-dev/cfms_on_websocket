__all__ = [
    "JsonInteger",
    "Omittable",
    "REQUEST_UNSET",
    "RequestDataModel",
    "RequestHandler",
    "Result",
]

from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum
from typing import Any, ClassVar

from pydantic import BaseModel, ConfigDict

from include.transport.connection import ConnectionHandler
from include.types import JsonInteger


@dataclass
class Result:
    code: int
    target: str | None = None
    data: dict[str, Any] | None = None
    username: str | None = None


class _RequestUnset(Enum):
    TOKEN = object()


REQUEST_UNSET = _RequestUnset.TOKEN
type Omittable[T] = T | _RequestUnset


class RequestDataModel(BaseModel):
    model_config = ConfigDict(
        strict=True,
        validate_default=True,
        extra="forbid",
    )


class RequestHandler(ABC):
    """
    Abstract base class for handling requests.
    Attributes:
        request_model: The Pydantic model defining valid request data.
    Methods:
        handle():
            Abstract method to process a request. Must be implemented by subclasses.
            Returns:
                1. -> None
                    The result is ignored. Use this for flows that should not
                    submit audit information through the return value.
                2. -> Result
                    The result is submitted as audit information.
    """

    # Legacy JSON Schema retained only while core handlers migrate to request models.
    schema: ClassVar[dict[str, Any]] = {}
    request_model: ClassVar[type[RequestDataModel] | None] = None
    # Defines whether the handler needs auth check before handling a request.
    require_auth: bool = False
    # Relative token cost used by transport-wide request rate control.
    rate_limit_cost: int = 1

    @abstractmethod
    def handle(self, handler: ConnectionHandler) -> Result | None:
        pass
