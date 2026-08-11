__all__ = [
    "JsonInteger",
    "Omittable",
    "REQUEST_UNSET",
    "RequestDataModel",
    "RequestHandler",
    "Result",
    "validate_request_handler_models",
]

from abc import ABC, abstractmethod
from collections.abc import Mapping
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

    request_model: ClassVar[type[RequestDataModel]]
    # Defines whether the handler needs auth check before handling a request.
    require_auth: bool = False
    # Relative token cost used by transport-wide request rate control.
    rate_limit_cost: int = 1

    @abstractmethod
    def handle(self, handler: ConnectionHandler) -> Result | None:
        pass


def validate_request_handler_models(
    handler_types: Mapping[str, type[RequestHandler]],
) -> None:
    for action, handler_type in handler_types.items():
        if not isinstance(handler_type, type) or not issubclass(
            handler_type, RequestHandler
        ):
            raise TypeError(
                f"Request handler for action {action!r} must inherit RequestHandler"
            )

        request_model = getattr(handler_type, "request_model", None)
        if not isinstance(request_model, type) or not issubclass(
            request_model, RequestDataModel
        ):
            raise TypeError(
                f"Request handler for action {action!r} must define a "
                "RequestDataModel subclass as request_model"
            )
