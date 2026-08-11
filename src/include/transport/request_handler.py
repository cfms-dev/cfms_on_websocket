__all__ = ["JsonInteger", "RequestDataModel", "RequestHandler", "Result"]

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Annotated, Any, ClassVar

from pydantic import BaseModel, BeforeValidator, ConfigDict

from include.transport.connection import ConnectionHandler


@dataclass
class Result:
    code: int
    target: str | None = None
    data: dict[str, Any] | None = None
    username: str | None = None


def _normalize_json_integer(value: Any) -> Any:
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


JsonInteger = Annotated[int, BeforeValidator(_normalize_json_integer)]


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
