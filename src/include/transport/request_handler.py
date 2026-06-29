__all__ = ["RequestHandler", "Result"]

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional

from include.transport.connection import ConnectionHandler


@dataclass
class Result:
    code: int
    target: Optional[str] = None
    data: Optional[dict[str, Any]] = None
    username: Optional[str] = None


class RequestHandler(ABC):
    """
    Abstract base class for handling requests.
    Attributes:
        schema (dict): A dictionary defining the expected schema for request data.
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

    # This property defines the json structure of the request data.
    schema: dict[str, Any] = {}
    # Defines whether the handler needs auth check before handling a request.
    require_auth: bool = False

    @abstractmethod
    def handle(self, handler: ConnectionHandler) -> Optional[Result]:
        pass
