from abc import ABC, abstractmethod
from contextlib import AbstractContextManager
from types import TracebackType
from typing import Any, Callable, ClassVar, Optional


class Provider(ABC):
    """Base class for all providers.

    This class defines the interface that all providers must implement.
    """

    identifier: ClassVar[str]
    """Unified identifier shared by a class of Providers.

    This identifier is used to categorize providers of the same type, allowing
    the `ProviderManager` to manage them effectively.

    It should be implemented on a base class of a `Provider` class, and once
    implemented, it should not be overridden by subclasses.
    """


class FileObject(AbstractContextManager["FileObject"]):
    """
    Abstract base class for file objects that manage read/write operations.
    """

    def __enter__(self) -> "FileObject":
        return self

    @abstractmethod
    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        pass

    @abstractmethod
    def read(self, size: int = -1) -> bytes:
        pass

    @abstractmethod
    def write(self, data: bytes) -> int:
        pass

    @abstractmethod
    def close(self) -> None:
        pass

    @abstractmethod
    def seekable(self) -> bool:
        pass

    def seek(self, offset: int, whence: int = 0, /) -> int:
        raise NotImplementedError

    def tell(self) -> int:
        raise NotImplementedError

    def truncate(self, size: Optional[int] = None, /) -> int:
        raise NotImplementedError


class StorageProvider(Provider):
    """Storage provider interface for managing file-like resources.

    The storage layer is designed to be transparent to the upper
    layers, so regardless of which provider performs the data I/O,
    the same path format is used, which means it is treated as a
    local path.
    """

    identifier: ClassVar[str] = "storage"

    @abstractmethod
    def fopen(self, path: str, mode: str = "rb") -> FileObject:
        pass

    @abstractmethod
    def exists(self, path: str) -> bool:
        pass

    @abstractmethod
    def remove(self, path: str) -> bool:
        pass

    @abstractmethod
    def mkdir(self, path: str, mode: int = 0o777) -> None:
        pass

    @abstractmethod
    def makedirs(self, name: str, mode: int = 0o777, exist_ok: bool = False) -> None:
        pass

    @abstractmethod
    def getsize(self, filename: str, /) -> int:
        pass


class EventBusProvider(Provider):
    """Event bus provider interface for publish-subscribe messaging."""

    identifier: ClassVar[str] = "event_bus"

    @abstractmethod
    def subscribe(self, channel: str, callback: Callable[[str], None]) -> None:
        pass

    @abstractmethod
    def publish(self, channel: str, message: str) -> None:
        pass


class CachingProvider(Provider):
    """Caching provider interface for key-value storage with optional TTL."""

    identifier: ClassVar[str] = "caching"

    @abstractmethod
    def get(self, key: str) -> Any:
        pass

    @abstractmethod
    def set(
        self, key: str, value: Any, ttl: Optional[float] = None, nx: bool = False
    ) -> bool:
        """Set a value with an optional time-to-live in seconds.

        If `nx` is True, the value will only be set if the key does not already exist.
        Returns True if the value was set, False otherwise (e.g. if nx=True and key already exists).
        """
        pass

    @abstractmethod
    def delete(self, key: str) -> None:
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        pass
