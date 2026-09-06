from abc import ABC, abstractmethod
from collections.abc import Buffer, Callable
from contextlib import AbstractContextManager
from dataclasses import dataclass
from io import UnsupportedOperation
from types import TracebackType
from typing import Any, ClassVar, Self


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


@dataclass(frozen=True, slots=True)
class SchedulingProviderStatus:
    available: bool
    mode: str
    detail: str | None = None


class SchedulingProvider(Provider):
    """Runtime boundary for schedule coordination and task delivery."""

    identifier: ClassVar[str] = "scheduling"

    @abstractmethod
    def start(self, registry: Any) -> None:
        pass

    @abstractmethod
    def shutdown(self) -> None:
        pass

    @abstractmethod
    def notify_schedule_change(self) -> None:
        pass

    @abstractmethod
    def status(self) -> SchedulingProviderStatus:
        pass


@dataclass(frozen=True, slots=True)
class RateLimitCharge:
    key: str
    scope: str
    capacity: int
    refill_tokens: int
    refill_period_seconds: int
    cost: int


@dataclass(frozen=True, slots=True)
class RateLimitDecision:
    allowed: bool
    scope: str | None = None
    effective_limit: int | None = None
    retry_after_seconds: int = 0


class RateLimitProvider(Provider):
    """Atomic token-bucket storage for request rate control."""

    identifier: ClassVar[str] = "rate_limit"

    @abstractmethod
    def consume(
        self,
        charges: tuple[RateLimitCharge, ...],
        *,
        retention_seconds: int,
        now: float | None = None,
    ) -> RateLimitDecision:
        pass


class FileObject(AbstractContextManager["FileObject"]):
    """
    Abstract base class for file objects that manage read/write operations.
    """

    def __enter__(self) -> Self:
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
    def write(self, data: Buffer) -> int:
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

    def truncate(self, size: int | None = None, /) -> int:
        raise NotImplementedError


class ResumableUploadSizeError(ValueError):
    pass


class ResumableUpload(AbstractContextManager["ResumableUpload"]):
    offset: int
    session_id: str | None
    checkpoint_size: int
    checkpoint_data: str | None

    def __enter__(self) -> Self:
        return self

    @abstractmethod
    def write(self, data: Buffer) -> int:
        pass

    @abstractmethod
    def finish(self) -> None:
        pass

    @abstractmethod
    def close(self) -> None:
        """Close local resources while preserving committed upload progress."""

    @abstractmethod
    def abort(self) -> None:
        """Discard both committed and buffered upload progress."""

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool | None:
        self.close()
        return None


class StorageProvider(Provider):
    """Storage provider interface for managing file-like resources.

    The storage layer is designed to be transparent to the upper
    layers, so regardless of which provider performs the data I/O,
    the same path format is used, which means it is treated as a
    local path.
    """

    identifier: ClassVar[str] = "storage"
    supports_resumable_uploads: ClassVar[bool] = False

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

    def open_resumable_upload(
        self,
        path: str,
        *,
        file_size: int,
        chunk_size: int,
        session_id: str | None = None,
        checkpoint_size: int | None = None,
        checkpoint_data: str | None = None,
        checkpoint_callback: Callable[[str], None] | None = None,
    ) -> ResumableUpload:
        raise UnsupportedOperation("This storage provider cannot resume uploads")

    def abort_resumable_upload(self, path: str, session_id: str) -> None:
        raise UnsupportedOperation("This storage provider cannot abort upload sessions")


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
        self, key: str, value: Any, ttl: float | None = None, nx: bool = False
    ) -> bool:
        """Set a value with an optional time-to-live in seconds.

        If `nx` is True, the value will only be set if the key does not already exist.
        Returns True if the value was set, False otherwise (e.g. if nx=True and key already exists).
        """

    @abstractmethod
    def delete(self, key: str) -> None:
        pass

    @abstractmethod
    def exists(self, key: str) -> bool:
        pass
