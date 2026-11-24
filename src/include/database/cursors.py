__all__ = [
    "KeysetBatchStrategy",
    "StreamingCursorBatchStrategy",
    "WindowedKeysetBatchStrategy",
    "default_keyset_batch_strategy",
]

from collections.abc import Callable, Generator
from dataclasses import dataclass
from typing import Any, Protocol

from sqlalchemy.orm import Session
from sqlalchemy.sql import Executable

from include.config.constants import QUERY_CHUNK_SIZE


class KeysetBatchStrategy(Protocol):
    """Strategy for iterating keyset-ordered query rows in batches."""

    def iter_batches(
        self,
        session: Session,
        *,
        build_select: Callable[[list[Any] | None, int | None], Executable],
        cursor_key_of: Callable[[dict[str, Any]], list[Any]],
        initial_last_key: list[Any] | None,
    ) -> Generator[list[dict[str, Any]]]: ...


@dataclass(frozen=True, slots=True)
class StreamingCursorBatchStrategy:
    """Keep a single cursor open and fetch chunks (safe on SQLite with nested queries)."""

    chunk_size: int = QUERY_CHUNK_SIZE

    def iter_batches(
        self,
        session: Session,
        *,
        build_select: Callable[[list[Any] | None, int | None], Executable],
        cursor_key_of: Callable[[dict[str, Any]], list[Any]],
        initial_last_key: list[Any] | None,
    ) -> Generator[list[dict[str, Any]]]:
        del cursor_key_of
        result = session.execute(build_select(initial_last_key, None))
        try:
            mappings = result.mappings()
            while True:
                fetched = mappings.fetchmany(self.chunk_size)
                if not fetched:
                    break
                yield [
                    {str(key): value for key, value in row.items()} for row in fetched
                ]
        finally:
            result.close()


@dataclass(frozen=True, slots=True)
class WindowedKeysetBatchStrategy:
    """Fetch escalating keyset-paginated windows so no cursor remains open across nested queries."""

    window_sizes: tuple[int, ...] = (2048, 8192)

    def iter_batches(
        self,
        session: Session,
        *,
        build_select: Callable[[list[Any] | None, int | None], Executable],
        cursor_key_of: Callable[[dict[str, Any]], list[Any]],
        initial_last_key: list[Any] | None,
    ) -> Generator[list[dict[str, Any]]]:
        if not self.window_sizes:
            raise ValueError("window_sizes must contain at least one positive size.")
        batch_last_key = initial_last_key
        window_index = 0
        while True:
            window_limit = self.window_sizes[
                min(window_index, len(self.window_sizes) - 1)
            ]
            window_index += 1
            rows = [
                {str(key): value for key, value in row.items()}
                for row in session.execute(
                    build_select(batch_last_key, window_limit)
                ).mappings()
            ]
            if not rows:
                break
            yield rows
            if len(rows) < window_limit:
                break
            batch_last_key = cursor_key_of(rows[-1])


def default_keyset_batch_strategy(session: Session) -> KeysetBatchStrategy:
    """Select the backend-appropriate keyset batching strategy for the session's dialect."""
    bind = session.get_bind()
    if bind is not None and bind.dialect.name == "sqlite":
        return StreamingCursorBatchStrategy()
    return WindowedKeysetBatchStrategy()
