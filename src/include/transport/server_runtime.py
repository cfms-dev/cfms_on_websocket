__all__ = ["ServerRuntime", "server_runtime"]

import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Protocol


class _ShutdownServer(Protocol):
    def shutdown(self) -> None: ...


class ServerRuntime:
    """Track the active WebSocket server and coordinate graceful shutdown."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._server: _ShutdownServer | None = None

    @contextmanager
    def bind(self, server: _ShutdownServer) -> Iterator[None]:
        with self._lock:
            if self._server is not None:
                raise RuntimeError("A WebSocket server is already bound")
            self._server = server

        try:
            yield
        finally:
            with self._lock:
                if self._server is server:
                    self._server = None

    def request_shutdown(self) -> bool:
        with self._lock:
            server = self._server
        if server is None:
            return False

        server.shutdown()
        return True

    def serve(
        self,
        server: _ShutdownServer,
        on_start: Callable[[], object],
        on_stop: Callable[[], object],
    ) -> None:
        """Run a bound server and guarantee the matching stop callback."""
        with self.bind(server):
            try:
                on_start()
                server.serve_forever()
            finally:
                on_stop()


server_runtime = ServerRuntime()
