__all__ = ["HttpApiRuntime"]

import threading
import time
from dataclasses import dataclass

import uvicorn
from fastapi import FastAPI
from loguru import logger as log

from include.config.settings import global_config
from include.transport.tls import create_server_ssl_context

from .config import HttpApiPolicy

logger = log.bind(name="http_api")


class _SignallingServer(uvicorn.Server):
    def __init__(self, config: uvicorn.Config, startup_event: threading.Event):
        super().__init__(config)
        self._startup_event = startup_event

    async def startup(self, sockets=None) -> None:
        try:
            await super().startup(sockets=sockets)
        finally:
            if self.started or self.should_exit:
                self._startup_event.set()


@dataclass(slots=True)
class _ActiveServer:
    server: _SignallingServer
    thread: threading.Thread
    startup_event: threading.Event
    failure: BaseException | None = None


class HttpApiRuntime:
    def __init__(self):
        self._lock = threading.Lock()
        self._active: _ActiveServer | None = None

    @staticmethod
    def _create_ssl_context(policy: HttpApiPolicy):
        server_config = global_config["server"]
        security_config = global_config.get("security", {})
        require_client_cert = security_config.get("require_client_cert", False)
        return create_server_ssl_context(
            policy.ssl_certfile or server_config["ssl_certfile"],
            policy.ssl_keyfile or server_config["ssl_keyfile"],
            require_client_cert=require_client_cert,
            client_ca_path=(
                security_config["client_cert_ca_path"] if require_client_cert else None
            ),
        )

    def start(self, app: FastAPI, policy: HttpApiPolicy) -> None:
        with self._lock:
            if self._active is not None:
                raise RuntimeError("The HTTP API server is already active")

            startup_event = threading.Event()
            config = uvicorn.Config(
                app,
                host=policy.host,
                port=policy.port,
                workers=1,
                access_log=False,
                proxy_headers=False,
                limit_concurrency=policy.max_concurrency,
                timeout_graceful_shutdown=int(policy.shutdown_timeout_seconds),
                ssl_context_factory=lambda _config, _factory: self._create_ssl_context(
                    policy
                ),
            )
            server = _SignallingServer(config, startup_event)
            active = _ActiveServer(
                server=server,
                thread=threading.Thread(
                    name="cfms-http-api",
                    target=lambda: self._run(active),
                    daemon=False,
                ),
                startup_event=startup_event,
            )
            self._active = active
            active.thread.start()

        if not startup_event.wait(policy.startup_timeout_seconds):
            server.should_exit = True
            active.thread.join(policy.shutdown_timeout_seconds)
            if active.thread.is_alive():
                server.force_exit = True
                logger.error(
                    "HTTP API startup timed out and its server thread did not stop "
                    f"within {policy.shutdown_timeout_seconds} seconds"
                )
            else:
                with self._lock:
                    if self._active is active:
                        self._active = None
            raise RuntimeError("Timed out while starting the HTTP API server")

        if active.failure is not None:
            with self._lock:
                if self._active is active:
                    self._active = None
            raise RuntimeError(
                "Failed to start the HTTP API server"
            ) from active.failure
        if not server.started or not active.thread.is_alive():
            with self._lock:
                if self._active is active:
                    self._active = None
            raise RuntimeError("The HTTP API server stopped during startup")
        logger.info(f"CFMS HTTP API started at https://{policy.host}:{policy.port}")

    def _run(self, active: _ActiveServer) -> None:
        try:
            active.server.run()
        except BaseException as exc:  # noqa: BLE001
            active.failure = exc
        finally:
            active.startup_event.set()

    def shutdown(self, timeout_seconds: float) -> None:
        with self._lock:
            active = self._active
        if active is None:
            return

        active.server.should_exit = True
        deadline = time.monotonic() + timeout_seconds
        active.thread.join(max(0.0, deadline - time.monotonic()))
        if active.thread.is_alive():
            active.server.force_exit = True
            logger.error(
                f"HTTP API server did not stop within {timeout_seconds} seconds"
            )
            return

        with self._lock:
            if self._active is active:
                self._active = None
