import platform
import ssl
import threading
from importlib.metadata import version as distribution_version
from typing import TYPE_CHECKING

from loguru import logger as log
from websockets.sync.server import Server

if TYPE_CHECKING:
    from sqlalchemy.orm import Session as OrmSession

from include.config.constants import CORE_VERSION, PROTOCOL_VERSION
from include.config.settings import global_config
from include.database.models.identity import User
from include.database.session import Session, engine
from include.domains.access.permissions import Permissions
from include.domains.operations.lockdown import lockdown_state_manager
from include.extensions.manager import (
    collect_extension_flags,
    get_loaded_extension_metadata,
    hookimpl,
)
from include.messages import Messages as smsg
from include.providers.manager import ProviderManager
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import (
    EmptyRequestDataModel,
    RequestHandler,
    Result,
)

from .file_deduplication import (
    file_deduplication_worker,
    release_file_deduplication,
    schedule_file_deduplication,
)
from .permission_cleanup import permission_cleanup_task
from .scheduled_tasks import BUILTIN_SCHEDULED_TASKS

logger = log.bind(name="builtin")
_active_server_lock = threading.Lock()
_active_server: Server | None = None

_CORE_COMPONENT_DISTRIBUTIONS = {
    "apscheduler": "APScheduler",
    "cryptography": "cryptography",
    "orjson": "orjson",
    "pluggy": "pluggy",
    "pydantic": "pydantic",
    "sqlalchemy": "SQLAlchemy",
    "websockets": "websockets",
}


def _component_versions() -> dict[str, str]:
    distributions = dict(_CORE_COMPONENT_DISTRIBUTIONS)
    provider_config = global_config["provider"]
    if "redis" in provider_config.values():
        distributions["redis"] = "redis"
    if provider_config["storage"] == "s3":
        distributions["boto3"] = "boto3"
    if global_config["database"]["type"] == "mysql":
        distributions["mysql_connector_python"] = "mysql-connector-python"
    if provider_config.get("scheduling", "local") == "redis":
        distributions["dramatiq"] = "dramatiq"
    return {
        component: distribution_version(distribution)
        for component, distribution in distributions.items()
    }


class RequestServerInfoHandler(RequestHandler):
    """
    Handle the 'server_info' action to return server information.

    Args:
        this_handler: The ConnectionHandler instance handling the request.
    """

    request_model = EmptyRequestDataModel
    rate_limit_cost = 1

    def handle(self, handler: ConnectionHandler):
        lockdown_state = lockdown_state_manager.get_state()

        server_info = {
            "server_name": global_config["server"]["name"],
            "protocol_version": PROTOCOL_VERSION,
            "lockdown": lockdown_state.enabled,
            "lockdown_reason": lockdown_state.reason,
            "extension_flags": collect_extension_flags(),
        }
        handler.conclude_request(
            200, server_info, "Server information retrieved successfully"
        )


class RequestDiagnosticsHandler(RequestHandler):
    request_model = EmptyRequestDataModel
    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        with Session() as session:
            user = User.get_existing(session, handler.username)
            if Permissions.DIAGNOSTICS not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.PERMISSION_DENIED)
                return Result(code=403, target=None, username=handler.username)

        lockdown_state = lockdown_state_manager.get_state()
        provider_config = global_config["provider"]
        scheduling_status = ProviderManager().scheduling.status()
        diagnostics = {
            "schema_version": 1,
            "server": {
                "server_name": global_config["server"]["name"],
                "core_version": CORE_VERSION.original,
                "protocol_version": PROTOCOL_VERSION,
                "debug_configured": global_config["debug"],
            },
            "runtime": {
                "python_implementation": platform.python_implementation(),
                "python_version": platform.python_version(),
                "openssl_version": ssl.OPENSSL_VERSION,
                "operating_system": platform.system(),
                "operating_system_release": platform.release(),
                "architecture": platform.machine(),
            },
            "component_versions": _component_versions(),
            "database": {
                "dialect": engine.dialect.name,
                "driver": engine.dialect.driver,
            },
            "providers": {
                "storage": provider_config["storage"],
                "caching": provider_config["caching"],
                "event_bus": provider_config["event_bus"],
                "rate_limit": provider_config.get("rate_limit", "memory"),
                "scheduling": provider_config.get("scheduling", "local"),
            },
            "scheduling": {
                "available": scheduling_status.available,
                "mode": scheduling_status.mode,
                "detail": scheduling_status.detail,
            },
            "extensions": [
                {
                    "identifier": metadata.identifier,
                    "name": metadata.name,
                    "version": metadata.version,
                }
                for metadata in get_loaded_extension_metadata()
            ],
            "extension_flags": collect_extension_flags(),
            "lockdown": {
                "enabled": lockdown_state.enabled,
                "reason": lockdown_state.reason,
            },
        }
        handler.conclude_request(
            200, diagnostics, "Server diagnostics retrieved successfully"
        )
        return Result(code=0, target=None, username=handler.username)


class RequestShutdownHandler(RequestHandler):
    """
    Handle the 'shutdown' action to gracefully shut down the server.

    Args:
        this_handler: The ConnectionHandler instance handling the request.
    """

    request_model = EmptyRequestDataModel
    require_auth = True
    rate_limit_cost = 1

    def handle(self, handler: ConnectionHandler):

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.SHUTDOWN not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.PERMISSION_DENIED)
                return

        handler.conclude_request(200, {}, "Server is shutting down")
        logger.info("Server is shutting down")
        with _active_server_lock:
            server = _active_server
        if server is None:
            logger.error("Shutdown requested while no WebSocket server is active")
        else:
            server.shutdown()


@hookimpl
def ext_on_startup(server: Server) -> None:
    global _active_server

    with _active_server_lock:
        if _active_server is not None:
            raise RuntimeError("A WebSocket server is already active")
        _active_server = server
    try:
        file_deduplication_worker.start()
    except Exception:
        try:
            file_deduplication_worker.stop()
        finally:
            with _active_server_lock:
                if _active_server is server:
                    _active_server = None
        raise


@hookimpl
def ext_on_shutdown() -> None:
    global _active_server

    try:
        file_deduplication_worker.stop()
    finally:
        with _active_server_lock:
            _active_server = None


@hookimpl
def ext_register_handlers():
    return {
        "server_info": RequestServerInfoHandler,
        "diagnostics": RequestDiagnosticsHandler,
        "shutdown": RequestShutdownHandler,
    }


@hookimpl
def ext_register_scheduled_tasks():
    return (permission_cleanup_task, *BUILTIN_SCHEDULED_TASKS)


@hookimpl
def ext_post_request(
    action: str,
    handler: ConnectionHandler,
    callback: Result | None,
    time_cost: float,
) -> None:
    logger.debug(f"Handled action '{action}' in {time_cost:.3f} seconds")


@hookimpl
def ext_before_file_upload_finalize(
    session: "OrmSession",
    id: str,
    path: str,
    sha256: str,
) -> None:
    if sha256:
        schedule_file_deduplication(session, id)


@hookimpl
def ext_on_file_upload_completed(id: str, path: str, sha256: str) -> None:
    if sha256:
        release_file_deduplication(id)
