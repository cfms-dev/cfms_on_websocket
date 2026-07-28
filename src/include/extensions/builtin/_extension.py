import threading

from loguru import logger as log
from websockets.sync.server import Server

from include.config.constants import CORE_VERSION, PROTOCOL_VERSION
from include.config.settings import global_config
from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.operations.lockdown import lockdown_state_manager
from include.extensions.manager import collect_extension_flags, hookimpl
from include.messages import Messages as smsg
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler, Result

logger = log.bind(name="builtin")
_active_server_lock = threading.Lock()
_active_server: Server | None = None


class RequestServerInfoHandler(RequestHandler):
    """
    Handle the 'server_info' action to return server information.

    Args:
        this_handler: The ConnectionHandler instance handling the request.
    """

    schema = {"type": "object", "properties": {}, "additionalProperties": False}

    def handle(self, handler: ConnectionHandler):
        lockdown_state = lockdown_state_manager.get_state()

        server_info = {
            "server_name": global_config["server"]["name"],
            "version": CORE_VERSION.original,
            "protocol_version": PROTOCOL_VERSION,
            "lockdown": lockdown_state.enabled,
            "lockdown_reason": lockdown_state.reason,
            "extension_flags": collect_extension_flags(),
        }
        handler.conclude_request(
            200, server_info, "Server information retrieved successfully"
        )


class RequestShutdownHandler(RequestHandler):
    """
    Handle the 'shutdown' action to gracefully shut down the server.

    Args:
        this_handler: The ConnectionHandler instance handling the request.
    """

    schema = {"type": "object", "properties": {}, "additionalProperties": False}
    require_auth = True

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


@hookimpl
def ext_on_shutdown() -> None:
    global _active_server

    with _active_server_lock:
        _active_server = None


@hookimpl
def ext_register_handlers():
    return {"server_info": RequestServerInfoHandler, "shutdown": RequestShutdownHandler}


@hookimpl
def ext_post_request(
    action: str,
    handler: ConnectionHandler,
    callback: Result | None,
    time_cost: float,
) -> None:
    logger.debug(f"Handled action '{action}' in {time_cost:.3f} seconds")
