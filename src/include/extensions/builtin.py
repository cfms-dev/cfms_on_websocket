import os
import threading
from typing import Optional, Union, cast

from loguru import logger as log
from sqlalchemy import update
from sqlalchemy.engine import Engine

from include.config.constants import CORE_VERSION, PROTOCOL_VERSION
from include.config.settings import global_config
from include.database.models.files import File
from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.documents.queries.file_references import _get_file_references
from include.domains.operations.messages import Messages as smsg
from include.extensions.manager import hookimpl
from include.shared import lockdown_enabled
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler

logger = log.bind(name="builtin")


class RequestServerInfoHandler(RequestHandler):
    """
    Handle the 'server_info' action to return server information.

    Args:
        this_handler: The ConnectionHandler instance handling the request.
    """

    schema = {"type": "object", "properties": {}, "additionalProperties": False}

    def handle(self, handler: ConnectionHandler):

        server_info = {
            "server_name": global_config["server"]["name"],
            "version": CORE_VERSION.original,
            "protocol_version": PROTOCOL_VERSION,
            "lockdown": lockdown_enabled.is_set(),
        }
        handler.conclude_request(
            200, server_info, "Server information retrieved successfully"
        )
        return


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

        # Shutdown the server
        handler.conclude_request(200, {}, "Server is shutting down")
        logger.info("Server is shutting down")
        threading.Thread(target=os._exit, args=(0,), daemon=True).start()


@hookimpl
def ext_register_handlers():
    return {"server_info": RequestServerInfoHandler, "shutdown": RequestShutdownHandler}


@hookimpl
def ext_post_request(
    action: str,
    handler: ConnectionHandler,
    callback: Union[
        int,
        tuple[int, Optional[str]],
        tuple[int, Optional[str], dict],
        tuple[int, Optional[str], str],
        tuple[int, Optional[str], dict, str],
        None,
    ],
    time_cost: float,
) -> None:
    logger.debug(f"Handled action '{action}' in {time_cost:.3f} seconds")


@hookimpl
def ext_on_file_uploaded(id: str, path: str, sha256: str):
    with Session() as session:
        try:
            if not sha256:
                return

            uploaded = session.get(File, id)
            if not uploaded:
                return

            # Ensure uploaded record has sha256 set
            if not uploaded.sha256:
                uploaded.sha256 = sha256
                session.commit()

            existing = (
                session.query(File)
                .filter(File.sha256 == sha256)
                .filter(File.id != uploaded.id)
                .filter(File.active == True)
                .order_by(File.created_time.asc())
                .first()
            )

            if not existing:
                return

            if uploaded.size is not None:
                existing.size = uploaded.size

            engine = cast(Engine, session.get_bind())
            for table, colname in _get_file_references(engine):
                stmt = (
                    update(table)
                    .where(table.c[colname] == uploaded.id)
                    .values({colname: existing.id})
                )
                session.execute(stmt)

            uploaded.delete()
            session.delete(uploaded)
            session.commit()

            logger.info(
                "Merged uploaded file {} into existing file {} and removed duplicate",
                uploaded.id,
                existing.id,
            )

        except Exception:
            logger.exception("Failed to process uploaded file for deduplication")
