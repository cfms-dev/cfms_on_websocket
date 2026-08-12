import threading
import time

import jsonschema
import orjson
from loguru import logger as log
from pydantic import ValidationError
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK
from websockets.sync.server import ServerConnection

from include.config.constants import NONCE_MIN_LENGTH
from include.config.validation import AdmissionControlPolicy
from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.handlers import (
    RequestGrantAccessHandler,
    RequestRevokeAccessHandler,
    RequestViewAccessEntriesHandler,
)
from include.domains.access.permissions import Permissions
from include.domains.documents.handlers.directories import (
    RequestCreateDirectoryHandler,
    RequestDeleteDirectoryHandler,
    RequestGetDirectoryAccessRulesHandler,
    RequestGetDirectoryInfoHandler,
    RequestListDeletedItemsHandler,
    RequestListDirectoryHandler,
    RequestMoveDirectoryHandler,
    RequestPurgeDirectoryHandler,
    RequestRenameDirectoryHandler,
    RequestRestoreDirectoryHandler,
    RequestSetDirectoryRulesHandler,
)
from include.domains.documents.handlers.documents import (
    RequestCreateDocumentHandler,
    RequestDeleteDocumentHandler,
    RequestDownloadFileHandler,
    RequestGetDocumentAccessRulesHandler,
    RequestGetDocumentHandler,
    RequestGetDocumentInfoHandler,
    RequestMoveDocumentHandler,
    RequestPurgeDocumentHandler,
    RequestRenameDocumentHandler,
    RequestRestoreDocumentHandler,
    RequestSetDocumentRulesHandler,
    RequestSetDocumentTagsHandler,
    RequestUploadDocumentHandler,
    RequestUploadFileHandler,
)
from include.domains.documents.handlers.revisions import (
    RequestDeleteRevisionHandler,
    RequestGetRevisionHandler,
    RequestListRevisionsHandler,
    RequestSetDocumentRevisionHandler,
)
from include.domains.documents.handlers.search import RequestSearchHandler
from include.domains.identity.handlers.auth import (
    RequestLoginHandler,
    RequestRefreshTokenHandler,
)
from include.domains.identity.handlers.groups import (
    RequestChangeGroupPermissionsHandler,
    RequestCreateGroupHandler,
    RequestDeleteGroupHandler,
    RequestGetGroupInfoHandler,
    RequestListGroupsHandler,
    RequestRenameGroupHandler,
)
from include.domains.identity.handlers.users import (
    RequestBlockUserHandler,
    RequestChangeUserGroupsHandler,
    RequestChangeUserPermissionsHandler,
    RequestCreateUserHandler,
    RequestDeleteUserHandler,
    RequestGetUserAvatarHandler,
    RequestGetUserInfoHandler,
    RequestListUserBlocksHandler,
    RequestListUsersHandler,
    RequestManageUserStatusHandler,
    RequestRenameUserHandler,
    RequestSetPasswdHandler,
    RequestSetUserAvatarHandler,
    RequestUnblockUserHandler,
)
from include.domains.keyrings.handlers.keyrings import (
    RequestDeleteUserKeyHandler,
    RequestGetUserKeyHandler,
    RequestListUserKeysHandler,
    RequestSetPreferenceDEKHandler,
    RequestUploadUserKeyHandler,
)
from include.domains.operations.commands.audit import log_audit
from include.domains.operations.handlers.system import (
    RequestLockdownHandler,
    RequestViewAuditLogsHandler,
)
from include.domains.operations.lockdown import lockdown_state_manager
from include.domains.security.guards.login import LoginGuard
from include.domains.security.guards.replay import nonce_store
from include.domains.security.guards.request_rate_control import check_request_rate
from include.domains.security.handlers.access_control import (
    RequestCreateBannedSubnetHandler,
    RequestDeleteBannedSubnetHandler,
    RequestListAuthLockoutsHandler,
    RequestListBannedSubnetsHandler,
    RequestUnlockAuthLockoutsHandler,
    RequestUpdateBannedSubnetHandler,
)
from include.domains.security.handlers.two_factor import (
    RequestCancel2FASetupHandler,
    RequestDisable2FAHandler,
    RequestGet2FAStatusHandler,
    RequestSetup2FAHandler,
    RequestValidate2FAHandler,
)
from include.domains.security.validators.certificates import get_client_cert_subject
from include.extensions.manager import pm
from include.shared import clients, clients_lock
from include.transport.admission import admission_controller
from include.transport.client_address import get_client_ip
from include.transport.connection import ConnectionHandler, send_conclusion
from include.transport.multiplexing import FrameType, MultiplexedConnection, Stream
from include.transport.request_handler import RequestHandler, Result

logger = log.bind(name="connection_handler")

available_functions: dict[str, type[RequestHandler]] = {
    # Authentication
    "login": RequestLoginHandler,
    "refresh_token": RequestRefreshTokenHandler,
    # Two-factor authentication
    "setup_2fa": RequestSetup2FAHandler,
    "cancel_2fa_setup": RequestCancel2FASetupHandler,  # especially for cancelling setup
    "validate_2fa": RequestValidate2FAHandler,
    "disable_2fa": RequestDisable2FAHandler,
    "get_2fa_status": RequestGet2FAStatusHandler,
    # Security administration
    "list_banned_subnets": RequestListBannedSubnetsHandler,
    "create_banned_subnet": RequestCreateBannedSubnetHandler,
    "update_banned_subnet": RequestUpdateBannedSubnetHandler,
    "delete_banned_subnet": RequestDeleteBannedSubnetHandler,
    "list_auth_lockouts": RequestListAuthLockoutsHandler,
    "unlock_auth_lockouts": RequestUnlockAuthLockoutsHandler,
    # Documents
    "get_document": RequestGetDocumentHandler,
    "create_document": RequestCreateDocumentHandler,
    "upload_document": RequestUploadDocumentHandler,
    "delete_document": RequestDeleteDocumentHandler,
    "restore_document": RequestRestoreDocumentHandler,
    "purge_document": RequestPurgeDocumentHandler,
    "rename_document": RequestRenameDocumentHandler,
    "move_document": RequestMoveDocumentHandler,
    "get_document_info": RequestGetDocumentInfoHandler,
    "get_document_access_rules": RequestGetDocumentAccessRulesHandler,
    "set_document_rules": RequestSetDocumentRulesHandler,
    "set_document_tags": RequestSetDocumentTagsHandler,
    # Revisions
    "list_revisions": RequestListRevisionsHandler,
    "get_revision": RequestGetRevisionHandler,
    "set_current_revision": RequestSetDocumentRevisionHandler,
    "delete_revision": RequestDeleteRevisionHandler,
    # Files
    "download_file": RequestDownloadFileHandler,
    "upload_file": RequestUploadFileHandler,
    # Directories
    "list_directory": RequestListDirectoryHandler,
    "get_directory_info": RequestGetDirectoryInfoHandler,
    "get_directory_access_rules": RequestGetDirectoryAccessRulesHandler,
    "set_directory_rules": RequestSetDirectoryRulesHandler,
    "create_directory": RequestCreateDirectoryHandler,
    "delete_directory": RequestDeleteDirectoryHandler,
    "restore_directory": RequestRestoreDirectoryHandler,
    "purge_directory": RequestPurgeDirectoryHandler,
    "rename_directory": RequestRenameDirectoryHandler,
    "move_directory": RequestMoveDirectoryHandler,
    "list_deleted_items": RequestListDeletedItemsHandler,
    # Search
    "search": RequestSearchHandler,
    # Users
    "manage_user_status": RequestManageUserStatusHandler,
    "block_user": RequestBlockUserHandler,
    "unblock_user": RequestUnblockUserHandler,
    "list_user_blocks": RequestListUserBlocksHandler,
    "list_users": RequestListUsersHandler,
    "create_user": RequestCreateUserHandler,
    "delete_user": RequestDeleteUserHandler,
    "rename_user": RequestRenameUserHandler,
    "get_user_info": RequestGetUserInfoHandler,
    "get_user_avatar": RequestGetUserAvatarHandler,
    "set_user_avatar": RequestSetUserAvatarHandler,
    "change_user_groups": RequestChangeUserGroupsHandler,
    "change_user_permissions": RequestChangeUserPermissionsHandler,
    "set_passwd": RequestSetPasswdHandler,
    # Groups
    "list_groups": RequestListGroupsHandler,
    "create_group": RequestCreateGroupHandler,
    "delete_group": RequestDeleteGroupHandler,
    "rename_group": RequestRenameGroupHandler,
    "get_group_info": RequestGetGroupInfoHandler,
    "change_group_permissions": RequestChangeGroupPermissionsHandler,
    # Access
    "grant_access": RequestGrantAccessHandler,
    "revoke_access": RequestRevokeAccessHandler,
    "view_access_entries": RequestViewAccessEntriesHandler,
    # System
    "lockdown": RequestLockdownHandler,
    "view_audit_logs": RequestViewAuditLogsHandler,
    # Keyring
    "upload_user_key": RequestUploadUserKeyHandler,
    "get_user_key": RequestGetUserKeyHandler,
    "delete_user_key": RequestDeleteUserKeyHandler,
    "set_user_preference_dek": RequestSetPreferenceDEKHandler,
    "list_user_keys": RequestListUserKeysHandler,
}

# Requests that remain available to all users during lockdown.
whitelisted_functions = [
    "server_info",
    "login",
    "refresh_token",
    "validate_2fa",
    "upload_file",
    "download_file",
]


def _log_handler_result(
    action: str,
    result: Result,
    remote_address: str | None = None,
) -> None:
    log_audit(
        action,
        result.code,
        username=result.username,
        target=result.target,
        data=result.data,
        remote_address=remote_address,
    )


def _validate_replay_protection(
    handler: ConnectionHandler,
) -> str | None:
    """Validate nonce and timestamp for an authenticated request.

    Returns None on success, or an error string after sending a rejection
    response via handler.conclude_request.
    """
    nonce = handler.nonce
    request_timestamp = handler.request_timestamp

    if not nonce or len(nonce) < NONCE_MIN_LENGTH:
        handler.conclude_request(
            400, {}, "Missing or invalid nonce for replay protection"
        )
        return "nonce"

    if not request_timestamp:
        handler.conclude_request(
            400, {}, "Missing or invalid timestamp for replay protection"
        )
        return "timestamp"

    replay_error = nonce_store.validate_and_store(nonce, float(request_timestamp))
    if replay_error is not None:
        handler.conclude_request(1001, {}, replay_error)
        return "replay"

    return None


def handle_connection(websocket: ServerConnection):
    """Handle incoming WebSocket connections.

    Args:
        websocket: The WebSocket connection object.

    """
    ip = get_client_ip(websocket)
    connection_admission = admission_controller.acquire_connection(ip)
    if not connection_admission.allowed:
        logger.warning(
            f"Rejecting connection from {ip}: {connection_admission.scope} capacity reached"
        )
        websocket.close(code=1013, reason="Server connection capacity reached")
        return

    client_cn = get_client_cert_subject(websocket)
    if client_cn:
        logger.info(
            f"Incoming connection: {websocket.remote_address[0]} (client cert CN: {client_cn})"
        )
    else:
        logger.info(f"Incoming connection: {websocket.remote_address[0]}")

    multiplexer: MultiplexedConnection | None = None
    extension_connected = False
    try:
        policy = AdmissionControlPolicy.from_config()
        multiplexer = MultiplexedConnection(
            websocket,
            max_pending_inbound_streams=policy.max_pending_streams_per_connection,
        )

        with clients_lock:
            clients.add(multiplexer)

        pm.hook.ext_on_connect(websocket=websocket)
        extension_connected = True

        while True:
            stream = multiplexer.accept_stream()
            if stream is None:
                break  # Connection closed

            request_admission = admission_controller.acquire_request(multiplexer)
            if not request_admission.allowed:
                send_conclusion(
                    stream,
                    503,
                    {
                        "scope": request_admission.scope,
                        "retry_after_seconds": request_admission.retry_after_seconds,
                    },
                    "Server is busy. Please try again later.",
                )
                continue

            try:
                threading.Thread(
                    target=_handle_request_with_admission,
                    args=(stream,),
                    daemon=True,
                ).start()
            except Exception:
                admission_controller.release_request(multiplexer)
                raise

    finally:
        if multiplexer is not None:
            multiplexer.close()
        websocket.close()

        if multiplexer is not None:
            with clients_lock:
                clients.discard(multiplexer)

        if extension_connected:
            pm.hook.ext_post_disconnect()
        admission_controller.release_connection(ip)


def _handle_request_with_admission(stream: Stream) -> None:
    try:
        handle_request(stream)
    finally:
        admission_controller.release_request(stream.connection)


def handle_request(stream: Stream):
    """Handle a specific request/message received over the WebSocket connection.

    Args:
        stream: The Stream object representing the logical request stream.

    """
    ip = get_client_ip(stream.connection._ws)

    if not LoginGuard.evaluate_subnet_access(ip).allowed:
        response = {
            "code": 403,
            "message": "Your IP address is not permitted.",
            "timestamp": time.time(),
        }
        stream.send(orjson.dumps(response), frame_type=FrameType.CONCLUSION)
        # Force-close the WebSocket connection.
        # 1008 is the WebSocket policy violation close code.
        stream.connection.close()
        stream.connection._ws.close(code=1008, reason="IP address is not permitted")
        return

    try:
        this_handler = ConnectionHandler(stream)
    except jsonschema.ValidationError as error:
        # Request envelope failed schema validation — send error and bail out
        response = {
            "code": 400,
            "data": {},
            "message": f"Invalid request format: {error.message}",
            "timestamp": time.time(),
        }
        stream.send(
            orjson.dumps(
                response,
            ),
            frame_type=FrameType.CONCLUSION,
        )
        return

    action = this_handler.action

    if action is None:
        this_handler.conclude_request(400, {}, "No action specified in request")
        return

    user_permissions: set[Permissions] = set()
    authenticated = False
    if this_handler.username and this_handler.token:
        with Session() as session:
            user = session.get(User, this_handler.username)
            if user and user.is_token_valid(this_handler.token):
                authenticated = True
                user_permissions = user.all_permissions
            else:
                this_handler.conclude_request(401, {}, "Invalid user or token")
                return

    handler_type = available_functions.get(action)
    if handler_type is None:
        this_handler.conclude_request(400, {}, f"Unknown action: {action}")
        return

    rate_decision = check_request_rate(
        action,
        handler_type.rate_limit_cost,
        ip,
        username=this_handler.username if authenticated else None,
        bypass=(
            authenticated and Permissions.BYPASS_REQUEST_RATE_LIMIT in user_permissions
        ),
    )
    if not rate_decision.allowed:
        this_handler.conclude_request(
            429,
            {
                "scope": rate_decision.scope,
                "limit": rate_decision.limit,
                "retry_after_seconds": rate_decision.retry_after_seconds,
            },
            "Too many requests. Please try again later.",
        )
        return

    lockdown_state = lockdown_state_manager.get_state()
    if lockdown_state.enabled and action not in whitelisted_functions:
        can_bypass_lockdown = False
        if authenticated and Permissions.BYPASS_LOCKDOWN in user_permissions:
            can_bypass_lockdown = True

        if not can_bypass_lockdown:
            this_handler.conclude_request(
                999, lockdown_state.as_response_data(), "lockdown"
            )
            return

    # Replay attack protection: validate nonce and timestamp.
    # Only applied to authenticated requests to prevent unauthenticated
    # traffic from polluting the nonce store (DoS vector).
    if authenticated and _validate_replay_protection(this_handler) is not None:
        return

    if handler_type is not None:
        _request_handler: RequestHandler = handler_type()

        try:
            _request_handler.request_model.model_validate(this_handler.data)
        except ValidationError as error:
            this_handler.conclude_request(
                400,
                {
                    "errors": error.errors(
                        include_url=False,
                        include_context=False,
                        include_input=False,
                    )
                },
                "Invalid request data",
            )
            return

        if _request_handler.require_auth and not authenticated:
            this_handler.conclude_request(401, {}, "Authentication required")
            log_audit(
                action,
                401,
                data=this_handler.data,
                remote_address=this_handler.remote_address,
            )
            return

        try:
            if (
                pm.hook.ext_before_request(
                    request_handler=_request_handler,
                    connection_handler=this_handler,
                )
                is False
            ):
                return
            t1 = time.perf_counter()

            callback: Result | None = _request_handler.handle(this_handler)

            t2 = time.perf_counter()
            if callback is not None:
                _log_handler_result(action, callback, this_handler.remote_address)
            pm.hook.ext_post_request(
                action=action,
                handler=this_handler,
                callback=callback,
                time_cost=t2 - t1,
            )
        except (
            ConnectionClosedOK,
            ConnectionClosedError,
        ):
            logger.info("WebSocket connection closed during request handling")
            return
        except Exception as e:  # noqa: BLE001 - convert handler failures into protocol errors.
            this_handler.report_error(e)
            return

        if callback is None:
            # Reserved for flows that should not submit audit data via return.
            return
    return
