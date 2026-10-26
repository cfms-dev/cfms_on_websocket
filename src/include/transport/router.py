import ssl
import threading
import time
import uuid

import jsonschema
import jwt
import orjson
from loguru import logger as log
from pydantic import ValidationError
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError
from websockets.exceptions import ConnectionClosedError, ConnectionClosedOK
lazy from websockets.sync.server import ServerConnection

from include.config.constants import NONCE_MIN_LENGTH
from include.config.validation import AdmissionControlPolicy
from include.database.models.identity import User, UserStatus
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
    RequestExchangeTokenHandler,
    RequestLoginHandler,
    RequestRefreshTokenHandler,
)
from include.domains.identity.handlers.auth_management import (
    RequestDeleteUserAuthPublicKeyHandler,
    RequestGetUserAuthenticationHandler,
    RequestRegisterUserAuthPublicKeyHandler,
    RequestSetUserAuthPoliciesHandler,
    RequestUpdateUserAuthPublicKeyHandler,
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
    RequestUpdateUserBlockHandler,
)
from include.domains.identity.states import AuthState
from include.domains.identity.tokens import Token, TokenPurpose
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
from include.domains.scheduling.handlers import (
    RequestCreateScheduleHandler,
    RequestDeleteScheduleHandler,
    RequestGetScheduleHandler,
    RequestListScheduledTaskTypesHandler,
    RequestListSchedulesHandler,
    RequestUpdateScheduleHandler,
)
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
from include.domains.security.handlers.totp import (
    RequestCancelTotpSetupHandler,
    RequestConfirmTotpSetupHandler,
    RequestDeleteTotpHandler,
    RequestGetTotpStatusHandler,
    RequestSetupTotpHandler,
)
from include.domains.security.validators.certificates import get_client_cert_subject
from include.extensions.manager import pm
from include.shared import clients, clients_lock
from include.transport.admission import admission_controller
from include.transport.client_address import get_client_ip
from include.transport.connection import ConnectionHandler, send_conclusion
from include.transport.multiplexing import FrameType, MultiplexedConnection, Stream
lazy from include.transport.request_handler import RequestHandler, Result

logger = log.bind(name="connection_handler")

available_functions: dict[str, type[RequestHandler]] = {
    # Authentication
    "core.auth.login": RequestLoginHandler,
    "core.auth.token.exchange": RequestExchangeTokenHandler,
    "core.auth.token.refresh": RequestRefreshTokenHandler,
    "core.user.authentication.get": RequestGetUserAuthenticationHandler,
    "core.user.authentication.policy.set": RequestSetUserAuthPoliciesHandler,
    "core.user.authentication.public_key.register": RequestRegisterUserAuthPublicKeyHandler,
    "core.user.authentication.public_key.update": RequestUpdateUserAuthPublicKeyHandler,
    "core.user.authentication.public_key.delete": RequestDeleteUserAuthPublicKeyHandler,
    # TOTP credentials
    "core.user.authentication.totp.setup": RequestSetupTotpHandler,
    "core.user.authentication.totp.setup.cancel": RequestCancelTotpSetupHandler,  # especially for cancelling setup
    "core.user.authentication.totp.setup.confirm": RequestConfirmTotpSetupHandler,
    "core.user.authentication.totp.delete": RequestDeleteTotpHandler,
    "core.user.authentication.totp.status.get": RequestGetTotpStatusHandler,
    # Security administration
    "core.security.banned_subnet.list": RequestListBannedSubnetsHandler,
    "core.security.banned_subnet.create": RequestCreateBannedSubnetHandler,
    "core.security.banned_subnet.update": RequestUpdateBannedSubnetHandler,
    "core.security.banned_subnet.delete": RequestDeleteBannedSubnetHandler,
    "core.security.auth_lockout.list": RequestListAuthLockoutsHandler,
    "core.security.auth_lockout.unlock": RequestUnlockAuthLockoutsHandler,
    # Documents
    "core.document.get": RequestGetDocumentHandler,
    "core.document.create": RequestCreateDocumentHandler,
    "core.document.upload": RequestUploadDocumentHandler,
    "core.document.delete": RequestDeleteDocumentHandler,
    "core.document.restore": RequestRestoreDocumentHandler,
    "core.document.purge": RequestPurgeDocumentHandler,
    "core.document.rename": RequestRenameDocumentHandler,
    "core.document.move": RequestMoveDocumentHandler,
    "core.document.info.get": RequestGetDocumentInfoHandler,
    "core.document.access_rule.get": RequestGetDocumentAccessRulesHandler,
    "core.document.access_rule.set": RequestSetDocumentRulesHandler,
    "core.document.tag.set": RequestSetDocumentTagsHandler,
    # Revisions
    "core.document.revision.list": RequestListRevisionsHandler,
    "core.document.revision.get": RequestGetRevisionHandler,
    "core.document.revision.current.set": RequestSetDocumentRevisionHandler,
    "core.document.revision.delete": RequestDeleteRevisionHandler,
    # Files
    "core.file.download": RequestDownloadFileHandler,
    "core.file.upload": RequestUploadFileHandler,
    # Directories
    "core.directory.list": RequestListDirectoryHandler,
    "core.directory.info.get": RequestGetDirectoryInfoHandler,
    "core.directory.access_rule.get": RequestGetDirectoryAccessRulesHandler,
    "core.directory.access_rule.set": RequestSetDirectoryRulesHandler,
    "core.directory.create": RequestCreateDirectoryHandler,
    "core.directory.delete": RequestDeleteDirectoryHandler,
    "core.directory.restore": RequestRestoreDirectoryHandler,
    "core.directory.purge": RequestPurgeDirectoryHandler,
    "core.directory.rename": RequestRenameDirectoryHandler,
    "core.directory.move": RequestMoveDirectoryHandler,
    "core.directory.deleted_item.list": RequestListDeletedItemsHandler,
    # Search
    "core.search.query": RequestSearchHandler,
    # Users
    "core.user.status.set": RequestManageUserStatusHandler,
    "core.user.block.create": RequestBlockUserHandler,
    "core.user.block.delete": RequestUnblockUserHandler,
    "core.user.block.update": RequestUpdateUserBlockHandler,
    "core.user.block.list": RequestListUserBlocksHandler,
    "core.user.list": RequestListUsersHandler,
    "core.user.create": RequestCreateUserHandler,
    "core.user.delete": RequestDeleteUserHandler,
    "core.user.rename": RequestRenameUserHandler,
    "core.user.info.get": RequestGetUserInfoHandler,
    "core.user.avatar.get": RequestGetUserAvatarHandler,
    "core.user.avatar.set": RequestSetUserAvatarHandler,
    "core.user.group.change": RequestChangeUserGroupsHandler,
    "core.user.permission.change": RequestChangeUserPermissionsHandler,
    "core.user.password.set": RequestSetPasswdHandler,
    # Groups
    "core.group.list": RequestListGroupsHandler,
    "core.group.create": RequestCreateGroupHandler,
    "core.group.delete": RequestDeleteGroupHandler,
    "core.group.rename": RequestRenameGroupHandler,
    "core.group.info.get": RequestGetGroupInfoHandler,
    "core.group.permission.change": RequestChangeGroupPermissionsHandler,
    # Access
    "core.access.entry.grant": RequestGrantAccessHandler,
    "core.access.entry.revoke": RequestRevokeAccessHandler,
    "core.access.entry.list": RequestViewAccessEntriesHandler,
    # System
    "core.server.lockdown.set": RequestLockdownHandler,
    "core.audit.entry.list": RequestViewAuditLogsHandler,
    # Scheduling
    "core.schedule.task_type.list": RequestListScheduledTaskTypesHandler,
    "core.schedule.create": RequestCreateScheduleHandler,
    "core.schedule.get": RequestGetScheduleHandler,
    "core.schedule.list": RequestListSchedulesHandler,
    "core.schedule.update": RequestUpdateScheduleHandler,
    "core.schedule.delete": RequestDeleteScheduleHandler,
    # Keyring
    "core.user.key.upload": RequestUploadUserKeyHandler,
    "core.user.key.get": RequestGetUserKeyHandler,
    "core.user.key.delete": RequestDeleteUserKeyHandler,
    "core.user.preferred_dek.set": RequestSetPreferenceDEKHandler,
    "core.user.key.list": RequestListUserKeysHandler,
}

# Requests that remain available to all users during lockdown.
whitelisted_functions = [
    "core.server.info.get",
    "core.auth.login",
    "core.auth.token.exchange",
    "core.auth.token.refresh",
    "core.user.authentication.totp.setup.confirm",
    "core.file.upload",
    "core.file.download",
    "core.server.lockdown.set",
]


def _log_handler_result(
    action: str,
    result: Result,
    remote_address: str | None = None,
) -> None:
    log_audit(
        action,
        result.code,
        user_id=result.user_id,
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

    # FIXME: For debugging purposes; remove this when unused.
    sock = websocket.socket
    if isinstance(sock, ssl.SSLSocket):
        logger.debug(
            f"Is a TLS connection: version={sock.version()} cipher={sock.cipher()} "
            f"group={sock.group()} server_sigalg={sock.server_sigalg()}",
        )

    multiplexer: MultiplexedConnection | None = None
    ext_on_connect_triggered = False
    try:
        policy = AdmissionControlPolicy.from_config()
        multiplexer = MultiplexedConnection(
            websocket,
            max_pending_inbound_streams=policy.max_pending_streams_per_connection,
        )

        with clients_lock:
            clients.add(multiplexer)

        pm.hook.ext_on_connect(websocket=websocket)
        ext_on_connect_triggered = True

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
            websocket.close(
                code=multiplexer.close_code,
                reason=multiplexer.close_reason,
            )
        else:
            websocket.close()

        if multiplexer is not None:
            with clients_lock:
                clients.discard(multiplexer)

        if ext_on_connect_triggered:
            pm.hook.ext_post_disconnect()
        admission_controller.release_connection(ip)


def _handle_request_with_admission(stream: Stream) -> None:
    try:
        handle_request(stream)
    except SQLAlchemyTimeoutError:
        policy = AdmissionControlPolicy.from_config()
        logger.bind(scope="database_pool").warning(
            "Database connection pool exhausted while handling a request"
        )
        send_conclusion(
            stream,
            503,
            {
                "scope": "database_pool",
                "retry_after_seconds": policy.busy_retry_after_seconds,
            },
            "Server database capacity is busy. Please try again later.",
        )
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
        stream.connection.close(code=1008, reason="IP address is not permitted")
        return

    try:
        this_handler = ConnectionHandler(stream)
    except orjson.JSONDecodeError:
        send_conclusion(stream, 400, {}, "Invalid request JSON")
        return
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
    user_auth_state: AuthState = AuthState.NONE
    token: Token | None = None

    if unverified_raw_token := this_handler.request.get("token"):
        # CAUTION! Touching a unverified token requires careful handling.
        try:
            unverified = jwt.decode(
                unverified_raw_token,
                options={"verify_signature": False},
            )
            claimed_user_id = uuid.UUID(unverified["sub"])
        except jwt.InvalidTokenError, KeyError, ValueError, TypeError, AttributeError:
            this_handler.conclude_request(401, {}, "Invalid token")
            return

        with Session() as session:
            user = session.get(User, claimed_user_id)
            if not user:  # User not found
                this_handler.conclude_request(401, {}, "Invalid token")
                return

            try:
                token = Token.from_raw(unverified_raw_token, user.secret_key)
            except jwt.ExpiredSignatureError:
                this_handler.conclude_request(401, {}, "Token has expired")
                return
            except jwt.InvalidTokenError:
                this_handler.conclude_request(401, {}, "Invalid token")
                return

            if user.status != UserStatus.ACTIVE:
                this_handler.conclude_request(401, {}, "Invalid token")
                return

            # The purpose of the token is left to subsequent logic for validation.
            # However, it is obvious to say that a token lacking the GENERAL purpose
            # cannot be considered authenticated.
            if token.purpose & TokenPurpose.GENERAL:
                user_auth_state = AuthState.FULL
                user_permissions = user.all_permissions
            else:
                user_auth_state = AuthState.PARTIAL

            this_handler.user_id = user.id
            this_handler.token = token

    if (
        token is not None
        and token.purpose & TokenPurpose.POST_AUTH
        and (
            token.purpose != TokenPurpose.POST_AUTH
            or action != "core.user.password.set"
        )
    ):
        this_handler.conclude_request(
            403, {}, "POST_AUTH is restricted to core.user.password.set"
        )
        return

    handler_type = available_functions.get(action)
    if handler_type is None:
        this_handler.conclude_request(400, {}, f"Unknown action: {action}")
        return

    rate_decision = check_request_rate(
        action,
        handler_type.rate_limit_cost,
        ip,
        user_id=this_handler.user_id if user_auth_state == AuthState.FULL else None,
        bypass=(
            user_auth_state == AuthState.FULL
            and Permissions.BYPASS_REQUEST_RATE_LIMIT in user_permissions
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
    if (
        lockdown_state.enabled
        and action not in whitelisted_functions
        and not (
            token is not None
            and token.purpose == TokenPurpose.POST_AUTH
            and action == "core.user.password.set"
        )
    ):
        can_bypass_lockdown = False
        if (
            user_auth_state == AuthState.FULL
            and Permissions.BYPASS_LOCKDOWN in user_permissions
        ):
            can_bypass_lockdown = True

        if not can_bypass_lockdown:
            this_handler.conclude_request(
                999, lockdown_state.as_response_data(), "lockdown"
            )
            return

    # Replay attack protection: validate nonce and timestamp.
    # Only applied to authenticated requests to prevent unauthenticated
    # traffic from polluting the nonce store (DoS vector).
    if (
        user_auth_state != AuthState.NONE
        and _validate_replay_protection(this_handler) is not None
    ):
        return

    if handler_type is not None:
        _request_handler: RequestHandler = handler_type()

        try:
            request = _request_handler.request_model.model_validate(this_handler.data)
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

        if _request_handler.requires_auth:
            if user_auth_state == AuthState.NONE:
                this_handler.conclude_request(401, {}, "Authentication required")
                log_audit(
                    action,
                    401,
                    data=None,
                    remote_address=this_handler.remote_address,
                )
                return

            assert token is not None

            if not token.purpose & _request_handler.required_token_purpose:
                this_handler.conclude_request(
                    403,
                    {},
                    "Token does not have the required purpose: "
                    f"{_request_handler.required_token_purpose.name}",
                )
                log_audit(
                    action,
                    403,
                    user_id=token.sub,
                    data=None,
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

            callback: Result | None = _request_handler.handle(this_handler, request)

            t2 = time.perf_counter()
            if callback is not None:
                _log_handler_result(action, callback, this_handler.remote_address)
            pm.hook.ext_post_request(
                action=action,
                handler=this_handler,
                callback=callback,
                time_cost=t2 - t1,
            )
        except SQLAlchemyTimeoutError:
            raise
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
