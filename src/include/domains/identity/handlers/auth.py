import time
from typing import Any

from include.config.settings import global_config
from include.database.models.identity import User
from include.database.session import Session
from include.domains.identity.sessions import build_login_success_data
from include.domains.identity.validators.passwords import check_passwd_requirements
from include.domains.operations.commands.audit import log_audit
from include.domains.security.guards.login import LoginGuard
from include.exceptions.misc import (
    UserNotActiveError,
    UserTOTPFailedError,
    UserTOTPRequiredError,
)
from include.transport.client_address import get_client_ip
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler, Result


class RequestLoginHandler(RequestHandler):
    """
    Handles user login requests.
    """

    schema = {
        "type": "object",
        "properties": {
            "username": {"type": "string", "minLength": 1},
            "password": {"type": "string", "minLength": 1},
            "2fa_token": {"type": "string", "minLength": 1},
        },
        "required": ["username", "password"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler):
        username: str = handler.data["username"]
        password: str = handler.data["password"]
        totp_token: str = handler.data.get("2fa_token", "")

        ip = get_client_ip(handler.stream.connection._ws)

        def respond(code: int, message: str, data: dict[str, Any] | None = None):
            handler.conclude_request(code=code, data=data or {}, message=message)
            return Result(code=code, target=username)

        def fail(code: int, message: str, data: dict[str, Any] | None = None):
            # Throttle by both IP+username and IP-only
            LoginGuard.report_failure(ip, username, max_attempts=5, ip_max_attempts=20)
            return respond(code, message, data)

        # Check access: both by IP+username and IP-only are checked simultaneously
        if not LoginGuard.check_access(ip, username):
            return respond(429, "Too many login attempts. Please try again later.")

        cfg = global_config["security"]

        with Session() as session:
            user = session.get(User, username)

            if not user:
                return fail(401, "Invalid credentials")

            try:
                token = user.authenticate_and_create_token(
                    password, totp_token=totp_token
                )
            except UserTOTPRequiredError:
                return respond(
                    202, "Two-factor authentication required", {"method": "totp"}
                )
            except UserTOTPFailedError:
                return fail(401, "Invalid two-factor authentication token")
            except UserNotActiveError as exc:
                return fail(
                    4003,
                    "User account is not active",
                    {"reason": exc.reason},
                )

            if not token:
                return fail(401, "Invalid credentials")

            LoginGuard.report_success(ip, username)

            try:
                check_passwd_requirements(
                    password,
                    cfg["passwd_min_length"],
                    cfg["passwd_max_length"],
                    cfg["passwd_rules"],
                    cfg["passwd_min_passed_count"],
                )
            except ValueError:
                return respond(4001, "Password must be changed before you can log in")

            if cfg["enable_passwd_force_expiration"]:
                expiration_seconds = 3600 * 24 * cfg["passwd_expire_after_days"]
                if time.time() - user.passwd_last_modified > expiration_seconds:
                    return respond(
                        4002, "Password should be changed because it's expired"
                    )

            return respond(
                200, "Login successful", build_login_success_data(session, user, token)
            )


class RequestRefreshTokenHandler(RequestHandler):
    """
    Handles token refresh requests.
    This util processes a token refresh request by validating the existing token and generating a new one if valid.
    It sends an appropriate response back to the client, indicating success or failure.
    Args:
        handler (ConnectionHandler): The connection handler containing request data and methods for responding.
    Response Codes:
        200   - Token refreshed successfully, returns a new token in the response data.
        400 - Missing or invalid token in the request.
        500 - Internal server error, with the exception message.
    """

    schema = {"type": "object", "properties": {}, "additionalProperties": False}
    require_auth = True

    def handle(self, handler: ConnectionHandler):

        # Parse the refresh token request
        old_token = handler.token

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if user and user.is_token_valid(old_token):
                new_token = user.renew_token()
                response = {
                    "code": 200,
                    "message": "Token refreshed successfully",
                    "data": {"token": new_token.raw, "exp": new_token.exp},
                }
                log_audit(
                    "refresh_token",
                    target=handler.username,
                    result=0,
                    remote_address=handler.remote_address,
                )
            else:
                response = {
                    "code": 400,
                    "message": "Invalid or expired token",
                    "data": {},
                }
                log_audit(
                    "refresh_token",
                    target=handler.username,
                    result=1,
                    remote_address=handler.remote_address,
                )

        # Send the response back to the client
        handler.conclude_request(**response)
