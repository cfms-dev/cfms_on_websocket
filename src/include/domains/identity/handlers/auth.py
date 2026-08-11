import time
from typing import Annotated, Any

from pydantic import Field, StringConstraints

from include.config.constants import USERNAME_MAX_LENGTH
from include.config.settings import global_config
from include.database.models.identity import User, UserStatus
from include.database.session import Session
from include.domains.identity.password_auth import verify_password_or_dummy
from include.domains.identity.sessions import build_login_success_data
from include.domains.identity.validators.passwords import check_passwd_requirements
from include.domains.operations.commands.audit import log_audit
from include.domains.security.guards.login import (
    AuthFactor,
    LoginGuard,
    ThrottleDecision,
    ThrottleScope,
)
from include.transport.client_address import get_client_ip
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import (
    REQUEST_UNSET,
    Omittable,
    RequestDataModel,
    RequestHandler,
    Result,
)

_NonEmptyString = Annotated[str, StringConstraints(min_length=1)]
_Username = Annotated[
    str,
    StringConstraints(min_length=1, max_length=USERNAME_MAX_LENGTH),
]
_TwoFactorToken = Annotated[str, StringConstraints(min_length=1, max_length=64)]


class _LoginRequest(RequestDataModel):
    username: _Username
    password: _NonEmptyString
    two_factor_token: Omittable[_TwoFactorToken] = Field(
        default=REQUEST_UNSET,
        alias="2fa_token",
    )


class _EmptyRequest(RequestDataModel):
    pass


class RequestLoginHandler(RequestHandler):
    """Authenticate a local user and issue a session token."""

    request_model = _LoginRequest
    rate_limit_cost = 5

    def handle(self, handler: ConnectionHandler):
        username: str = handler.data["username"]
        password: str = handler.data["password"]
        totp_token: str = handler.data.get("2fa_token", "")
        ip = get_client_ip(handler.stream.connection._ws)

        def respond(code: int, message: str, data: dict[str, Any] | None = None):
            handler.conclude_request(code=code, data=data or {}, message=message)
            return Result(code=code, target=username)

        def throttled(decision: ThrottleDecision):
            if decision.scope == ThrottleScope.BANNED_SUBNET:
                return respond(403, "Access denied")
            data = {}
            if decision.retry_after_seconds is not None:
                data["retry_after_seconds"] = decision.retry_after_seconds
            return respond(
                429, "Too many authentication attempts. Please try again later.", data
            )

        password_access = LoginGuard.evaluate(ip, username, AuthFactor.PASSWORD)
        if not password_access.allowed:
            return throttled(password_access)

        cfg = global_config["security"]
        with Session() as session:
            user = session.get(User, username)
            if not verify_password_or_dummy(user, password):
                LoginGuard.report_failure(ip, username, AuthFactor.PASSWORD)
                return respond(401, "Invalid credentials")

            assert user is not None
            LoginGuard.report_success(ip, username, AuthFactor.PASSWORD)

            if user.totp_enabled:
                if not totp_token:
                    return respond(
                        202,
                        "Two-factor authentication required",
                        {"method": "totp"},
                    )

                # For different authentication factors, we evaluate the access
                # separately to ensure that each factor is throttled independently.
                totp_access = LoginGuard.evaluate(ip, username, AuthFactor.TOTP)

                if not totp_access.allowed:
                    return throttled(totp_access)
                if not user.verify_totp(totp_token):
                    LoginGuard.report_failure(ip, username, AuthFactor.TOTP)
                    return respond(401, "Invalid two-factor authentication token")
                LoginGuard.report_success(
                    ip,
                    username,
                    AuthFactor.TOTP,
                    completed_authentication=True,
                )
            else:
                LoginGuard.report_success(
                    ip,
                    username,
                    AuthFactor.PASSWORD,
                    completed_authentication=True,
                )

            if user.status != UserStatus.ACTIVE:
                return respond(
                    4003,
                    "User account is not active",
                    {"reason": user.status_reason},
                )

            token = user.create_token_after_authentication(password)

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
    request_model = _EmptyRequest
    require_auth = True
    rate_limit_cost = 2

    def handle(self, handler: ConnectionHandler):
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

        handler.conclude_request(**response)
