import time
from typing import Any, Literal, Self, TypedDict

from pydantic import model_validator, with_config

from include.config.constants import DEFAULT_TOKEN_EXPIRY_SECONDS
from include.config.settings import global_config
from include.database.models.identity import User, UserStatus
from include.database.session import Session
from include.domains.identity.password_auth import verify_password_or_dummy
from include.domains.identity.sessions import build_login_success_data
from include.domains.identity.tokens import Token, TokenPurpose
from include.domains.identity.validators.passwords import check_passwd_requirements
from include.domains.security.guards.login import (
    AuthFactor,
    LoginGuard,
    ThrottleDecision,
    ThrottleScope,
)
from include.transport.client_address import get_client_ip
from include.transport.request_handler import (
    EmptyRequestDataModel,
    RequestDataModel,
    RequestHandler,
    Result,
)
lazy from include.transport.connection import ConnectionHandler
lazy from include.types import NonEmptyString


@with_config(extra="forbid")
class PasswordCredential(TypedDict):
    username: NonEmptyString
    password: NonEmptyString


@with_config(extra="forbid")
class PublicKeyCredential(TypedDict):
    username: NonEmptyString
    publickey: NonEmptyString


class _LoginRequest(RequestDataModel):
    method: Literal["password", "publickey"]
    credential: PasswordCredential | PublicKeyCredential

    @model_validator(mode="after")
    def validate_credential(self) -> Self:
        match self.method:
            case "password":
                if "password" not in self.credential:
                    raise ValueError("Expected password credentials")
            case "publickey":
                if "publickey" not in self.credential:
                    raise ValueError("Expected public key credentials")
            case _:
                # This should never happen due to the type hinting.
                raise ValueError(f"Unknown authentication method: {self.method}")

        return self


class TOTPMethodData(TypedDict):
    token: NonEmptyString


class _CompleteMFARequest(RequestDataModel):
    method: Literal["totp"]
    data: TOTPMethodData  # TODO: Add other 2FA methods in the future


class RequestLoginHandler(RequestHandler):
    """Authenticate a local user and issue a session token."""

    request_model = _LoginRequest
    rate_limit_cost = 5

    def handle(self, handler: ConnectionHandler):
        match handler.data["method"]:
            case "password":
                return self._handle_password_login(handler)
            case "publickey":
                return self._handle_publickey_login(handler)

    def _handle_password_login(self, handler: ConnectionHandler):
        credential: PasswordCredential = handler.data["credential"]

        username: str = credential["username"]
        password: str = credential["password"]

        # totp_token: str = handler.data.get("2fa_token", "")
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
                # FIXME: Abstract token generation logic
                secret: str = user.secret_key or global_config["server"]["secret_key"]
                token = Token.new(
                    user.username,
                    DEFAULT_TOKEN_EXPIRY_SECONDS
                    / 2,  # FIXME: Specify expiration time for AUTH purposes
                    secret,
                    purpose=TokenPurpose.AUTH,
                )

                return respond(
                    202,
                    "Two-factor authentication required",
                    {
                        "methods": [
                            "totp",
                            # TODO: Add other 2FA methods in the future
                        ]
                    },
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

    def _handle_publickey_login(self, handler: ConnectionHandler):
        credential: PublicKeyCredential = handler.data["credential"]

        username: str = credential["username"]
        publickey: str = credential["publickey"]

        with Session() as session:
            user = session.get(User, username)
            if not user:
                handler.conclude_request(401, message="Invalid credentials")
                return Result(code=401, target=username)

            raise NotImplementedError(
                "Public key authentication is not yet implemented"
            )

            if publickey:
                pass  # TODO


class RequestCompleteMFAHandler(RequestHandler):
    request_model = _CompleteMFARequest
    requires_auth = True
    required_token_purpose = TokenPurpose.AUTH

    def handle(self, handler: ConnectionHandler):

        # TODO: Abstract the response logic to a common function to avoid duplication.
        def respond(code: int, message: str, data: dict[str, Any] | None = None):
            handler.conclude_request(code=code, data=data or {}, message=message)
            return Result(code=code, target=handler.username)

        def throttled(decision: ThrottleDecision):
            if decision.scope == ThrottleScope.BANNED_SUBNET:
                return respond(403, "Access denied")
            data = {}
            if decision.retry_after_seconds is not None:
                data["retry_after_seconds"] = decision.retry_after_seconds
            return respond(
                429, "Too many authentication attempts. Please try again later.", data
            )

        assert handler.username
        assert handler.token

        with Session() as session:
            user = User.get_existing(session, handler.username)
            totp_token: str = handler.data["data"]["token"]

            ip = get_client_ip(handler.stream.connection._ws)

            # For different authentication factors, we evaluate the access
            # separately to ensure that each factor is throttled independently.
            totp_access = LoginGuard.evaluate(ip, handler.username, AuthFactor.TOTP)

            if not totp_access.allowed:
                return throttled(totp_access)
            if not user.verify_totp(totp_token):
                LoginGuard.report_failure(ip, handler.username, AuthFactor.TOTP)
                return respond(401, "Invalid two-factor authentication token")
            LoginGuard.report_success(
                ip,
                handler.username,
                AuthFactor.TOTP,
                completed_authentication=True,
            )

            return Result(code=0, target=handler.username)


class RequestRefreshTokenHandler(RequestHandler):
    request_model = EmptyRequestDataModel
    requires_auth = True
    rate_limit_cost = 2

    def handle(self, handler: ConnectionHandler):
        with Session() as session:
            user = User.get_existing(session, handler.username)

            new_token = user.renew_token(handler.token)
            response = {
                "code": 200,
                "message": "Token refreshed successfully",
                "data": {"token": new_token.raw, "exp": new_token.exp},
            }

        handler.conclude_request(**response)
        return Result(code=0, target=handler.username)
