import time
import uuid
from typing import Any, Literal, Self, TypedDict

from pydantic import model_validator, with_config
from sqlalchemy import select

from include.config.settings import global_config
from include.database.models.auth import UserPasswordCredential, UserTotpCredential
from include.database.models.identity import User, UserStatus
from include.database.session import Session
from include.domains.identity.auth.flows import (
    InvalidAuthenticationAttempt,
    get_login_progress,
    start_login_attempt,
)
from include.domains.identity.auth.types import AuthEvidence
from include.domains.identity.password_auth import verify_password_or_dummy
from include.domains.identity.sessions import finish_login_attempt
from include.domains.identity.tokens import TokenPurpose
from include.domains.identity.types import RequestUsername
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
    username: RequestUsername
    password: NonEmptyString


@with_config(extra="forbid")
class PublicKeyCredential(TypedDict):
    username: RequestUsername
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

        ip = get_client_ip(handler.stream.connection._ws)
        authenticated_user_id: uuid.UUID | None = None

        def respond(code: int, message: str, data: dict[str, Any] | None = None):
            handler.conclude_request(code=code, data=data or {}, message=message)
            return Result(code=code, target=username, user_id=authenticated_user_id)

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
            user = session.scalar(select(User).where(User.username == username))
            password_credential = (
                session.get(UserPasswordCredential, user.id)
                if user is not None
                else None
            )
            if not verify_password_or_dummy(password_credential, password):
                LoginGuard.report_failure(ip, username, AuthFactor.PASSWORD)
                return respond(401, "Invalid credentials")

            assert user is not None
            assert password_credential is not None
            context = start_login_attempt(
                session, user, "password", password_credential.credential_id
            )
            if context is None:
                LoginGuard.report_failure(ip, username, AuthFactor.PASSWORD)
                return respond(401, "Invalid credentials")
            authenticated_user_id = user.id
            LoginGuard.report_success(ip, username, AuthFactor.PASSWORD)

            if user.status != UserStatus.ACTIVE:
                return respond(
                    4003,
                    "User account is not active",
                    {"reason": user.status_reason},
                )

            # FIXME: Password requirement checks must be done after MFA verification
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
                if (
                    time.time() - password_credential.passwd_last_modified
                    > expiration_seconds
                ):
                    return respond(
                        4002, "Password should be changed because it's expired"
                    )

            password_credential.rehash_if_needed(password)
            code, message, data = finish_login_attempt(session, user, context)
            if code == 200:
                LoginGuard.report_success(
                    ip,
                    username,
                    AuthFactor.PASSWORD,
                    completed_authentication=True,
                )
            return respond(code, message, data)

    def _handle_publickey_login(self, handler: ConnectionHandler):
        credential: PublicKeyCredential = handler.data["credential"]

        username: str = credential["username"]
        handler.conclude_request(403, {}, "Public key login is not yet supported")
        return Result(code=403, target=username)


class RequestCompleteMFAHandler(RequestHandler):
    rate_limit_cost = 2
    request_model = _CompleteMFARequest
    requires_auth = True
    required_token_purpose = TokenPurpose.AUTH

    def handle(self, handler: ConnectionHandler):

        # TODO: Abstract the response logic to a common function to avoid duplication.
        def respond(code: int, message: str, data: dict[str, Any] | None = None):
            handler.conclude_request(code=code, data=data or {}, message=message)
            return Result(code=code, target=username, user_id=handler.user_id)

        def throttled(decision: ThrottleDecision):
            if decision.scope == ThrottleScope.BANNED_SUBNET:
                return respond(403, "Access denied")
            data = {}
            if decision.retry_after_seconds is not None:
                data["retry_after_seconds"] = decision.retry_after_seconds
            return respond(
                429, "Too many authentication attempts. Please try again later.", data
            )

        assert handler.user_id
        assert handler.token

        with Session() as session:
            user = User.get_existing(session, handler.user_id)
            username = user.username
            if user.status != UserStatus.ACTIVE:
                return respond(
                    4003, "User account is not active", {"reason": user.status_reason}
                )
            totp_token: str = handler.data["data"]["token"]

            ip = get_client_ip(handler.stream.connection._ws)

            # For different authentication factors, we evaluate the access
            # separately to ensure that each factor is throttled independently.
            totp_access = LoginGuard.evaluate(ip, username, AuthFactor.TOTP)

            if not totp_access.allowed:
                return throttled(totp_access)
            context = handler.token.auth_context
            if context is None:
                return respond(401, "Authentication context missing; restart login")
            try:
                progress = get_login_progress(session, user, context)
            except InvalidAuthenticationAttempt as exc:
                return respond(401, str(exc))
            totp_credential = session.get(UserTotpCredential, user.id)
            if (
                totp_credential is None
                or not totp_credential.enabled
                or not any(
                    step.method == "totp"
                    and totp_credential.credential_id in step.credential_ids
                    for step in progress.next_steps
                )
            ):
                return respond(
                    403, "Authentication policy cannot be completed by this endpoint"
                )
            if not totp_credential.verify(totp_token):
                LoginGuard.report_failure(ip, username, AuthFactor.TOTP)
                return respond(401, "Invalid two-factor authentication token")
            context = context.model_copy(
                update={
                    "evidence": [
                        *context.evidence,
                        AuthEvidence(
                            user_id=user.id,
                            attempt_id=context.attempt_id,
                            method="totp",
                            credential_id=totp_credential.credential_id,
                        ),
                    ]
                }
            )
            code, message, data = finish_login_attempt(
                session,
                user,
                context,
                expires_at=handler.token.exp,
            )
            if code == 200:
                LoginGuard.report_success(
                    ip,
                    username,
                    AuthFactor.TOTP,
                    completed_authentication=True,
                )
            return respond(code, message, data)


class RequestRefreshTokenHandler(RequestHandler):
    request_model = EmptyRequestDataModel
    requires_auth = True
    rate_limit_cost = 2

    def handle(self, handler: ConnectionHandler):
        with Session() as session:
            user = User.get_existing(session, handler.user_id)

            username = user.username
            new_token = user.renew_token(handler.token)
            response = {
                "code": 200,
                "message": "Token refreshed successfully",
                "data": {"token": new_token.raw, "exp": new_token.exp},
            }

        handler.conclude_request(**response)
        return Result(code=0, target=username, user_id=handler.user_id)
