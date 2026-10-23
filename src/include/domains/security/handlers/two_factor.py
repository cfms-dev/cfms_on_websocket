"""
Two-Factor Authentication (TOTP) handlers for CFMS.

This module provides handlers for setting up, validating, and canceling
two-factor authentication using Time-based One-Time Passwords (TOTP).
"""

import uuid
from operator import xor
from typing import Literal, Self

import orjson
from pydantic import model_validator

from include.database.models.auth import UserPasswordCredential, UserTotpCredential
from include.database.models.identity import User, UserStatus
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.identity.auth.registry import auth_registry
from include.domains.identity.commands.credentials import (
    enable_login_totp,
    remove_totp,
    setup_totp,
)
from include.domains.identity.password_auth import verify_password_or_dummy
from include.domains.security.guards.login import (
    AuthFactor,
    LoginGuard,
    ThrottleDecision,
)
from include.transport.client_address import get_client_ip
from include.transport.request_handler import (
    REQUEST_UNSET,
    EmptyRequestDataModel,
    Omittable,
    RequestDataModel,
    RequestHandler,
    Result,
)
lazy from include.domains.identity.types import RequestUserID
lazy from include.domains.security.types import TwoFactorToken
lazy from include.transport.connection import ConnectionHandler
lazy from include.types import NonEmptyString


class _Setup2FARequest(RequestDataModel):
    method: Omittable[Literal["totp"]] = REQUEST_UNSET


class _Validate2FARequest(RequestDataModel):
    token: TwoFactorToken


class _Disable2FARequest(RequestDataModel):
    user_id: Omittable[RequestUserID] = REQUEST_UNSET
    password: Omittable[NonEmptyString] = REQUEST_UNSET

    @model_validator(mode="after")
    def require_user_id_or_password(self) -> Self:
        if not {"user_id", "password"} & self.model_fields_set:
            raise ValueError("user_id or password is required")
        return self


class _Get2FAStatusRequest(RequestDataModel):
    user_id: Omittable[RequestUserID] = REQUEST_UNSET


def _conclude_throttled(
    handler: ConnectionHandler,
    decision: ThrottleDecision,
    target: str,
    user_id: uuid.UUID | None = None,
) -> Result:
    data = {}
    if decision.retry_after_seconds is not None:
        data["retry_after_seconds"] = decision.retry_after_seconds
    handler.conclude_request(
        429,
        data,
        "Too many authentication attempts. Please try again later.",
    )
    return Result(code=429, target=target, user_id=user_id)


class RequestSetup2FAHandler(RequestHandler):
    """
    Handler for setting up two-factor authentication.

    This handler generates a TOTP secret and backup codes for the user.
    The TOTP secret is returned as a provisioning URI that can be used
    to generate a QR code for scanning with authenticator apps.

    Response Data:
        - secret: The TOTP secret (for manual entry)
        - provisioning_uri: URI for QR code generation
        - backup_codes: List of backup codes for account recovery
    """

    request_model = _Setup2FARequest

    requires_auth = True
    rate_limit_cost = 20

    def handle(self, handler: ConnectionHandler):
        with Session() as session:
            user = User.get_existing(session, handler.user_id)

            # Check if user already has 2FA enabled
            credential = session.get(UserTotpCredential, user.id)
            if credential is not None and credential.enabled:
                handler.conclude_request(
                    code=400,
                    message="Two-factor authentication is already enabled. Please cancel it first.",
                    data={
                        "method": "totp"
                    },  # will be extended if other methods are added
                )
                return

            # Setup TOTP
            credential, backup_codes = setup_totp(session, user)
            session.commit()

            handler.conclude_request(
                code=200,
                message="Two-factor authentication setup initiated. Please verify with your authenticator app.",
                data={
                    "secret": credential.secret,
                    "provisioning_uri": credential.provisioning_uri,
                    "backup_codes": backup_codes,
                },
            )
            return Result(
                code=200,
                target=str(user.id),
                data={"target_username": user.username},
                user_id=handler.user_id,
            )


class RequestValidate2FAHandler(RequestHandler):
    """
    Handler for validating and enabling two-factor authentication.

    After setup, the user must validate their TOTP configuration by
    providing a valid code from their authenticator app. This enables 2FA.
    """

    request_model = _Validate2FARequest

    requires_auth = True
    rate_limit_cost = 2

    def handle(self, handler: ConnectionHandler):
        token = handler.data["token"]
        user_id = handler.user_id

        success = False

        with Session() as session:
            user = session.get(User, user_id)

            if user is None:
                handler.conclude_request(
                    code=404,
                    message="User not found",
                    data={},
                )
                return

            # Check if TOTP secret exists but not enabled yet
            credential = session.get(UserTotpCredential, user.id)
            if credential is None or not credential.secret:
                handler.conclude_request(
                    code=400,
                    message="Two-factor authentication has not been set up. Please set it up first.",
                    data={},
                )
                return

            if credential.enabled:
                handler.conclude_request(
                    code=400,
                    message="Two-factor authentication is already enabled.",
                    data={"method": "totp"},
                )
                return

            username = user.username

            # Verify the provided TOTP token
            if credential.verify(token):
                enable_login_totp(session, user, credential)
                session.commit()
                success = True

        if success:
            handler.conclude_request(
                code=200,
                message="Two-factor authentication enabled successfully",
                data={"method": "totp"},
            )
        else:
            handler.conclude_request(401, {}, "Invalid verification code")

        return Result(
            code=0 if success else 401, target=username, user_id=handler.user_id
        )


class RequestDisable2FAHandler(RequestHandler):
    """
    Handler for canceling two-factor authentication.

    This handler disables and removes TOTP configuration for the user.
    The user must provide their password for verification.
    """

    request_model = _Disable2FARequest

    requires_auth = True
    rate_limit_cost = 5

    def handle(self, handler: ConnectionHandler):
        password = handler.data.get("password")
        with Session() as session:
            requester = User.get_existing(session, handler.user_id)
            requester_username = requester.username
        target_user_id = (
            uuid.UUID(handler.data["user_id"])
            if "user_id" in handler.data
            else handler.user_id
        )
        audit_target = str(target_user_id)
        audit_data = {}
        requester_user_id = handler.user_id

        is_self = target_user_id == requester_user_id
        has_password = bool(password)

        if xor(is_self, has_password):
            error_msg = (
                "Password is required when disabling your own 2FA"
                if is_self
                else "Password should not be provided when disabling 2FA for another user"
            )
            handler.conclude_request(400, {}, error_msg)
            return Result(code=400, target=audit_target, user_id=requester_user_id)

        ip = get_client_ip(handler.stream.connection._ws)
        if password:
            decision = LoginGuard.evaluate(ip, requester_username, AuthFactor.PASSWORD)
            if not decision.allowed:
                return _conclude_throttled(
                    handler, decision, audit_target, requester_user_id
                )

        with Session() as session:
            if not is_self:
                requester = User.get_existing(session, requester_user_id)
                if Permissions.MANAGE_2FA not in requester.all_permissions:
                    handler.conclude_request(403, {}, "Permission denied")
                    return Result(
                        code=403,
                        target=audit_target,
                        user_id=requester_user_id,
                    )

            user = session.get(User, target_user_id)
            if user is not None:
                audit_data["target_username"] = user.username
            credential = session.get(UserTotpCredential, user.id) if user else None
            if credential is None or not credential.enabled:
                handler.conclude_request(400, {}, "2FA not enabled or user not found")
                return Result(
                    code=400,
                    target=audit_target,
                    data=audit_data or None,
                    user_id=requester_user_id,
                )

            if password:
                password_credential = session.get(UserPasswordCredential, user.id)
                if not verify_password_or_dummy(password_credential, password):
                    LoginGuard.report_failure(ip, user.username, AuthFactor.PASSWORD)
                    handler.conclude_request(401, {}, "Invalid password")
                    return Result(
                        code=401,
                        target=audit_target,
                        data=audit_data,
                        user_id=requester_user_id,
                    )

                LoginGuard.report_success(
                    ip,
                    user.username,
                    AuthFactor.PASSWORD,
                    completed_authentication=True,
                )

                if user.status != UserStatus.ACTIVE:
                    handler.conclude_request(4003, {}, "User account is not active")
                    return Result(
                        code=4003,
                        target=audit_target,
                        data=audit_data,
                        user_id=requester_user_id,
                    )

            remove_totp(session, user, credential)
            session.commit()

        handler.conclude_request(200, {}, "2FA disabled successfully")
        return Result(
            code=0, target=audit_target, data=audit_data, user_id=requester_user_id
        )


class RequestCancel2FASetupHandler(RequestHandler):
    """
    Handler for canceling two-factor authentication setup.

    This handler removes the TOTP configuration that was set up
    but not yet validated/enabled.
    """

    request_model = EmptyRequestDataModel

    requires_auth = True
    rate_limit_cost = 1

    def handle(self, handler: ConnectionHandler):
        with Session() as session:
            user = User.get_existing(session, handler.user_id)

            # Check if TOTP setup exists but not enabled yet
            credential = session.get(UserTotpCredential, user.id)
            if credential is None or not credential.secret or credential.enabled:
                handler.conclude_request(
                    code=400,
                    message="No pending two-factor authentication setup to cancel.",
                    data={},
                )
                return

            # Cancel TOTP setup
            remove_totp(session, user, credential)
            session.commit()

            handler.conclude_request(
                code=200,
                message="Two-factor authentication setup canceled successfully",
                data={},
            )


class RequestGet2FAStatusHandler(RequestHandler):
    """
    Handler for getting two-factor authentication status.

    Returns whether 2FA is enabled for the authenticated user.
    """

    request_model = _Get2FAStatusRequest

    requires_auth = True
    rate_limit_cost = 1

    def handle(self, handler: ConnectionHandler):

        with Session() as session:
            user = User.get_existing(session, handler.user_id)
            target_user_id = (
                uuid.UUID(handler.data["user_id"])
                if "user_id" in handler.data
                else user.id
            )

            if (
                target_user_id != user.id
                and Permissions.MANAGE_2FA not in user.all_permissions
            ):
                handler.conclude_request(
                    code=403,
                    message="Forbidden: Cannot access another user's two-factor authentication status",
                    data={},
                )
                return Result(
                    code=403, target=str(target_user_id), user_id=handler.user_id
                )

            target = session.get(User, target_user_id)
            if not target:
                handler.conclude_request(
                    code=404,
                    message="Target user not found",
                    data={},
                )
                return Result(
                    code=404, target=str(target_user_id), user_id=handler.user_id
                )

            credential = session.get(UserTotpCredential, target.id)
            enabled = auth_registry.user_requires_mfa(session, target)
            methods = auth_registry.get_user_mfa_methods(session, target)
            handler.conclude_request(
                code=200,
                message="Two-factor authentication status",
                data={
                    "enabled": enabled,
                    "method": methods[0] if len(methods) == 1 else None,
                    "methods": methods,
                    "backup_codes_count": (
                        len(orjson.loads(credential.backup_codes))
                        if credential is not None and credential.backup_codes
                        else 0
                    ),
                },
            )
            return Result(
                code=200,
                target=str(target_user_id),
                data={"target_username": target.username},
                user_id=handler.user_id,
            )
