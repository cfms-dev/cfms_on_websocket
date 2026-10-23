from typing import Any, Literal

from pydantic import Field, ValidationError
from sqlalchemy import update
from websockets.exceptions import ConnectionClosed

from include.config.constants import ESCALATION_TOKEN_EXPIRY_SECONDS
from include.config.settings import global_config
from include.database.models.auth import UserAuthPolicy
from include.database.models.identity import User, UserStatus
from include.database.session import Session
from include.domains.identity.auth.flows import (
    AuthenticationAttempt,
    AuthenticationFailure,
)
from include.domains.identity.auth.registry import auth_registry
from include.domains.identity.auth.types import (
    AuthPurpose,
    InvalidAuthenticationAttempt,
)
from include.domains.identity.sessions import finish_login_attempt
from include.domains.identity.tokens import Token, TokenPurpose
from include.domains.security.guards.login import LoginGuard
from include.transport.client_address import get_client_ip
from include.transport.request_handler import (
    REQUEST_UNSET,
    EmptyRequestDataModel,
    Omittable,
    RequestDataModel,
    RequestHandler,
    Result,
)
lazy from include.transport.connection import ConnectionHandler
lazy from include.types import NonEmptyString


class _LoginRequest(RequestDataModel):
    method: NonEmptyString
    credential: dict[str, Any] = Field(repr=False)


class _CompleteMFARequest(RequestDataModel):
    method: Omittable[NonEmptyString] = REQUEST_UNSET
    data: Omittable[dict[str, Any]] = Field(default=REQUEST_UNSET, repr=False)
    target_purpose: Literal[
        2, 6
    ]  # TokenPurpose.GENERAL or TokenPurpose.GENERAL | TokenPurpose.ESCALATION


def authenticate_request(
    handler: ConnectionHandler, attempt: AuthenticationAttempt, payload: dict[str, Any]
) -> Result:
    try:
        provider = auth_registry.get(attempt.method)
        if provider is None:
            raise AuthenticationFailure(400, "Unknown authentication method")
        if attempt.purpose not in provider.supported_purposes:
            raise AuthenticationFailure(
                403, "Authentication method does not support this purpose"
            )
        provider.authenticate(handler, attempt, payload)
        attempt.check_expiry()
        with Session() as session:
            user = session.get(User, attempt.user_id)
            if user is None:
                raise InvalidAuthenticationAttempt(
                    "Account changed; restart authentication"
                )
            if user.status != UserStatus.ACTIVE:
                raise AuthenticationFailure(
                    4003, "User account is not active", {"reason": user.status_reason}
                )
            progress = attempt.progress(session, user)
            username = user.username
            if attempt.purpose == AuthPurpose.ESCALATION:
                if not progress.satisfied:
                    raise AuthenticationFailure(
                        403, "Escalation policy is not complete"
                    )
                token = Token.new(
                    user.id,
                    ESCALATION_TOKEN_EXPIRY_SECONDS,
                    user.secret_key or global_config["server"]["secret_key"],
                    TokenPurpose.GENERAL | TokenPurpose.ESCALATION,
                )
                code, message, data = (
                    200,
                    "Escalation successful",
                    {
                        "token": token.raw,
                        "exp": token.exp,
                        "purpose": int(token.purpose),
                    },
                )
            else:
                if attempt.purpose == AuthPurpose.MFA and not progress.satisfied:
                    raise AuthenticationFailure(403, "MFA policy is not complete")
                assert attempt.context is not None
                code, message, data = finish_login_attempt(
                    session,
                    user,
                    attempt.context,
                    expires_at=attempt.expires_at,
                    password_assessment=attempt.password_assessment,
                )
        if code in (200, 4001, 4002):
            LoginGuard.report_success(
                attempt.ip,
                username,
                provider.throttle_factor,
                completed_authentication=True,
            )
    except AuthenticationFailure as exc:
        code, message, data = exc.code, exc.message, exc.data
    except InvalidAuthenticationAttempt as exc:
        code, message, data = 401, str(exc), {}
    except ValidationError:
        code, message, data = 400, "Invalid authentication message", {}
    except TimeoutError:
        code, message, data = 408, "Authentication request timed out", {}
    except ConnectionClosed, ConnectionError:
        return Result(
            code=499,
            target=attempt.username,
            user_id=attempt.user_id
            if attempt.context and attempt.context.evidence
            else handler.user_id,
        )
    handler.conclude_request(code=code, message=message, data=data)
    return Result(
        code=code,
        target=attempt.username,
        user_id=attempt.user_id
        if attempt.context and attempt.context.evidence
        else handler.user_id,
    )


class RequestLoginHandler(RequestHandler[_LoginRequest]):
    request_model = _LoginRequest
    rate_limit_cost = 5

    def handle(self, handler: ConnectionHandler) -> Result:
        attempt = AuthenticationAttempt(
            handler.data["method"],
            AuthPurpose.LOGIN,
            get_client_ip(handler.stream.connection._ws),
            self.rate_limit_cost,
        )
        return authenticate_request(handler, attempt, handler.data["credential"])


class RequestCompleteMFAHandler(RequestHandler[_CompleteMFARequest]):
    request_model = _CompleteMFARequest
    rate_limit_cost = 2
    requires_auth = True
    required_token_purpose = TokenPurpose.AUTH | TokenPurpose.GENERAL

    def handle(self, handler: ConnectionHandler) -> Result:
        try:
            request = self.request_model.model_validate(handler.data)
        except ValidationError:
            handler.conclude_request(400, {}, "Invalid token exchange request")
            return Result(code=400, user_id=handler.user_id)
        source = handler.token
        if (
            source is not None
            and source.purpose == TokenPurpose.AUTH
            and request.target_purpose == TokenPurpose.GENERAL
        ):
            purpose = AuthPurpose.MFA
            if source.auth_context is None or not source.auth_context.login_method:
                handler.conclude_request(
                    401, {}, "Authentication context missing; restart login"
                )
                return Result(code=401, user_id=handler.user_id)
        elif (
            source is not None
            and source.purpose == TokenPurpose.GENERAL
            and request.target_purpose == TokenPurpose.GENERAL | TokenPurpose.ESCALATION
        ):
            purpose = AuthPurpose.ESCALATION
        else:
            handler.conclude_request(403, {}, "Token exchange is not permitted")
            return Result(code=403, user_id=handler.user_id)
        if purpose == AuthPurpose.ESCALATION:
            try:
                issued: tuple[str, Token] | None = None
                with Session.begin() as session:
                    session.execute(
                        update(User)
                        .where(User.id == source.sub)
                        .values(id=User.id)
                        .execution_options(synchronize_session=False)
                    )
                    user = session.get(User, source.sub)
                    if user is None:
                        raise AuthenticationFailure(401, "Invalid authentication token")
                    if user.status != UserStatus.ACTIVE:
                        raise AuthenticationFailure(4003, "User account is not active")
                    if not user.is_token_valid(source):
                        raise AuthenticationFailure(401, "Invalid authentication token")
                    policy = session.get(
                        UserAuthPolicy, (user.id, AuthPurpose.ESCALATION.value)
                    )
                    if policy is None or not policy.chains:
                        issued = (
                            user.username,
                            Token.new(
                                user.id,
                                ESCALATION_TOKEN_EXPIRY_SECONDS,
                                user.secret_key
                                or global_config["server"]["secret_key"],
                                TokenPurpose.GENERAL | TokenPurpose.ESCALATION,
                            ),
                        )
                if issued is not None:
                    username, token = issued
                    handler.conclude_request(
                        200,
                        {
                            "token": token.raw,
                            "exp": token.exp,
                            "purpose": int(token.purpose),
                        },
                        "Escalation successful",
                    )
                    return Result(code=200, target=username, user_id=source.sub)
            except AuthenticationFailure as exc:
                handler.conclude_request(exc.code, exc.data, exc.message)
                return Result(code=exc.code, user_id=handler.user_id)
        if request.method is REQUEST_UNSET or request.data is REQUEST_UNSET:
            handler.conclude_request(
                400, {}, "Authentication method and data are required"
            )
            return Result(code=400, user_id=handler.user_id)
        attempt = AuthenticationAttempt(
            request.method,
            purpose,
            get_client_ip(handler.stream.connection._ws),
            self.rate_limit_cost,
            user_id=source.sub,
            context=source.auth_context if purpose == AuthPurpose.MFA else None,
            expires_at=source.exp,
        )
        return authenticate_request(handler, attempt, request.data)


class RequestRefreshTokenHandler(RequestHandler[EmptyRequestDataModel]):
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
                "data": {
                    "token": new_token.raw,
                    "exp": new_token.exp,
                    "purpose": int(new_token.purpose),
                },
            }
        handler.conclude_request(**response)
        return Result(code=0, target=username, user_id=handler.user_id)
