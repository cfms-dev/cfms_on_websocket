import hashlib
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

from pydantic import Field
from sqlalchemy.orm import Session

from include.database.models.auth import UserAuthPolicy
from include.database.models.identity import User, UserStatus
from include.domains.identity.auth.types import (
    AuthenticationContext,
    AuthEvidence,
    AuthPolicyDecision,
    AuthPurpose,
    InvalidAuthenticationAttempt,
    PasswordAssessment,
)
from include.domains.security.guards.login import LoginGuard, ThrottleScope
from include.domains.security.guards.request_rate_control import check_request_rate
from include.transport.multiplexing import FrameType
from include.transport.request_handler import RequestDataModel
lazy from include.domains.identity.auth.base import (
    AuthVerificationResult,
    BaseAuthMethodProvider,
)
lazy from include.domains.identity.auth.registry import auth_registry
lazy from include.transport.connection import ConnectionHandler
lazy from include.types import NonEmptyString


class AuthenticationFailure(Exception):
    def __init__(self, code: int, message: str, data: dict | None = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data or {}


class AuthenticationResponse(RequestDataModel):
    action: Literal["auth_response"]
    interaction_id: NonEmptyString
    method: NonEmptyString
    data: dict[str, Any] = Field(repr=False)


def create_authentication_context(
    session: Session, user: User, purpose: AuthPurpose, method: str
) -> AuthenticationContext:
    purposes = (
        (AuthPurpose.ESCALATION,)
        if purpose == AuthPurpose.ESCALATION
        else (AuthPurpose.LOGIN, AuthPurpose.MFA)
    )
    revisions = {}
    for policy_purpose in purposes:
        policy = session.get(UserAuthPolicy, (user.id, policy_purpose.value))
        revisions[policy_purpose] = policy.revision if policy else 0
    return AuthenticationContext(
        login_method=method if purpose == AuthPurpose.LOGIN else None,
        login_revision=revisions.get(AuthPurpose.LOGIN, 0),
        mfa_revision=revisions.get(AuthPurpose.MFA, 0),
        escalation_revision=revisions.get(AuthPurpose.ESCALATION, 0),
        signing_key_digest=hashlib.sha256(user.secret_key.encode()).hexdigest(),
    )


def validate_authentication_context(
    session: Session,
    user: User,
    context: AuthenticationContext,
    purposes: tuple[AuthPurpose, ...],
) -> None:
    if (
        context.signing_key_digest
        != hashlib.sha256(user.secret_key.encode()).hexdigest()
    ):
        raise InvalidAuthenticationAttempt(
            "Authentication credentials changed; restart authentication"
        )
    for purpose in purposes:
        policy = session.get(UserAuthPolicy, (user.id, purpose.value))
        revision = getattr(context, f"{purpose.value}_revision")
        if (policy.revision if policy else 0) != revision:
            raise InvalidAuthenticationAttempt(
                "Authentication policy changed; restart authentication"
            )
    active = {
        (credential.method, credential.credential_id)
        for method in {e.method for e in context.evidence}
        if (provider := auth_registry.get(method)) is not None
        for credential in provider.list_credentials(session, user)
        if credential.active
    }
    if len({e.event_id for e in context.evidence}) != len(context.evidence) or any(
        e.user_id != user.id
        or e.attempt_id != context.attempt_id
        or (e.method, e.credential_id) not in active
        for e in context.evidence
    ):
        raise InvalidAuthenticationAttempt(
            "Authentication credentials changed; restart authentication"
        )


def get_login_progress(
    session: Session, user: User, context: AuthenticationContext
) -> AuthPolicyDecision:
    validate_authentication_context(
        session, user, context, (AuthPurpose.LOGIN, AuthPurpose.MFA)
    )
    if context.login_method is None:
        raise InvalidAuthenticationAttempt("Login method missing; restart login")
    login_evidence = [e for e in context.evidence if e.method == context.login_method]
    login = auth_registry.evaluate_user_policy(
        session,
        user,
        AuthPurpose.LOGIN,
        login_evidence,
        attempt_id=context.attempt_id,
        method=context.login_method,
    )
    if not login.satisfied:
        return login.model_copy(update={"purpose": AuthPurpose.LOGIN})
    mfa_evidence = [e for e in context.evidence if e.method != context.login_method]
    if len({e.method for e in mfa_evidence}) > 1:
        raise InvalidAuthenticationAttempt("MFA must use one method")
    mfa = auth_registry.evaluate_user_policy(
        session,
        user,
        AuthPurpose.MFA,
        mfa_evidence,
        attempt_id=context.attempt_id,
        method=mfa_evidence[0].method if mfa_evidence else None,
        excluded_method=context.login_method,
    )
    return mfa.model_copy(update={"purpose": AuthPurpose.MFA})


@dataclass(slots=True)
class AuthenticationAttempt:
    method: str
    purpose: AuthPurpose
    ip: str
    rate_limit_cost: int
    user_id: uuid.UUID | None = None
    username: str | None = None
    context: AuthenticationContext | None = field(default=None, repr=False)
    expires_at: float | None = None
    password_assessment: PasswordAssessment | None = field(default=None, repr=False)

    def check_expiry(self) -> None:
        if self.expires_at is not None and time.time() >= self.expires_at:
            raise InvalidAuthenticationAttempt(
                "Authentication expired; restart authentication"
            )

    def check_throttle(self, provider: BaseAuthMethodProvider) -> None:
        decision = LoginGuard.evaluate(self.ip, self.username, provider.throttle_factor)
        if not decision.allowed:
            if decision.scope == ThrottleScope.BANNED_SUBNET:
                raise AuthenticationFailure(403, "Access denied")
            data = {}
            if decision.retry_after_seconds is not None:
                data["retry_after_seconds"] = decision.retry_after_seconds
            raise AuthenticationFailure(429, "Too many authentication attempts", data)

    def bind(self, session: Session, user: User) -> None:
        self.user_id, self.username = user.id, user.username
        self.check_expiry()
        if self.context is None:
            if self.purpose == AuthPurpose.MFA:
                raise InvalidAuthenticationAttempt(
                    "Authentication context missing; restart login"
                )
            self.context = create_authentication_context(
                session, user, self.purpose, self.method
            )

    def progress(self, session: Session, user: User) -> AuthPolicyDecision:
        self.check_expiry()
        assert self.context is not None
        if self.purpose == AuthPurpose.ESCALATION:
            validate_authentication_context(
                session, user, self.context, (AuthPurpose.ESCALATION,)
            )
            return auth_registry.evaluate_user_policy(
                session,
                user,
                self.purpose,
                self.context.evidence,
                attempt_id=self.context.attempt_id,
                method=self.method,
            )
        progress = get_login_progress(session, user, self.context)
        if self.purpose == AuthPurpose.MFA and self.method == self.context.login_method:
            raise AuthenticationFailure(
                403, "MFA must use a different authentication method"
            )
        return progress

    def permitted_credentials(self, session: Session, user: User) -> set[str]:
        progress = self.progress(session, user)
        assert self.context is not None
        if progress.satisfied or (
            progress.purpose is not None and progress.purpose != self.purpose
        ):
            raise AuthenticationFailure(403, "Authentication stage is not pending")
        return {
            cid
            for step in progress.next_steps
            if step.method == self.method
            for cid in step.credential_ids
        }

    def accept(
        self,
        session: Session,
        user: User,
        provider: BaseAuthMethodProvider,
        verified: AuthVerificationResult,
    ) -> AuthPolicyDecision:
        username = user.username
        if (
            not verified.success
            or verified.credential_id not in self.permitted_credentials(session, user)
        ):
            LoginGuard.report_failure(self.ip, username, provider.throttle_factor)
            raise AuthenticationFailure(401, "Invalid credentials")
        if user.status != UserStatus.ACTIVE:
            raise AuthenticationFailure(
                4003, "User account is not active", {"reason": user.status_reason}
            )
        assert self.context is not None
        self.context = self.context.model_copy(
            update={
                "evidence": [
                    *self.context.evidence,
                    AuthEvidence(
                        user_id=user.id,
                        attempt_id=self.context.attempt_id,
                        method=self.method,
                        credential_id=verified.credential_id,
                    ),
                ]
            }
        )
        if verified.password_assessment is not None:
            self.password_assessment = verified.password_assessment
        progress = self.progress(session, user)
        session.commit()
        LoginGuard.report_success(self.ip, username, provider.throttle_factor)
        return progress

    def receive(
        self,
        handler: ConnectionHandler,
        interaction_id: str,
        provider: BaseAuthMethodProvider,
    ) -> dict[str, Any]:
        frame = handler.stream.recv()
        self.check_expiry()
        if frame.frame_type != FrameType.PROCESS:
            raise AuthenticationFailure(400, "Expected an authentication PROCESS frame")
        response = AuthenticationResponse.model_validate_json(bytes(frame.data))
        if response.interaction_id != interaction_id or response.method != self.method:
            raise AuthenticationFailure(
                400, "Invalid authentication interaction or method"
            )
        rate = check_request_rate(
            "login" if self.purpose == AuthPurpose.LOGIN else "exchange_token",
            self.rate_limit_cost,
            self.ip,
            user_id=None,
            bypass=False,
        )
        if not rate.allowed:
            raise AuthenticationFailure(
                429,
                "Too many requests",
                {"retry_after_seconds": rate.retry_after_seconds},
            )
        self.check_throttle(provider)
        return response.data
