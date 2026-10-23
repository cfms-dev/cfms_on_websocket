from typing import Any

from pydantic import Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from include.database.models.auth import UserPasswordCredential
from include.database.models.identity import User
from include.database.session import Session as DatabaseSession
from include.domains.identity.auth.base import (
    AuthFactorCategory,
    AuthVerificationResult,
    BaseAuthMethodProvider,
)
from include.domains.identity.auth.flows import (
    AuthenticationAttempt,
    AuthenticationFailure,
)
from include.domains.identity.auth.password_state import assess_password
from include.domains.identity.auth.types import (
    AuthPurpose,
    InvalidAuthenticationAttempt,
    RegisteredCredential,
)
from include.domains.identity.password_auth import verify_password_or_dummy
from include.domains.identity.types import RequestUsername
from include.domains.security.guards.login import LoginGuard
from include.transport.request_handler import RequestDataModel
lazy from include.transport.connection import ConnectionHandler
lazy from include.types import NonEmptyString


class PasswordCredentialSchema(RequestDataModel):
    username: RequestUsername
    password: NonEmptyString = Field(repr=False)


class PasswordVerificationRequest(RequestDataModel):
    password: NonEmptyString = Field(repr=False)


class PasswordAuthProvider(BaseAuthMethodProvider):
    method_id = "password"
    category = AuthFactorCategory.PRIMARY
    throttle_factor = "password"
    credential_schema = PasswordCredentialSchema
    supported_purposes = frozenset(AuthPurpose)

    def authenticate(
        self,
        handler: ConnectionHandler,
        attempt: AuthenticationAttempt,
        payload: dict[str, Any],
    ) -> None:
        if attempt.purpose == AuthPurpose.LOGIN:
            credential = PasswordCredentialSchema.model_validate(payload)
            attempt.username = credential.username
        else:
            credential = PasswordVerificationRequest.model_validate(payload)
        attempt.check_throttle(self)
        with DatabaseSession() as session:
            user = (
                session.scalar(select(User).where(User.username == attempt.username))
                if attempt.purpose == AuthPurpose.LOGIN
                else session.get(User, attempt.user_id)
            )
            if user is None:
                verify_password_or_dummy(None, credential.password)
                if attempt.purpose != AuthPurpose.LOGIN:
                    raise InvalidAuthenticationAttempt(
                        "Account changed; restart authentication"
                    )
                assert attempt.username is not None
                LoginGuard.report_failure(
                    attempt.ip, attempt.username, self.throttle_factor
                )
                raise AuthenticationFailure(401, "Invalid credentials")
            attempt.bind(session, user)
            if attempt.purpose != AuthPurpose.LOGIN:
                attempt.check_throttle(self)
            attempt.permitted_credentials(session, user)
            verified = self.verify(session, user, {"password": credential.password}, {})
            progress = attempt.accept(session, user, self, verified)
            if not progress.satisfied and (
                progress.purpose is None or progress.purpose == attempt.purpose
            ):
                raise AuthenticationFailure(
                    403, "Password authentication cannot satisfy this policy"
                )

    def list_credentials(
        self, session: Session, user: User
    ) -> list[RegisteredCredential]:
        credential = session.get(UserPasswordCredential, user.id)
        return (
            []
            if credential is None
            else [
                RegisteredCredential(
                    method=self.method_id,
                    credential_id=credential.credential_id,
                    active=True,
                )
            ]
        )

    def verify(
        self,
        session: Session,
        user: User,
        payload: dict[str, Any],
        context: dict[str, Any],
    ) -> AuthVerificationResult:
        password: str = payload.get("password", "")
        credential = session.get(UserPasswordCredential, user.id)
        if not verify_password_or_dummy(credential, password):
            return AuthVerificationResult(
                success=False, error_code=401, error_message="Invalid credentials"
            )

        assert credential is not None

        assessment = assess_password(credential, password)
        credential.rehash_if_needed(password)

        return AuthVerificationResult(
            success=True,
            credential_id=credential.credential_id,
            password_assessment=assessment,
        )
