from typing import Any, cast

from pydantic import Field
from sqlalchemy import CursorResult, update
from sqlalchemy.orm import Session

from include.database.models.auth import UserTotpCredential
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
from include.domains.identity.auth.types import AuthPurpose, RegisteredCredential
from include.transport.request_handler import RequestDataModel
lazy from include.transport.connection import ConnectionHandler
lazy from include.types import NonEmptyString


class TOTPCredentialSchema(RequestDataModel):
    token: NonEmptyString = Field(repr=False)


class TOTPAuthProvider(BaseAuthMethodProvider):
    method_id = "totp"
    category = AuthFactorCategory.SECONDARY
    throttle_factor = "totp"
    credential_schema = TOTPCredentialSchema
    supported_purposes = frozenset({AuthPurpose.MFA, AuthPurpose.ESCALATION})

    def authenticate(
        self,
        handler: ConnectionHandler,
        attempt: AuthenticationAttempt,
        payload: dict[str, Any],
    ) -> None:
        credential = TOTPCredentialSchema.model_validate(payload)
        with DatabaseSession() as session:
            user = session.get(User, attempt.user_id)
            if user is None:
                raise AuthenticationFailure(401, "Invalid credentials")
            attempt.bind(session, user)
            attempt.check_throttle(self)
            verified = (
                self.verify(session, user, {"token": credential.token}, {})
                if attempt.permitted_credentials(session, user)
                else AuthVerificationResult(success=False)
            )
            progress = attempt.accept(session, user, self, verified)
            if not progress.satisfied and (
                progress.purpose is None or progress.purpose == attempt.purpose
            ):
                raise AuthenticationFailure(
                    403, "TOTP authentication cannot satisfy this policy"
                )

    def list_credentials(
        self, session: Session, user: User
    ) -> list[RegisteredCredential]:
        credential = session.get(UserTotpCredential, user.id)
        return (
            []
            if credential is None
            else [
                RegisteredCredential(
                    method=self.method_id,
                    credential_id=credential.credential_id,
                    active=credential.enabled,
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
        credential = session.get(UserTotpCredential, user.id)
        if credential is None or not credential.enabled:
            return AuthVerificationResult(
                success=False,
                error_code=400,
                error_message="Two-factor authentication is not enabled for this user",
            )

        token: str = payload.get("token", "")
        backup_codes = credential.backup_codes
        if not credential.verify(token):
            return AuthVerificationResult(
                success=False,
                error_code=401,
                error_message="Invalid two-factor authentication token",
            )

        if credential.backup_codes != backup_codes:
            with session.no_autoflush:
                consumed = cast(
                    CursorResult,
                    session.execute(
                        update(UserTotpCredential)
                        .where(
                            UserTotpCredential.user_id == user.id,
                            UserTotpCredential.credential_id
                            == credential.credential_id,
                            UserTotpCredential.backup_codes == backup_codes,
                        )
                        .values(backup_codes=credential.backup_codes)
                        .execution_options(synchronize_session=False)
                    ),
                )
            session.expire(credential, ["backup_codes"])
            if consumed.rowcount != 1:
                return AuthVerificationResult(
                    success=False,
                    error_message="Invalid two-factor authentication token",
                )

        return AuthVerificationResult(
            success=True, credential_id=credential.credential_id
        )
