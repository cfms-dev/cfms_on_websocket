from typing import Any

from pydantic import BaseModel
from sqlalchemy.orm import Session

from include.database.models.identity import User
from include.domains.identity.auth.base import (
    AuthFactorCategory,
    AuthVerificationResult,
    BaseAuthMethodProvider,
)
lazy from include.types import NonEmptyString


class TOTPCredentialSchema(BaseModel):
    token: NonEmptyString


class TOTPAuthProvider(BaseAuthMethodProvider):
    method_id = "totp"
    category = AuthFactorCategory.SECONDARY
    throttle_factor = "totp"
    credential_schema = TOTPCredentialSchema

    def is_configured(self, session: Session, user: User) -> bool:
        return user.totp_credential is not None and user.totp_credential.enabled

    def verify(
        self,
        session: Session,
        user: User,
        payload: dict[str, Any],
        context: dict[str, Any],
    ) -> AuthVerificationResult:
        if not user.totp_credential or not user.totp_credential.enabled:
            return AuthVerificationResult(
                success=False,
                error_code=400,
                error_message="Two-factor authentication is not enabled for this user",
            )

        token: str = payload.get("token", "")
        if not user.totp_credential.verify(token):
            return AuthVerificationResult(
                success=False,
                error_code=401,
                error_message="Invalid two-factor authentication token",
            )

        return AuthVerificationResult(success=True)
