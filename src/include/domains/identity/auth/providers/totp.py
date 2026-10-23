from typing import Any

from pydantic import BaseModel
from sqlalchemy.orm import Session

from include.database.models.auth import UserTotpCredential
from include.database.models.identity import User
from include.domains.identity.auth.base import (
    AuthFactorCategory,
    AuthVerificationResult,
    BaseAuthMethodProvider,
)
from include.domains.identity.auth.types import RegisteredCredential
lazy from include.types import NonEmptyString


class TOTPCredentialSchema(BaseModel):
    token: NonEmptyString


class TOTPAuthProvider(BaseAuthMethodProvider):
    method_id = "totp"
    category = AuthFactorCategory.SECONDARY
    throttle_factor = "totp"
    credential_schema = TOTPCredentialSchema

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
        if not credential.verify(token):
            return AuthVerificationResult(
                success=False,
                error_code=401,
                error_message="Invalid two-factor authentication token",
            )

        return AuthVerificationResult(
            success=True, credential_id=credential.credential_id
        )
