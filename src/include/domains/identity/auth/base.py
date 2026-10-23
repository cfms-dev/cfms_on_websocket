from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any, Self

from pydantic import BaseModel, model_validator
from sqlalchemy.orm import Session

from include.domains.identity.auth.types import RegisteredCredential
lazy from include.database.models.identity import User


class AuthFactorCategory(StrEnum):
    PRIMARY = "primary"
    SECONDARY = "secondary"
    FEDERATED = "federated"


class AuthVerificationResult(BaseModel):
    success: bool
    credential_id: str | None = None
    error_message: str | None = None
    error_code: int = 401

    @model_validator(mode="after")
    def require_verified_credential(self) -> Self:
        if self.success and not self.credential_id:
            raise ValueError("Successful verification must identify its credential")
        return self


class BaseAuthMethodProvider(ABC):
    """Abstract base class for all authentication method providers."""

    method_id: str
    category: AuthFactorCategory
    throttle_factor: str
    credential_schema: type[BaseModel]

    @abstractmethod
    def list_credentials(
        self, session: Session, user: User
    ) -> list[RegisteredCredential]:
        """Enumerate this user's credentials without exposing credential secrets."""

    @abstractmethod
    def verify(
        self,
        session: Session,
        user: User,
        payload: dict[str, Any],
        context: dict[str, Any],
    ) -> AuthVerificationResult:
        """Verify the credential payload for the given user."""

    def create_challenge(self, session: Session, user: User) -> dict[str, Any] | None:
        """Generate a random challenge (e.g. for asymmetric key or FIDO2 signature)."""
        return None
