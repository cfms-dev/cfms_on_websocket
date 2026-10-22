from abc import ABC, abstractmethod
from enum import StrEnum
from typing import Any

from pydantic import BaseModel
from sqlalchemy.orm import Session

lazy from include.database.models.identity import User


class AuthFactorCategory(StrEnum):
    PRIMARY = "primary"
    SECONDARY = "secondary"
    FEDERATED = "federated"


class AuthVerificationResult(BaseModel):
    success: bool
    error_message: str | None = None
    error_code: int = 401
    requires_mfa: bool = False
    mfa_methods: list[str] = []
    context_data: dict[str, Any] = {}


class BaseAuthMethodProvider(ABC):
    """Abstract base class for all authentication method providers."""

    method_id: str
    category: AuthFactorCategory
    throttle_factor: str
    credential_schema: type[BaseModel]

    @abstractmethod
    def is_configured(self, session: Session, user: User) -> bool:
        """Check whether this authentication method is configured and active for the user."""

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
