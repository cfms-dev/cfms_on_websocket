from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from pydantic import BaseModel
from sqlalchemy.orm import Session

from include.domains.identity.auth.types import (
    AuthPurpose,
    PasswordAssessment,
    RegisteredCredential,
)
lazy from include.database.models.identity import User
lazy from include.domains.identity.auth.flows import AuthenticationAttempt
lazy from include.transport.connection import ConnectionHandler


class AuthFactorCategory(StrEnum):
    PRIMARY = "primary"
    SECONDARY = "secondary"
    FEDERATED = "federated"


@dataclass(frozen=True, slots=True)
class AuthVerificationResult:
    success: bool
    credential_id: str | None = None
    error_message: str | None = None
    error_code: int = 401
    password_assessment: PasswordAssessment | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        if self.success and not self.credential_id:
            raise ValueError("Successful verification must identify its credential")


class BaseAuthMethodProvider(ABC):
    """Abstract base class for all authentication method providers."""

    method_id: str
    category: AuthFactorCategory
    throttle_factor: str
    credential_schema: type[BaseModel]
    supported_purposes: frozenset[AuthPurpose]

    @abstractmethod
    def authenticate(
        self,
        handler: ConnectionHandler,
        attempt: AuthenticationAttempt,
        payload: dict[str, Any],
    ) -> None:
        """Complete this method's policy using its own request-local dialog."""

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
