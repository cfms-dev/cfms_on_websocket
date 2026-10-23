import secrets
import uuid
from enum import StrEnum
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter


class AuthPurpose(StrEnum):
    LOGIN = "login"
    MFA = "mfa"
    ESCALATION = "escalation"


class RegisteredCredential(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    method: str
    credential_id: str
    active: bool
    label: str | None = None
    key_identity: str | None = None


class AuthStep(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    method: str = Field(min_length=1)
    credential_ids: list[Annotated[str, Field(min_length=1)]] = Field(min_length=1)


type AuthChains = list[Annotated[list[AuthStep], Field(min_length=1)]]
auth_chains_adapter = TypeAdapter(AuthChains)


class AuthEvidence(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    user_id: uuid.UUID
    attempt_id: str
    event_id: str = Field(default_factory=lambda: secrets.token_hex(16))
    method: str
    credential_id: str


class AuthenticationContext(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    attempt_id: str = Field(default_factory=lambda: secrets.token_hex(16))
    login_revision: int = Field(ge=0)
    mfa_revision: int = Field(ge=0)
    evidence: list[AuthEvidence] = Field(default_factory=list)


class AuthPolicyDecision(BaseModel):
    satisfied: bool
    next_steps: list[AuthStep] = Field(default_factory=list)
