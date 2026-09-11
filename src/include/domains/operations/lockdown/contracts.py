from dataclasses import dataclass
from enum import StrEnum
from typing import Self

from pydantic import BaseModel, ConfigDict, model_validator

from include.domains.operations.comments import OperationReason

LockdownReason = OperationReason


class LockdownSource(StrEnum):
    """Internal provenance used to protect security-owned lockdowns."""

    MANUAL = "manual"
    SCHEDULED = "scheduled"
    AUTOMATIC = "automatic"
    UNKNOWN = "unknown"


class _LockdownStateBase(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        strict=True,
        extra="forbid",
    )

    enabled: bool
    reason: LockdownReason | None

    @model_validator(mode="after")
    def _validate_reason(self) -> Self:
        if not self.enabled and self.reason is not None:
            raise ValueError("A lockdown reason requires lockdown to be enabled")
        return self


class LockdownState(_LockdownStateBase):
    enabled: bool = False
    reason: LockdownReason | None = None

    def as_response_data(self) -> dict[str, bool | str | None]:
        return {
            "status": self.enabled,
            "reason": self.reason,
        }


class LockdownTransitionOutcome(StrEnum):
    APPLIED = "applied"
    UNCHANGED = "unchanged"
    CONDITION_NOT_MET = "condition_not_met"


@dataclass(frozen=True, slots=True)
class ScheduledLockdownActivation:
    activation_id: str
    expires_at: float | None
    observed_at: float


@dataclass(frozen=True, slots=True)
class LockdownTransition:
    previous_state: LockdownState
    state: LockdownState
    outcome: LockdownTransitionOutcome
    cancelled_file_tasks: int = 0
    previous_source: LockdownSource | None = None
    source: LockdownSource | None = None

    @property
    def applied(self) -> bool:
        return self.outcome is LockdownTransitionOutcome.APPLIED
