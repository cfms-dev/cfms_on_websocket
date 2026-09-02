from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from include.domains.access.permissions import Permissions


@dataclass(frozen=True, slots=True)
class ScheduledTaskContext:
    schedule_id: str
    execution_id: str
    scheduled_for: float
    attempt: int


@dataclass(frozen=True, slots=True)
class ScheduledTaskResult:
    target: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


type ScheduledTaskCallable = Callable[
    [ScheduledTaskContext, BaseModel], ScheduledTaskResult | None
]


@dataclass(frozen=True, slots=True)
class ScheduledTaskRegistration:
    name: str
    contract_version: int
    payload_model: type[BaseModel]
    execute: ScheduledTaskCallable
    required_permission: Permissions
    max_attempts: int = 5
    initial_backoff_seconds: int = 5
    maximum_backoff_seconds: int = 300

    def __post_init__(self) -> None:
        owner, separator, task_name = self.name.partition(".")
        if not separator or not owner or not task_name:
            raise ValueError("Scheduled task names must use '<extension>.<task>'")
        if self.contract_version <= 0:
            raise ValueError("Scheduled task contract versions must be positive")
        if self.max_attempts <= 0:
            raise ValueError("Scheduled task max_attempts must be positive")
        if self.initial_backoff_seconds <= 0:
            raise ValueError("Scheduled task initial backoff must be positive")
        if self.maximum_backoff_seconds < self.initial_backoff_seconds:
            raise ValueError(
                "Scheduled task maximum backoff must not be less than initial backoff"
            )
