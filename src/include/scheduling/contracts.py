"""Public value objects used to register and execute scheduled task types.

Extensions normally interact only with :class:`ScheduledTaskRegistration`,
:class:`ScheduledTaskContext`, :class:`ScheduledTaskResult`, and optionally
:class:`SystemScheduleDefinition`.  The remaining snapshots are internal hand-off
objects used to keep ORM state out of worker threads.
"""

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel

from include.domains.access.permissions import Permissions


@dataclass(frozen=True, slots=True)
class ClaimedExecution:
    """Immutable execution snapshot handed from a lease claimant to a worker.

    ``lease_owner`` proves which worker may persist the outcome.  The task name,
    contract version, and payload are copied from the execution row so later
    edits to the parent schedule cannot reinterpret already queued work.
    """

    id: str
    schedule_id: str
    task_name: str
    task_contract_version: int
    payload: dict
    scheduled_for: float
    attempt: int
    lease_owner: str


@dataclass(frozen=True, slots=True)
class PendingDispatch:
    """Cluster delivery candidate and its attempt number at selection time."""

    id: str
    attempt: int


@dataclass(frozen=True, slots=True)
class ScheduledTaskContext:
    """Stable occurrence metadata supplied to a registered task callable.

    Scheduled tasks run with at-least-once semantics.  Implementations should use
    ``execution_id`` as an idempotency key and use ``scheduled_for`` when business
    behavior must be based on the intended fire time rather than worker start time.
    """

    schedule_id: str
    execution_id: str
    scheduled_for: float
    attempt: int


@dataclass(frozen=True, slots=True)
class ScheduledTaskResult:
    """Optional JSON-serializable result and success-audit decision.

    ``audit_success=False`` is honored only for system task registrations. User-
    schedulable tasks and all failed attempts remain auditable.
    """

    target: str | None = None
    data: dict[str, Any] = field(default_factory=dict)
    audit_success: bool = True


type ScheduledTaskCallable[PayloadT: BaseModel] = Callable[
    [ScheduledTaskContext, PayloadT], ScheduledTaskResult | None
]


@dataclass(frozen=True, slots=True)
class SystemScheduleDefinition:
    """Desired schedule state produced by an internal task's factory.

    Reconciliation creates or updates a hidden schedule with ``id``.  Returning
    ``None`` from the factory retires any previous definition.  An interval may
    omit ``start_at`` because reconciliation supplies and preserves its anchor.
    ``run_immediately`` queues a separate immediate occurrence without shifting
    that anchor.
    """

    id: str
    payload: dict[str, Any]
    trigger_type: str
    trigger_data: dict[str, Any]
    timezone: str = "UTC"
    run_immediately: bool = True

    def __post_init__(self) -> None:
        """Reject identifiers that cannot be stored in the schedule primary key."""

        if not self.id or len(self.id) > 32:
            raise ValueError("System schedule IDs must contain 1 to 32 characters")


type SystemScheduleFactory = Callable[[], SystemScheduleDefinition | None]


@dataclass(frozen=True, slots=True)
class ScheduledTaskRegistration[PayloadT: BaseModel]:
    """Trusted executable task contract contributed by core code or an extension.

    Names are globally unique and use ``<owner>.<task>``.  Payloads are validated
    again immediately before execution.  User-schedulable tasks must declare the
    permission required to create or re-enable their schedules; system tasks set
    ``user_schedulable=False`` and may expose a desired-state factory instead.

    The retry settings apply to every occurrence.  Because a worker can finish an
    external effect before losing its lease or persisting success, ``execute`` must
    be synchronous and safe to repeat with the same execution ID.
    """

    name: str
    contract_version: int
    payload_model: type[PayloadT]
    execute: ScheduledTaskCallable[PayloadT]
    required_permission: Permissions | None = None
    max_attempts: int = 5
    initial_backoff_seconds: int = 5
    maximum_backoff_seconds: int = 300
    user_schedulable: bool = True
    system_schedule: SystemScheduleFactory | None = None

    def __post_init__(self) -> None:
        """Enforce naming, retry, permission, and ownership invariants."""

        owner, separator, task_name = self.name.partition(".")
        if not separator or not owner or not task_name:
            raise ValueError("Scheduled task names must use '<owner>.<task>'")
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
        if self.user_schedulable and self.required_permission is None:
            raise ValueError(
                "User-schedulable tasks must declare a required permission"
            )
        if self.user_schedulable and self.system_schedule is not None:
            raise ValueError("System-scheduled tasks cannot be user schedulable")
