"""Always-available core system task registrations.

Feature-owned maintenance tasks belong in their extensions; this module contains
only scheduling's own history cleanup and the core lockdown-expiry deadline.
"""

import datetime as dt

from pydantic import BaseModel, ConfigDict

from include.config.validation import SchedulingPolicy
from include.domains.operations.lockdown import (
    expire_scheduled_lockdown,
    lockdown_state_manager,
)
from include.scheduling.contracts import (
    ScheduledTaskContext,
    ScheduledTaskRegistration,
    ScheduledTaskResult,
    SystemScheduleDefinition,
)
from include.scheduling.outcomes import purge_execution_history


class _EmptyPayload(BaseModel):
    """Strict empty contract shared by core tasks without runtime parameters."""

    model_config = ConfigDict(extra="forbid")


class _LockdownExpiryPayload(BaseModel):
    """Identify the scheduled activation this deadline is allowed to release."""

    model_config = ConfigDict(extra="forbid")

    activation_id: str


def _schedule_history_cleanup_schedule() -> SystemScheduleDefinition:
    """Declare the hourly bounded cleanup for terminal execution history."""

    return SystemScheduleDefinition(
        id="core.schedule_history_cleanup",
        payload={},
        trigger_type="interval",
        trigger_data={"seconds": 3600},
    )


def _run_schedule_history_cleanup(
    _context: ScheduledTaskContext,
    _payload: _EmptyPayload,
) -> ScheduledTaskResult:
    """Delete one policy-bounded batch of expired terminal executions."""

    deleted = purge_execution_history(SchedulingPolicy.from_config())
    return ScheduledTaskResult(
        data={"deleted_executions": deleted},
        audit_success=deleted > 0,
    )


def _lockdown_expiry_schedule() -> SystemScheduleDefinition | None:
    """Reflect the current durable scheduled-lockdown deadline, if one exists."""

    activation = lockdown_state_manager.get_scheduled_activation()
    if activation is None or activation.expires_at is None:
        return None
    return SystemScheduleDefinition(
        id="core.lockdown_expiry",
        payload={"activation_id": activation.activation_id},
        trigger_type="date",
        trigger_data={
            "run_at": dt.datetime.fromtimestamp(
                activation.expires_at,
                dt.UTC,
            ).isoformat()
        },
        run_immediately=activation.expires_at <= activation.observed_at,
    )


def _run_lockdown_expiry(
    _context: ScheduledTaskContext,
    payload: _LockdownExpiryPayload,
) -> ScheduledTaskResult:
    """Expire only the activation identified by the reconciled payload."""

    transition = expire_scheduled_lockdown(payload.activation_id)
    return ScheduledTaskResult(
        data={
            "activation_id": payload.activation_id,
            "outcome": transition.outcome,
        }
    )


CORE_SCHEDULED_TASKS = (
    ScheduledTaskRegistration(
        name="core.schedule_history_cleanup",
        contract_version=1,
        payload_model=_EmptyPayload,
        execute=_run_schedule_history_cleanup,
        max_attempts=1,
        user_schedulable=False,
        system_schedule=_schedule_history_cleanup_schedule,
    ),
    ScheduledTaskRegistration(
        name="core.lockdown_expiry",
        contract_version=1,
        payload_model=_LockdownExpiryPayload,
        execute=_run_lockdown_expiry,
        user_schedulable=False,
        system_schedule=_lockdown_expiry_schedule,
    ),
)
