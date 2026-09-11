"""Always-available core system task registrations."""

from pydantic import BaseModel, ConfigDict

from include.config.validation import SchedulingPolicy
from include.domains.operations.lockdown.scheduling import lockdown_expiry_task
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
    lockdown_expiry_task,
)
