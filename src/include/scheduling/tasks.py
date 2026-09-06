from pydantic import BaseModel, ConfigDict

from include.config.validation import SchedulingPolicy
from include.scheduling.contracts import (
    ScheduledTaskContext,
    ScheduledTaskRegistration,
    ScheduledTaskResult,
    SystemScheduleDefinition,
)
from include.scheduling.engine import purge_execution_history


class _EmptyPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _schedule_history_cleanup_schedule() -> SystemScheduleDefinition:
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
    deleted = purge_execution_history(SchedulingPolicy.from_config())
    return ScheduledTaskResult(data={"deleted_executions": deleted})


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
)
