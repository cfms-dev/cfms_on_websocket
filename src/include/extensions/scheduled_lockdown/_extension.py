from pydantic import BaseModel, ConfigDict

from include.domains.access.permissions import Permissions
from include.domains.operations.lockdown import (
    LockdownReason,
    apply_scheduled_lockdown,
)
from include.extensions.manager import hookimpl
from include.scheduling import (
    ScheduledTaskContext,
    ScheduledTaskRegistration,
    ScheduledTaskResult,
)
from include.types import PositiveInt


class ScheduledLockdownWindowPayload(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")

    duration_seconds: PositiveInt
    reason: LockdownReason | None = None


def run_scheduled_lockdown_window(
    context: ScheduledTaskContext,
    payload: ScheduledLockdownWindowPayload,
) -> ScheduledTaskResult:
    expires_at = context.scheduled_for + payload.duration_seconds
    transition = apply_scheduled_lockdown(
        context.execution_id,
        expires_at,
        payload.reason,
    )
    return ScheduledTaskResult(
        data={
            "activation_id": context.execution_id,
            "expires_at": expires_at,
            "outcome": transition.outcome,
            "cancelled_file_tasks": transition.cancelled_file_tasks,
        }
    )


scheduled_lockdown_window_task = ScheduledTaskRegistration(
    name="scheduled_lockdown.window",
    contract_version=1,
    payload_model=ScheduledLockdownWindowPayload,
    execute=run_scheduled_lockdown_window,
    required_permission=Permissions.APPLY_LOCKDOWN,
)


@hookimpl
def ext_register_scheduled_tasks():
    return (scheduled_lockdown_window_task,)
