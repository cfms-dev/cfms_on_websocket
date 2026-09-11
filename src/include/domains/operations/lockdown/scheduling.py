"""Always-available scheduling adapter for owned lockdown expiration."""

import datetime as dt

from pydantic import BaseModel, ConfigDict

from include.domains.operations.lockdown.commands import expire_scheduled_lockdown
from include.domains.operations.lockdown.state import lockdown_state_manager
from include.scheduling.contracts import (
    ScheduledTaskContext,
    ScheduledTaskRegistration,
    ScheduledTaskResult,
    SystemScheduleDefinition,
)


class _LockdownExpiryPayload(BaseModel):
    """Identify the scheduled activation this deadline is allowed to release."""

    model_config = ConfigDict(extra="forbid")

    activation_id: str


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


lockdown_expiry_task = ScheduledTaskRegistration(
    name="core.lockdown_expiry",
    contract_version=1,
    payload_model=_LockdownExpiryPayload,
    execute=_run_lockdown_expiry,
    user_schedulable=False,
    system_schedule=_lockdown_expiry_schedule,
)
