"""User-schedulable lockdown transitions and fixed-duration windows."""

from pydantic import BaseModel, ConfigDict

from include.domains.access.permissions import Permissions
from include.domains.operations.lockdown import (
    LockdownReason,
    apply_scheduled_lockdown,
    disable_scheduled_lockdown,
)
from include.extensions.manager import hookimpl
from include.scheduling import (
    ScheduledTaskContext,
    ScheduledTaskRegistration,
    ScheduledTaskResult,
)
from include.types import PositiveInt


class ScheduledLockdownWindowPayload(BaseModel):
    """Strict persisted contract for one scheduled lockdown occurrence."""

    model_config = ConfigDict(strict=True, extra="forbid")

    duration_seconds: PositiveInt
    reason: LockdownReason | None = None


class ScheduledLockdownEnablePayload(BaseModel):
    """Strict contract for enabling lockdown without an automatic deadline."""

    model_config = ConfigDict(strict=True, extra="forbid")

    reason: LockdownReason | None = None


class ScheduledLockdownDisablePayload(BaseModel):
    """Strict empty contract for a guarded scheduled disable operation."""

    model_config = ConfigDict(strict=True, extra="forbid")


def run_scheduled_lockdown_window(
    context: ScheduledTaskContext,
    payload: ScheduledLockdownWindowPayload,
) -> ScheduledTaskResult:
    """Apply a lockdown owned by this occurrence until its scheduled deadline.

    The deterministic execution ID identifies the activation, making retrying the
    same occurrence safe.  Duration is added to ``scheduled_for`` so queue delay
    and daylight-saving transitions do not extend the maintenance window.
    """

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


def run_scheduled_lockdown_enable(
    context: ScheduledTaskContext,
    payload: ScheduledLockdownEnablePayload,
) -> ScheduledTaskResult:
    """Enable lockdown for this occurrence without scheduling an expiry."""

    transition = apply_scheduled_lockdown(
        context.execution_id,
        None,
        payload.reason,
    )
    return ScheduledTaskResult(
        data={
            "activation_id": context.execution_id,
            "outcome": transition.outcome,
            "cancelled_file_tasks": transition.cancelled_file_tasks,
        }
    )


def run_scheduled_lockdown_disable(
    _context: ScheduledTaskContext,
    _payload: ScheduledLockdownDisablePayload,
) -> ScheduledTaskResult:
    """Disable only a manual or schedule-owned active lockdown."""

    transition = disable_scheduled_lockdown()
    return ScheduledTaskResult(data={"outcome": transition.outcome})


scheduled_lockdown_window_task = ScheduledTaskRegistration(
    name="scheduled_lockdown.window",
    contract_version=1,
    payload_model=ScheduledLockdownWindowPayload,
    execute=run_scheduled_lockdown_window,
    required_permission=Permissions.APPLY_LOCKDOWN,
)

scheduled_lockdown_enable_task = ScheduledTaskRegistration(
    name="scheduled_lockdown.enable",
    contract_version=1,
    payload_model=ScheduledLockdownEnablePayload,
    execute=run_scheduled_lockdown_enable,
    required_permission=Permissions.APPLY_LOCKDOWN,
)

scheduled_lockdown_disable_task = ScheduledTaskRegistration(
    name="scheduled_lockdown.disable",
    contract_version=1,
    payload_model=ScheduledLockdownDisablePayload,
    execute=run_scheduled_lockdown_disable,
    required_permission=Permissions.APPLY_LOCKDOWN,
)


@hookimpl
def ext_register_scheduled_tasks():
    """Register the extension's operator-configurable lockdown task types."""

    return (
        scheduled_lockdown_window_task,
        scheduled_lockdown_enable_task,
        scheduled_lockdown_disable_task,
    )
