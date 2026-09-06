import time

from loguru import logger as log
from pydantic import BaseModel, ConfigDict

from include.config.validation import IdentityPermissionRetentionPolicy
from include.database.session import Session
from include.domains.identity.commands.permission_cleanup import (
    PermissionEntryCounts,
    purge_expired_permission_entries,
)
from include.scheduling import (
    ScheduledTaskContext,
    ScheduledTaskRegistration,
    ScheduledTaskResult,
    SystemScheduleDefinition,
)

logger = log.bind(name="permission_cleanup")
_SECONDS_PER_DAY = 24 * 60 * 60


class _PermissionCleanupPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")


def cleanup_expired_permission_entries(
    policy: IdentityPermissionRetentionPolicy,
    now: float | None = None,
) -> PermissionEntryCounts:
    if now is None:
        now = time.time()
    cutoff = now - policy.retention_days * _SECONDS_PER_DAY

    with Session.begin() as session:
        result = purge_expired_permission_entries(
            session,
            cutoff,
            policy.batch_size,
        )

    if result.total:
        logger.bind(
            cutoff=cutoff,
            user_entries=result.user_entries,
            group_entries=result.group_entries,
        ).info("Expired permission entries were purged")
    return result


def _permission_cleanup_schedule() -> SystemScheduleDefinition:
    policy = IdentityPermissionRetentionPolicy.from_config()
    return SystemScheduleDefinition(
        id="builtin.permission_cleanup",
        payload={},
        trigger_type="interval",
        trigger_data={"seconds": policy.cleanup_interval_seconds},
    )


def run_scheduled_permission_cleanup(
    _context: ScheduledTaskContext,
    _payload: _PermissionCleanupPayload,
) -> ScheduledTaskResult:
    result = cleanup_expired_permission_entries(
        IdentityPermissionRetentionPolicy.from_config()
    )
    return ScheduledTaskResult(
        data={
            "user_entries": result.user_entries,
            "group_entries": result.group_entries,
        }
    )


permission_cleanup_task = ScheduledTaskRegistration(
    name="builtin.permission_cleanup",
    contract_version=1,
    payload_model=_PermissionCleanupPayload,
    execute=run_scheduled_permission_cleanup,
    max_attempts=1,
    user_schedulable=False,
    system_schedule=_permission_cleanup_schedule,
)
