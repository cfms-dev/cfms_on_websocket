from pydantic import BaseModel, ConfigDict

from include.config.validation import AuthThrottlePolicy, DocumentUploadPolicy
from include.database.session import Session
from include.domains.documents.commands.upload_cleanup import reclaim_abandoned_uploads
from include.domains.documents.creation_limits import (
    cleanup_document_creation_risk_state,
)
from include.domains.documents.download_limits import (
    cleanup_document_download_risk_state,
)
from include.domains.security.guards.login import purge_expired_auth_throttle_records
from include.scheduling import (
    ScheduledTaskContext,
    ScheduledTaskRegistration,
    ScheduledTaskResult,
    SystemScheduleDefinition,
)

_UPLOAD_CLEANUP_BATCH_SIZE = 256


class _EmptyPayload(BaseModel):
    model_config = ConfigDict(extra="forbid")


def _interval_schedule(identifier: str, seconds: int) -> SystemScheduleDefinition:
    return SystemScheduleDefinition(
        id=identifier,
        payload={},
        trigger_type="interval",
        trigger_data={"seconds": seconds},
    )


def _upload_cleanup_schedule() -> SystemScheduleDefinition:
    return _interval_schedule(
        "builtin.upload_cleanup",
        DocumentUploadPolicy.from_config().cleanup_interval_seconds,
    )


def _creation_risk_cleanup_schedule() -> SystemScheduleDefinition:
    return _interval_schedule(
        "builtin.creation_risk_cleanup",
        DocumentUploadPolicy.from_config().cleanup_interval_seconds,
    )


def _run_upload_cleanup(
    _context: ScheduledTaskContext,
    _payload: _EmptyPayload,
) -> ScheduledTaskResult:
    result = reclaim_abandoned_uploads(limit=_UPLOAD_CLEANUP_BATCH_SIZE)
    return ScheduledTaskResult(
        data={
            "matched_tasks": result.matched_tasks,
            "expired_tasks": result.expired_tasks,
            "removed_revisions": result.removed_revisions,
            "removed_documents": result.removed_documents,
            "storage_cleanup_failures": result.storage_cleanup_failures,
        }
    )


def _run_auth_throttle_cleanup(
    _context: ScheduledTaskContext,
    _payload: _EmptyPayload,
) -> ScheduledTaskResult:
    result = purge_expired_auth_throttle_records(AuthThrottlePolicy.from_config())
    return ScheduledTaskResult(
        data={
            "account_records": result.account_records,
            "login_records": result.login_records,
            "traffic_records": result.traffic_records,
        }
    )


def _run_creation_risk_cleanup(
    _context: ScheduledTaskContext,
    _payload: _EmptyPayload,
) -> ScheduledTaskResult:
    with Session.begin() as session:
        result = cleanup_document_creation_risk_state(session)
    return ScheduledTaskResult(
        data={"ip_accounts": result.ip_accounts, "buckets": result.buckets}
    )


def _run_download_risk_cleanup(
    _context: ScheduledTaskContext,
    _payload: _EmptyPayload,
) -> ScheduledTaskResult:
    with Session.begin() as session:
        result = cleanup_document_download_risk_state(session)
    return ScheduledTaskResult(
        data={"ip_accounts": result.ip_accounts, "buckets": result.buckets}
    )


BUILTIN_SCHEDULED_TASKS = (
    ScheduledTaskRegistration(
        name="builtin.upload_cleanup",
        contract_version=1,
        payload_model=_EmptyPayload,
        execute=_run_upload_cleanup,
        max_attempts=1,
        user_schedulable=False,
        system_schedule=_upload_cleanup_schedule,
    ),
    ScheduledTaskRegistration(
        name="builtin.auth_throttle_cleanup",
        contract_version=1,
        payload_model=_EmptyPayload,
        execute=_run_auth_throttle_cleanup,
        max_attempts=1,
        user_schedulable=False,
        system_schedule=lambda: _interval_schedule(
            "builtin.auth_throttle_cleanup", 3600
        ),
    ),
    ScheduledTaskRegistration(
        name="builtin.creation_risk_cleanup",
        contract_version=1,
        payload_model=_EmptyPayload,
        execute=_run_creation_risk_cleanup,
        max_attempts=1,
        user_schedulable=False,
        system_schedule=_creation_risk_cleanup_schedule,
    ),
    ScheduledTaskRegistration(
        name="builtin.download_risk_cleanup",
        contract_version=1,
        payload_model=_EmptyPayload,
        execute=_run_download_risk_cleanup,
        max_attempts=1,
        user_schedulable=False,
        system_schedule=lambda: _interval_schedule("builtin.download_risk_cleanup", 60),
    ),
)
