import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, cast

from sqlalchemy import or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, joinedload

from include.config.validation import DocumentUploadPolicy
from include.database.models.files import FileTask, FileTaskStatus, TransferMode

ACTIVE_FILE_TASK_STATUSES = (
    FileTaskStatus.PENDING,
    FileTaskStatus.IN_PROGRESS,
)


@dataclass(frozen=True, slots=True, kw_only=True)
class ClaimedFileTask:
    task_id: str
    file_id: str
    file_path: str
    stored_file_size: int | None
    issued_by_username: str | None
    encryption_key: str | None = field(repr=False)
    chunk_size: int | None
    upload_file_size: int | None
    upload_sha256: str | None
    upload_session_id: str | None = field(repr=False)
    upload_checkpoint_size: int | None
    upload_checkpoint_data: str | None = field(repr=False)


class FileTaskClaimFailure(StrEnum):
    INVALID = "invalid"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    EXPIRED = "expired"
    CONFLICT = "conflict"


_CLAIM_FAILURE_BY_STATUS = {
    FileTaskStatus.IN_PROGRESS: FileTaskClaimFailure.IN_PROGRESS,
    FileTaskStatus.COMPLETED: FileTaskClaimFailure.COMPLETED,
    FileTaskStatus.CANCELLED: FileTaskClaimFailure.CANCELLED,
    FileTaskStatus.EXPIRED: FileTaskClaimFailure.EXPIRED,
}


def serialize_file_task(task: FileTask) -> dict[str, Any]:
    return {
        "task_id": task.id,
        "provider": "native",  # reserved for future use
        "start_time": task.start_time,
        "end_time": task.end_time,
        "supports_resume": True,
    }


def expire_file_task_if_due(
    session: Session, task_id: str, *, now: float | None = None
) -> FileTaskStatus | None:
    if now is None:
        now = time.time()
    task = session.get(FileTask, task_id)
    if task is None:
        return None

    status = FileTaskStatus(task.status)
    if (
        status not in ACTIVE_FILE_TASK_STATUSES
        or task.end_time is None
        or task.end_time > now
    ):
        return status

    result = cast(
        CursorResult[Any],
        session.execute(
            update(FileTask)
            .where(
                FileTask.id == task_id,
                FileTask.status.in_(ACTIVE_FILE_TASK_STATUSES),
                FileTask.end_time.is_not(None),
                FileTask.end_time <= now,
            )
            .values(status=FileTaskStatus.EXPIRED)
        ),
    )
    session.expire(task)
    if result.rowcount == 1:
        return FileTaskStatus.EXPIRED
    return FileTaskStatus(task.status)


def claim_file_task(
    session: Session,
    task_id: str,
    transfer_mode: TransferMode,
    *,
    now: float | None = None,
) -> ClaimedFileTask | FileTaskClaimFailure:
    now = time.time() if now is None else now
    is_upload = transfer_mode == TransferMode.UPLOAD

    task = session.get(
        FileTask,
        task_id,
        options=(joinedload(FileTask.file),),
    )
    if task is None or task.mode != transfer_mode:
        return FileTaskClaimFailure.INVALID

    status = expire_file_task_if_due(session, task_id, now=now)
    if status != FileTaskStatus.PENDING:
        if status is None:
            return FileTaskClaimFailure.INVALID
        return _CLAIM_FAILURE_BY_STATUS.get(status, FileTaskClaimFailure.INVALID)

    # The following line is used to avoid executing an UPDATE that is bound to fail.
    if task.start_time > now:
        return FileTaskClaimFailure.INVALID

    values: dict[str, object] = {
        "status": FileTaskStatus.IN_PROGRESS,
    }

    if is_upload:
        policy = DocumentUploadPolicy.from_config()

        initial_window = (
            task.end_time is not None
            and task.end_time - task.start_time <= policy.start_timeout_seconds
        )

        if initial_window:
            values.update(
                {
                    "start_time": now,
                    "end_time": now + policy.max_duration_seconds,
                }
            )

    statement = (
        update(FileTask)
        .where(
            FileTask.id == task_id,
            FileTask.mode == transfer_mode,
            FileTask.status == FileTaskStatus.PENDING,
            FileTask.start_time <= now,
            or_(
                FileTask.end_time.is_(None),
                FileTask.end_time > now,
            ),
        )
        .values(**values)
        .execution_options(synchronize_session=False)
    )

    result = cast(
        CursorResult[Any],
        session.execute(statement),
    )

    if result.rowcount != 1:
        session.expire(task)
        status = expire_file_task_if_due(session, task_id, now=now)
        if status is None:
            return FileTaskClaimFailure.CONFLICT
        return _CLAIM_FAILURE_BY_STATUS.get(status, FileTaskClaimFailure.CONFLICT)

    try:
        stored_file = task.file

        return ClaimedFileTask(
            task_id=task.id,
            file_id=task.file_id,
            file_path=stored_file.path,
            stored_file_size=(stored_file.size if not is_upload else None),
            issued_by_username=task.issued_by_username,
            encryption_key=(task.encryption_key if not is_upload else None),
            chunk_size=task.chunk_size,
            upload_file_size=(task.upload_file_size if is_upload else None),
            upload_sha256=(task.upload_sha256 if is_upload else None),
            upload_session_id=(task.upload_session_id if is_upload else None),
            upload_checkpoint_size=(task.upload_checkpoint_size if is_upload else None),
            upload_checkpoint_data=(task.upload_checkpoint_data if is_upload else None),
        )
    finally:
        session.expire(task)


def complete_file_task(session: Session, task_id: str) -> bool:
    result = cast(
        CursorResult[Any],
        session.execute(
            update(FileTask)
            .where(
                FileTask.id == task_id,
                FileTask.status == FileTaskStatus.IN_PROGRESS,
            )
            .values(status=FileTaskStatus.COMPLETED)
        ),
    )
    return result.rowcount == 1


def release_file_task(
    session: Session, task_id: str, *, now: float | None = None
) -> FileTaskStatus | None:
    if now is None:
        now = time.time()
    task = session.get(FileTask, task_id)
    if task is None or task.status != FileTaskStatus.IN_PROGRESS:
        return None
    next_status = (
        FileTaskStatus.EXPIRED
        if task.end_time is not None and task.end_time <= now
        else FileTaskStatus.PENDING
    )
    result = cast(
        CursorResult[Any],
        session.execute(
            update(FileTask)
            .where(
                FileTask.id == task_id,
                FileTask.status == FileTaskStatus.IN_PROGRESS,
            )
            .values(status=next_status)
        ),
    )
    return next_status if result.rowcount == 1 else None


def cancel_file_tasks_for_files(session: Session, file_ids: set[str]) -> list[str]:
    if not file_ids:
        return []
    task_ids = list(
        session.scalars(
            select(FileTask.id).where(
                FileTask.file_id.in_(file_ids),
                FileTask.status.in_(ACTIVE_FILE_TASK_STATUSES),
            )
        ).all()
    )
    if not task_ids:
        return []
    session.execute(
        update(FileTask)
        .where(
            FileTask.id.in_(task_ids),
            FileTask.status.in_(ACTIVE_FILE_TASK_STATUSES),
        )
        .values(status=FileTaskStatus.CANCELLED)
    )
    return task_ids
