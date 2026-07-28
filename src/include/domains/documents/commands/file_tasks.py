import time
from dataclasses import dataclass, field
from typing import Any, cast

from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

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
    encryption_key: str | None = field(repr=False)


def serialize_file_task(task: FileTask) -> dict[str, Any]:
    return {
        "task_id": task.id,
        "provider": "native",  # reserved for future use
        "start_time": task.start_time,
        "end_time": task.end_time,
        "supports_resume": task.mode == TransferMode.DOWNLOAD,
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
) -> ClaimedFileTask | None:
    if now is None:
        now = time.time()
    task = session.get(FileTask, task_id)
    if task is None or task.mode != transfer_mode:
        return None
    if expire_file_task_if_due(session, task_id, now=now) != FileTaskStatus.PENDING:
        return None
    if task.start_time > now:
        return None

    values: dict[Any, Any] = {FileTask.status: FileTaskStatus.IN_PROGRESS}
    if transfer_mode == TransferMode.UPLOAD:
        policy = DocumentUploadPolicy.from_config()
        initial_window = (
            task.end_time is not None
            and (task.end_time - task.start_time) <= policy.start_timeout_seconds
        )
        if initial_window:
            values.update(
                {
                    FileTask.start_time: now,
                    FileTask.end_time: now + policy.max_duration_seconds,
                }
            )

    result = cast(
        CursorResult[Any],
        session.execute(
            update(FileTask)
            .where(
                FileTask.id == task_id,
                FileTask.mode == transfer_mode,
                FileTask.status == FileTaskStatus.PENDING,
                FileTask.start_time <= now,
                (FileTask.end_time.is_(None) | (FileTask.end_time > now)),
            )
            .values(values)
        ),
    )
    if result.rowcount != 1:
        session.expire(task)
        return None

    file = task.file
    claimed = ClaimedFileTask(
        task_id=task.id,
        file_id=file.id,
        file_path=file.path,
        stored_file_size=(
            file.size if transfer_mode == TransferMode.DOWNLOAD else None
        ),
        encryption_key=(
            task.encryption_key if transfer_mode == TransferMode.DOWNLOAD else None
        ),
    )
    session.expire(task)
    return claimed


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
