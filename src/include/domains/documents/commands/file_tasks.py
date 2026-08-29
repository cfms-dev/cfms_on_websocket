import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, cast

from sqlalchemy import or_, select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session, joinedload

from include.config.validation import DocumentUploadPolicy
from include.database.models.files import File, FileTask, FileTaskStatus, TransferMode

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


class FileTaskChunkSizeConflict(ValueError):
    def __init__(self, chunk_size: int) -> None:
        self.chunk_size = chunk_size
        super().__init__("Persisted chunk size exceeds the client maximum")


class UploadMetadataConflict(ValueError):
    def __init__(
        self,
        *,
        file_size: int,
        sha256: str,
        chunk_size: int,
    ) -> None:
        self.file_size = file_size
        self.sha256 = sha256
        self.chunk_size = chunk_size
        super().__init__("Upload metadata does not match the resumable task")


@dataclass(frozen=True, slots=True, kw_only=True)
class UploadPreparation:
    chunk_size: int
    resumable: bool
    discard_existing: bool
    prior_session_id: str | None = field(repr=False)
    checkpoint_size: int | None
    checkpoint_data: str | None = field(repr=False)


_CLAIM_FAILURE_BY_STATUS = {
    FileTaskStatus.IN_PROGRESS: FileTaskClaimFailure.IN_PROGRESS,
    FileTaskStatus.COMPLETED: FileTaskClaimFailure.COMPLETED,
    FileTaskStatus.CANCELLED: FileTaskClaimFailure.CANCELLED,
    FileTaskStatus.EXPIRED: FileTaskClaimFailure.EXPIRED,
}


def plan_upload_file_task(
    claimed: ClaimedFileTask,
    *,
    file_size: int,
    sha256: str | None,
    proposed_chunk_size: int,
    client_max_chunk_size: int,
    restart: bool,
    supports_resumable_uploads: bool,
) -> UploadPreparation:
    chunk_size = claimed.chunk_size or proposed_chunk_size
    if chunk_size > client_max_chunk_size:
        raise FileTaskChunkSizeConflict(chunk_size)

    resumable = supports_resumable_uploads and sha256 is not None and file_size > 0
    stored_metadata = claimed.upload_file_size is not None
    metadata_matches = (
        claimed.upload_file_size == file_size and claimed.upload_sha256 == sha256
    )
    if (
        supports_resumable_uploads
        and stored_metadata
        and claimed.upload_sha256 is not None
        and not metadata_matches
        and not restart
    ):
        raise UploadMetadataConflict(
            file_size=claimed.upload_file_size,
            sha256=claimed.upload_sha256,
            chunk_size=chunk_size,
        )

    discard_existing = restart or (stored_metadata and not resumable)
    return UploadPreparation(
        chunk_size=chunk_size,
        resumable=resumable,
        discard_existing=discard_existing,
        prior_session_id=(None if discard_existing else claimed.upload_session_id),
        checkpoint_size=(None if discard_existing else claimed.upload_checkpoint_size),
        checkpoint_data=(None if discard_existing else claimed.upload_checkpoint_data),
    )


def apply_upload_file_task_preparation(
    session: Session,
    task_id: str,
    preparation: UploadPreparation,
    *,
    file_size: int,
    sha256: str | None,
) -> FileTaskStatus | None:
    task = session.get(FileTask, task_id)
    if task is None:
        return None
    status = FileTaskStatus(task.status)
    if status != FileTaskStatus.IN_PROGRESS:
        return status
    if task.chunk_size is None:
        task.chunk_size = preparation.chunk_size
    task.upload_file_size = file_size
    task.upload_sha256 = sha256
    if preparation.discard_existing:
        task.upload_session_id = None
        task.upload_checkpoint_size = None
        task.upload_checkpoint_data = None
    return status


def record_upload_checkpoint(
    session: Session, task_id: str, checkpoint_data: str
) -> FileTaskStatus | None:
    task = session.get(FileTask, task_id)
    if task is None:
        return None
    status = FileTaskStatus(task.status)
    if status == FileTaskStatus.IN_PROGRESS:
        task.upload_checkpoint_data = checkpoint_data
    return status


def record_upload_storage_session(
    session: Session,
    task_id: str,
    *,
    session_id: str | None,
    checkpoint_size: int | None,
    checkpoint_data: str | None,
) -> FileTaskStatus | None:
    task = session.get(FileTask, task_id)
    if task is None:
        return None
    status = FileTaskStatus(task.status)
    if status == FileTaskStatus.IN_PROGRESS:
        task.upload_session_id = session_id
        task.upload_checkpoint_size = checkpoint_size
        task.upload_checkpoint_data = checkpoint_data
    return status


def clear_upload_progress(session: Session, task_id: str) -> bool:
    task = session.get(FileTask, task_id)
    if task is None:
        return False
    task.upload_file_size = None
    task.upload_sha256 = None
    task.upload_session_id = None
    task.upload_checkpoint_size = None
    task.upload_checkpoint_data = None
    return True


def serialize_file_task(task: FileTask, *, supports_resume: bool) -> dict[str, Any]:
    return {
        "task_id": task.id,
        "provider": "native",  # reserved for future use
        "start_time": task.start_time,
        "end_time": task.end_time,
        "supports_resume": supports_resume,
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


def get_or_set_file_task_chunk_size(
    session: Session,
    task_id: str,
    proposed_chunk_size: int,
    client_max_chunk_size: int,
) -> int | FileTaskStatus | None:
    task = session.get(FileTask, task_id)
    if task is None:
        return None
    status = FileTaskStatus(task.status)
    if status != FileTaskStatus.IN_PROGRESS:
        return status
    if task.chunk_size is None:
        task.chunk_size = proposed_chunk_size
        return proposed_chunk_size
    if task.chunk_size > client_max_chunk_size:
        raise FileTaskChunkSizeConflict(task.chunk_size)
    return task.chunk_size


def get_or_set_download_encryption_key(
    session: Session, task_id: str, proposed_key: str
) -> str | FileTaskStatus | None:
    task = session.get(FileTask, task_id)
    if task is None:
        return None
    status = FileTaskStatus(task.status)
    if status != FileTaskStatus.IN_PROGRESS:
        return status
    if task.encryption_key is None:
        task.encryption_key = proposed_key
    return task.encryption_key


def complete_file_task(session: Session, task_id: str) -> FileTaskStatus | None:
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
    if result.rowcount == 1:
        return FileTaskStatus.COMPLETED
    task = session.get(FileTask, task_id)
    return None if task is None else FileTaskStatus(task.status)


def finalize_upload_task(
    session: Session,
    task_id: str,
    file_id: str,
    *,
    sha256: str | None,
    size: int,
) -> FileTaskStatus | None:
    task = session.get(FileTask, task_id)
    if task is None:
        return None
    file = session.get(File, file_id)
    if file is None:
        raise ValueError(f"File not found for file_id: {file_id}")

    status = complete_file_task(session, task_id)
    if status != FileTaskStatus.COMPLETED:
        return status

    task.upload_session_id = None
    task.upload_checkpoint_size = None
    task.upload_checkpoint_data = None
    file.sha256 = sha256
    file.size = size
    file.active = True
    return status


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
