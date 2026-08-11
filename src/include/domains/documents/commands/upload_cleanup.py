import threading
import time
from dataclasses import dataclass
from typing import Any, cast

from loguru import logger as log
from sqlalchemy import and_, delete, or_, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session as ORMSession

from include.config.validation import DocumentUploadPolicy
from include.database.models.documents import Document, DocumentRevision
from include.database.models.files import (
    File,
    FileTask,
    FileTaskStatus,
    TransferMode,
    _queue_deferred_file_deletion,
)
from include.database.session import Session
from include.domains.documents.commands.bulk_purge import purge_documents_bulk
from include.domains.documents.commands.file_tasks import (
    ACTIVE_FILE_TASK_STATUSES,
    expire_file_task_if_due,
)
from include.domains.documents.file_task_signals import publish_cancelled_file_tasks

logger = log.bind(name="upload_cleanup")
_opportunistic_cleanup_lock = threading.Lock()
_last_opportunistic_cleanup = 0.0
_OPPORTUNISTIC_CLEANUP_BATCH_SIZE = 256


@dataclass(frozen=True, slots=True)
class UploadCleanupResult:
    matched_tasks: int = 0
    expired_tasks: int = 0
    removed_revisions: int = 0
    removed_documents: int = 0
    storage_cleanup_failures: int = 0


def _has_live_upload_for_document(
    session: ORMSession, document_id: str, excluded_task_id: str, now: float
) -> bool:
    return (
        session.scalar(
            select(FileTask.id)
            .join(File, File.id == FileTask.file_id)
            .join(DocumentRevision, DocumentRevision.file_id == File.id)
            .where(
                DocumentRevision.document_id == document_id,
                FileTask.id != excluded_task_id,
                FileTask.mode == TransferMode.UPLOAD,
                FileTask.status.in_(ACTIVE_FILE_TASK_STATUSES),
                (FileTask.end_time.is_(None) | (FileTask.end_time > now)),
            )
            .limit(1)
        )
        is not None
    )


def _document_has_active_revision(session: ORMSession, document_id: str) -> bool:
    return (
        session.scalar(
            select(DocumentRevision.id)
            .join(File, File.id == DocumentRevision.file_id)
            .where(
                DocumentRevision.document_id == document_id,
                File.active.is_(True),
            )
            .limit(1)
        )
        is not None
    )


def _find_cleanup_candidates(
    session: ORMSession,
    now: float,
    *,
    document_id: str | None,
    folder_id: str | None,
    title: str | None,
    limit: int | None,
) -> list[tuple[str, str, FileTaskStatus]]:
    statement = (
        select(FileTask.id, FileTask.file_id, FileTask.status)
        .join(File, File.id == FileTask.file_id)
        .join(DocumentRevision, DocumentRevision.file_id == File.id)
        .join(Document, Document.id == DocumentRevision.document_id)
        .where(
            FileTask.mode == TransferMode.UPLOAD,
            or_(
                and_(
                    FileTask.status.in_(ACTIVE_FILE_TASK_STATUSES),
                    FileTask.end_time.is_not(None),
                    FileTask.end_time <= now,
                ),
                and_(
                    FileTask.status == FileTaskStatus.EXPIRED,
                    File.active.is_(False),
                ),
            ),
        )
        .distinct()
        .order_by(FileTask.end_time, FileTask.id)
    )
    if document_id is not None:
        statement = statement.where(DocumentRevision.document_id == document_id)
    if folder_id is not None:
        statement = statement.where(Document.folder_id == folder_id)
    if title is not None:
        statement = statement.where(Document.title == title)
    if limit is not None:
        statement = statement.limit(limit)
    return [
        (task_id, file_id, FileTaskStatus(status))
        for task_id, file_id, status in session.execute(statement).all()
    ]


def reclaim_abandoned_uploads(
    now: float | None = None,
    *,
    document_id: str | None = None,
    folder_id: str | None = None,
    title: str | None = None,
    limit: int | None = None,
) -> UploadCleanupResult:
    if now is None:
        now = time.time()
    expired_task_ids: list[str] = []
    cancelled_task_ids: list[str] = []
    removed_revisions = 0
    removed_documents = 0

    with Session.begin() as session:
        candidates = _find_cleanup_candidates(
            session,
            now,
            document_id=document_id,
            folder_id=folder_id,
            title=title,
            limit=limit,
        )
        for task_id, file_id, original_status in candidates:
            status = expire_file_task_if_due(session, task_id, now=now)
            if status != FileTaskStatus.EXPIRED:
                continue
            if original_status != FileTaskStatus.EXPIRED:
                expired_task_ids.append(task_id)
                cancelled_task_ids.append(task_id)

            file = session.get(File, file_id)
            if file is None or file.active:
                continue
            task = session.get(FileTask, task_id)
            if task is not None and task.upload_session_id is not None:
                _queue_deferred_file_deletion(
                    session, file.path, (task.upload_session_id,)
                )
            claimed = cast(
                CursorResult[Any],
                session.execute(
                    delete(FileTask).where(
                        FileTask.id == task_id,
                        FileTask.status == FileTaskStatus.EXPIRED,
                    )
                ),
            )
            if claimed.rowcount != 1:
                continue
            if task_id not in cancelled_task_ids:
                cancelled_task_ids.append(task_id)
            revisions = list(
                session.scalars(
                    select(DocumentRevision).where(DocumentRevision.file_id == file_id)
                ).all()
            )
            for revision in revisions:
                document_id_for_revision = revision.document_id
                if not _document_has_active_revision(
                    session, document_id_for_revision
                ) and not _has_live_upload_for_document(
                    session, document_id_for_revision, task_id, now
                ):
                    purge_documents_bulk(session, [document_id_for_revision])
                    removed_documents += 1
                    break

                document = session.get(Document, document_id_for_revision)
                if document is not None and document.current_revision_id == revision.id:
                    document.current_revision = revision.parent_revision
                revision.before_delete()
                session.delete(revision)
                removed_revisions += 1

    storage_cleanup_failures = int(session.info.pop("deferred_delete_failure_count", 0))
    publish_cancelled_file_tasks(cancelled_task_ids)
    result = UploadCleanupResult(
        matched_tasks=len(candidates),
        expired_tasks=len(expired_task_ids),
        removed_revisions=removed_revisions,
        removed_documents=removed_documents,
        storage_cleanup_failures=storage_cleanup_failures,
    )
    if result.matched_tasks:
        logger.bind(
            matched_tasks=result.matched_tasks,
            expired_tasks=result.expired_tasks,
            removed_revisions=result.removed_revisions,
            removed_documents=result.removed_documents,
            storage_cleanup_failures=result.storage_cleanup_failures,
        ).info("Abandoned upload cleanup completed")
    return result


def try_reclaim_abandoned_uploads(
    now: float | None = None,
    *,
    document_id: str | None = None,
    folder_id: str | None = None,
    title: str | None = None,
    limit: int | None = None,
) -> UploadCleanupResult | None:
    try:
        return reclaim_abandoned_uploads(
            now,
            document_id=document_id,
            folder_id=folder_id,
            title=title,
            limit=limit,
        )
    except Exception:
        logger.exception("Failed to reclaim abandoned uploads")
        return None


def maybe_reclaim_abandoned_uploads() -> UploadCleanupResult | None:
    global _last_opportunistic_cleanup

    interval = DocumentUploadPolicy.from_config().cleanup_interval_seconds
    if time.monotonic() - _last_opportunistic_cleanup < interval:
        return None
    if not _opportunistic_cleanup_lock.acquire(blocking=False):
        return None
    try:
        if time.monotonic() - _last_opportunistic_cleanup < interval:
            return None
        return try_reclaim_abandoned_uploads(limit=_OPPORTUNISTIC_CLEANUP_BATCH_SIZE)
    finally:
        _last_opportunistic_cleanup = time.monotonic()
        _opportunistic_cleanup_lock.release()
