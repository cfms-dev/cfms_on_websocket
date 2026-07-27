import threading
import time
from dataclasses import dataclass

from loguru import logger as log
from sqlalchemy import select, update

from include.config.validation import DocumentUploadPolicy
from include.database.models.documents import Document, DocumentRevision
from include.database.models.files import File, FileTask, FileTaskStatus, TransferMode
from include.database.session import Session
from include.domains.documents.commands.bulk_purge import purge_documents_bulk
from include.domains.documents.commands.file_tasks import ACTIVE_FILE_TASK_STATUSES
from include.domains.documents.file_task_signals import publish_cancelled_file_tasks

logger = log.bind(name="upload_lifecycle")


@dataclass(frozen=True, slots=True)
class UploadCleanupResult:
    expired_tasks: int = 0
    removed_revisions: int = 0
    removed_documents: int = 0


def _has_live_upload_for_document(
    session, document_id: str, excluded_task_id: str, now: float
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


def _document_has_active_revision(session, document_id: str) -> bool:
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


def expire_abandoned_uploads(now: float | None = None) -> UploadCleanupResult:
    if now is None:
        now = time.time()
    expired_task_ids: list[str] = []
    removed_revisions = 0
    removed_documents = 0

    with Session.begin() as session:
        due_tasks = session.execute(
            select(FileTask.id, FileTask.file_id, FileTask.mode).where(
                FileTask.status.in_(ACTIVE_FILE_TASK_STATUSES),
                FileTask.end_time.is_not(None),
                FileTask.end_time <= now,
            )
        ).all()

        for task_id, file_id, mode in due_tasks:
            claimed = session.execute(
                update(FileTask)
                .where(
                    FileTask.id == task_id,
                    FileTask.status.in_(ACTIVE_FILE_TASK_STATUSES),
                    FileTask.end_time.is_not(None),
                    FileTask.end_time <= now,
                )
                .values(status=FileTaskStatus.EXPIRED)
            )
            if claimed.rowcount != 1:
                continue
            expired_task_ids.append(task_id)
            if mode != TransferMode.UPLOAD:
                continue

            file = session.get(File, file_id)
            if file is None or file.active:
                continue
            revisions = list(
                session.scalars(
                    select(DocumentRevision).where(DocumentRevision.file_id == file_id)
                ).all()
            )
            for revision in revisions:
                document_id = revision.document_id
                if not _document_has_active_revision(
                    session, document_id
                ) and not _has_live_upload_for_document(
                    session, document_id, task_id, now
                ):
                    purge_documents_bulk(session, [document_id])
                    removed_documents += 1
                    break

                document = session.get(Document, document_id)
                if document is not None and document.current_revision_id == revision.id:
                    document.current_revision = revision.parent_revision
                revision.before_delete()
                session.delete(revision)
                removed_revisions += 1

    publish_cancelled_file_tasks(expired_task_ids)
    result = UploadCleanupResult(
        expired_tasks=len(expired_task_ids),
        removed_revisions=removed_revisions,
        removed_documents=removed_documents,
    )
    if result.expired_tasks:
        logger.info(
            "Expired {} file tasks; removed {} revisions and {} empty documents",
            result.expired_tasks,
            result.removed_revisions,
            result.removed_documents,
        )
    return result


class UploadLifecycleService:
    def __init__(self) -> None:
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run, name="upload-lifecycle", daemon=True
            )
            self._thread.start()

    def stop(self) -> None:
        with self._lock:
            thread = self._thread
            self._thread = None
            self._stop_event.set()
        if thread is not None:
            thread.join(timeout=5)

    def _run(self) -> None:
        while not self._stop_event.is_set():
            try:
                expire_abandoned_uploads()
            except Exception:
                logger.exception("Failed to clean up abandoned uploads")
            interval = DocumentUploadPolicy.from_config().cleanup_interval_seconds
            self._stop_event.wait(interval)


upload_lifecycle_service = UploadLifecycleService()
