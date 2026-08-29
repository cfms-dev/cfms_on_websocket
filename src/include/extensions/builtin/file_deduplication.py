import random
import secrets
import threading
import time
from dataclasses import dataclass
from typing import cast

from loguru import logger as log
from sqlalchemy import CursorResult, delete, or_, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session as OrmSession

from include.database.models.files import (
    File,
    FileDeduplicationPhase,
    FileDeduplicationTask,
    FileTask,
    FileTaskStatus,
    TransferMode,
)
from include.database.session import Session
from include.domains.documents.queries.file_references import _get_file_references
from include.providers.manager import ProviderManager

logger = log.bind(name="builtin.file_deduplication")

_HOOK_RECOVERY_SECONDS = 300.0
_LEASE_SECONDS = 300.0
_IDLE_POLL_SECONDS = 1.0
_SHUTDOWN_TIMEOUT_SECONDS = 10.0
_MAX_RETRY_SECONDS = 300.0
_LIVE_TASK_STATUSES = (FileTaskStatus.PENDING, FileTaskStatus.IN_PROGRESS)
_TERMINAL_TASK_STATUSES = (
    FileTaskStatus.COMPLETED,
    FileTaskStatus.CANCELLED,
    FileTaskStatus.EXPIRED,
)


@dataclass(frozen=True)
class ClaimedDeduplicationTask:
    file_id: str
    lease_owner: str
    recovered_lease: bool


def schedule_file_deduplication(
    session: OrmSession,
    file_id: str,
    *,
    now: float | None = None,
) -> None:
    """Persist deduplication work in the same transaction as upload completion."""
    timestamp = time.time() if now is None else now
    session.add(
        FileDeduplicationTask(
            file_id=file_id,
            phase=FileDeduplicationPhase.MERGE,
            available_at=timestamp + _HOOK_RECOVERY_SECONDS,
            attempts=0,
            created_time=timestamp,
        )
    )


def release_file_deduplication(file_id: str, *, now: float | None = None) -> bool:
    """Make post-upload work eligible after the client has received success."""
    timestamp = time.time() if now is None else now
    try:
        with Session() as session, session.begin():
            result = cast(
                CursorResult,
                session.execute(
                    update(FileDeduplicationTask)
                    .where(
                        FileDeduplicationTask.file_id == file_id,
                        FileDeduplicationTask.phase == FileDeduplicationPhase.MERGE,
                    )
                    .values(available_at=timestamp)
                ),
            )
        released = result.rowcount == 1
    except Exception:
        logger.exception(
            "Failed to release file deduplication task; recovery deadline remains"
        )
        return False

    if released:
        file_deduplication_worker.wake()
    return released


def _claim_next_task(now: float | None = None) -> ClaimedDeduplicationTask | None:
    timestamp = time.time() if now is None else now
    with Session() as session, session.begin():
        candidate = session.execute(
            select(
                FileDeduplicationTask.file_id,
                FileDeduplicationTask.lease_expires_at,
            )
            .where(
                FileDeduplicationTask.available_at <= timestamp,
                or_(
                    FileDeduplicationTask.lease_expires_at.is_(None),
                    FileDeduplicationTask.lease_expires_at <= timestamp,
                ),
            )
            .order_by(
                FileDeduplicationTask.available_at,
                FileDeduplicationTask.file_id,
            )
            .limit(1)
        ).first()
        if candidate is None:
            return None

        file_id, previous_lease_expires_at = candidate
        lease_owner = secrets.token_hex(32)
        result = cast(
            CursorResult,
            session.execute(
                update(FileDeduplicationTask)
                .where(
                    FileDeduplicationTask.file_id == file_id,
                    FileDeduplicationTask.available_at <= timestamp,
                    or_(
                        FileDeduplicationTask.lease_expires_at.is_(None),
                        FileDeduplicationTask.lease_expires_at <= timestamp,
                    ),
                )
                .values(
                    lease_owner=lease_owner,
                    lease_expires_at=timestamp + _LEASE_SECONDS,
                    attempts=FileDeduplicationTask.attempts + 1,
                )
            ),
        )
        if result.rowcount != 1:
            return None

    claim = ClaimedDeduplicationTask(
        file_id,
        lease_owner,
        recovered_lease=previous_lease_expires_at is not None,
    )
    if claim.recovered_lease:
        logger.bind(file_id=file_id).info("Recovered expired deduplication lease")
    return claim


def _get_claimed_task(
    session: OrmSession, claim: ClaimedDeduplicationTask
) -> FileDeduplicationTask | None:
    return session.scalar(
        select(FileDeduplicationTask)
        .where(
            FileDeduplicationTask.file_id == claim.file_id,
            FileDeduplicationTask.lease_owner == claim.lease_owner,
        )
        .with_for_update()
    )


def _process_merge(claim: ClaimedDeduplicationTask) -> bool:
    should_delete_storage = False
    with Session() as session, session.begin():
        task = _get_claimed_task(session, claim)
        if task is None:
            return False
        if FileDeduplicationPhase(task.phase) != FileDeduplicationPhase.MERGE:
            return (
                FileDeduplicationPhase(task.phase)
                == FileDeduplicationPhase.STORAGE_DELETE
            )

        source = session.scalar(
            select(File).where(File.id == claim.file_id).with_for_update()
        )
        if source is None or not source.active or not source.sha256:
            session.delete(task)
            return False

        matching_files = session.scalars(
            select(File)
            .where(File.sha256 == source.sha256, File.active == True)
            .order_by(File.created_time, File.id)
            .with_for_update()
        ).all()
        if not matching_files:
            session.delete(task)
            return False

        canonical = matching_files[0]
        if canonical.id == source.id:
            session.delete(task)
            return False

        if source.size is not None:
            canonical.size = source.size

        engine = cast(Engine, session.get_bind())
        for table, column_name in _get_file_references(engine):
            session.execute(
                update(table)
                .where(table.c[column_name] == source.id)
                .values({column_name: canonical.id})
            )

        session.execute(
            update(FileTask)
            .where(
                FileTask.file_id == source.id,
                FileTask.mode == TransferMode.DOWNLOAD,
                FileTask.status == FileTaskStatus.PENDING,
            )
            .values(file_id=canonical.id)
        )
        session.execute(
            delete(FileTask).where(
                FileTask.file_id == source.id,
                FileTask.status.in_(_TERMINAL_TASK_STATUSES),
            )
        )

        source.active = False
        task.phase = FileDeduplicationPhase.STORAGE_DELETE
        task.lease_expires_at = time.time() + _LEASE_SECONDS
        task.last_error = None
        should_delete_storage = True

        logger.bind(source_id=source.id, canonical_id=canonical.id).info(
            "Merged duplicate file references"
        )

    return should_delete_storage


def _defer_for_live_transfer(
    session: OrmSession,
    task: FileDeduplicationTask,
) -> None:
    task.available_at = time.time() + _IDLE_POLL_SECONDS
    task.lease_owner = None
    task.lease_expires_at = None


def _process_storage_delete(claim: ClaimedDeduplicationTask) -> None:
    with Session() as session, session.begin():
        task = _get_claimed_task(session, claim)
        if task is None:
            return
        if FileDeduplicationPhase(task.phase) != FileDeduplicationPhase.STORAGE_DELETE:
            return

        source = session.scalar(
            select(File).where(File.id == claim.file_id).with_for_update()
        )
        if source is None:
            session.delete(task)
            return

        live_task = session.scalar(
            select(FileTask.id)
            .where(
                FileTask.file_id == source.id,
                FileTask.status.in_(_LIVE_TASK_STATUSES),
            )
            .limit(1)
        )
        if live_task is not None:
            _defer_for_live_transfer(session, task)
            return

        source_path = source.path
        task.lease_expires_at = time.time() + _LEASE_SECONDS

    storage = ProviderManager().storage
    try:
        removed = storage.remove(source_path)
        if not removed and storage.exists(source_path):
            raise OSError(f"Storage provider did not remove {source_path!r}")
    except FileNotFoundError:
        pass

    with Session() as session, session.begin():
        task = _get_claimed_task(session, claim)
        if task is None:
            return
        if FileDeduplicationPhase(task.phase) != FileDeduplicationPhase.STORAGE_DELETE:
            return

        source = session.scalar(
            select(File).where(File.id == claim.file_id).with_for_update()
        )
        if source is None:
            session.delete(task)
            return

        live_task = session.scalar(
            select(FileTask.id)
            .where(
                FileTask.file_id == source.id,
                FileTask.status.in_(_LIVE_TASK_STATUSES),
            )
            .limit(1)
        )
        if live_task is not None:
            _defer_for_live_transfer(session, task)
            return

        session.execute(delete(FileTask).where(FileTask.file_id == source.id))
        session.delete(task)
        session.delete(source)

        logger.bind(file_id=source.id, path=source_path).info(
            "Removed duplicate file from storage"
        )


def _reschedule_failed_task(
    claim: ClaimedDeduplicationTask,
    error: Exception,
) -> None:
    try:
        with Session() as session, session.begin():
            task = _get_claimed_task(session, claim)
            if task is None:
                return
            retry_seconds = min(
                _MAX_RETRY_SECONDS,
                2.0 ** min(max(task.attempts - 1, 0), 8),
            )
            task.available_at = time.time() + retry_seconds * random.uniform(1.0, 1.2)
            task.lease_owner = None
            task.lease_expires_at = None
            task.last_error = str(error)
    except Exception:
        logger.exception("Failed to reschedule file deduplication task")
        return

    logger.bind(file_id=claim.file_id, retry_seconds=retry_seconds).exception(
        "File deduplication task failed and was rescheduled"
    )


def process_one_file_deduplication_task() -> bool:
    claim = _claim_next_task()
    if claim is None:
        return False

    try:
        with Session() as session:
            task = _get_claimed_task(session, claim)
            if task is None:
                return True
            phase = FileDeduplicationPhase(task.phase)

        if phase == FileDeduplicationPhase.MERGE:
            if _process_merge(claim):
                _process_storage_delete(claim)
        else:
            _process_storage_delete(claim)
    except Exception as error:  # noqa: BLE001
        _reschedule_failed_task(claim, error)

    return True


class FileDeduplicationWorker:
    def __init__(self) -> None:
        self._lifecycle_lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._wake.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="file-deduplication-worker",
                daemon=True,
            )
            self._thread.start()

    def stop(self, timeout: float = _SHUTDOWN_TIMEOUT_SECONDS) -> None:
        with self._lifecycle_lock:
            thread = self._thread
            if thread is None:
                return
            self._stop.set()
            self._wake.set()
        thread.join(timeout)
        with self._lifecycle_lock:
            if self._thread is thread and not thread.is_alive():
                self._thread = None

    def wake(self) -> None:
        self._wake.set()

    def _run(self) -> None:
        while not self._stop.is_set():
            try:
                processed = process_one_file_deduplication_task()
            except Exception:
                logger.exception("Unexpected file deduplication worker failure")
                processed = False

            if not processed:
                self._wake.wait(_IDLE_POLL_SECONDS)
                self._wake.clear()


file_deduplication_worker = FileDeduplicationWorker()
