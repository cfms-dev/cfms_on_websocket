import secrets
import sys
import time
from enum import IntEnum

from loguru import logger as log
from sqlalchemy import (
    VARCHAR,
    BigInteger,
    Boolean,
    CheckConstraint,
    Float,
    ForeignKey,
    Index,
    Integer,
    Text,
    event,
    select,
)
from sqlalchemy.orm import Mapped, Session, mapped_column, relationship
from sqlalchemy.orm.session import object_session

from include.database.session import Base
from include.providers.manager import ProviderManager
from include.providers.storage import LocalStorageProvider

logger = log.bind(name="database.file")


class TransferMode(IntEnum):
    DOWNLOAD = 0
    UPLOAD = 1


class FileTaskStatus(IntEnum):
    PENDING = 0
    COMPLETED = 1
    CANCELLED = 2
    IN_PROGRESS = 3
    EXPIRED = 4


class FileDeduplicationPhase(IntEnum):
    MERGE = 0
    STORAGE_DELETE = 1


def _queue_deferred_file_deletion(
    session: Session, path: str, upload_session_ids: tuple[str, ...] = ()
) -> None:
    """Queue a file path for physical deletion after the session's next successful commit.

    This ensures filesystem changes only happen after the DB transaction is committed,
    preventing orphaned DB records if ``os.remove`` raises, and preventing deleted files
    when the DB transaction rolls back.

    On rollback the queue is cleared so no files are ever removed.
    """
    pending: list = session.info.setdefault("pending_delete_files", [])
    pending.append((path, upload_session_ids))

    # Register lifecycle hooks only once per session instance to avoid duplicate callbacks.
    if not session.info.get("_deferred_delete_hooks_registered"):
        session.info["_deferred_delete_hooks_registered"] = True

        @event.listens_for(session, "after_commit")
        def _do_deferred_file_deletes(session: Session):
            paths = session.info.pop("pending_delete_files", [])
            for pending_path, pending_upload_session_ids in paths:
                for upload_session_id in pending_upload_session_ids:
                    try:
                        ProviderManager().storage.abort_resumable_upload(
                            pending_path, upload_session_id
                        )
                    except Exception as exc:  # noqa: BLE001 - cleanup is post-commit.
                        logger.warning(  # noqa: PLE1205 - Loguru uses brace formatting.
                            "Failed to abort upload session after commit: {} — {}",
                            upload_session_id,
                            exc,
                        )
                        session.info["deferred_delete_failure_count"] = (
                            session.info.get("deferred_delete_failure_count", 0) + 1
                        )
                try:
                    ProviderManager().storage.remove(pending_path)
                except FileNotFoundError:
                    pass  # already removed manually — this is fine
                except Exception as exc:  # noqa: BLE001 - provider cleanup is post-commit.
                    # The DB record has already been deleted, so cleanup cannot change
                    # the committed result. Log the orphan for operator recovery.
                    logger.warning(  # noqa: PLE1205 - Loguru uses brace-style formatting.
                        "Failed to remove file after commit (orphaned file): {} — {}",
                        pending_path,
                        exc,
                    )
                    session.info["deferred_delete_failure_count"] = (
                        session.info.get("deferred_delete_failure_count", 0) + 1
                    )

        @event.listens_for(session, "after_rollback")
        def _clear_deferred_file_deletes(session: Session):
            # Discard queued paths so they are never removed on a failed transaction.
            session.info.pop("pending_delete_files", None)


class File(Base):
    __tablename__ = "files"
    __table_args__ = (
        Index(
            "ix_files_sha256_active_created_time_id",
            "sha256",
            "active",
            "created_time",
            "id",
        ),
    )
    id: Mapped[str] = mapped_column(
        VARCHAR(255), primary_key=True, default=lambda: secrets.token_hex(32)
    )

    sha256: Mapped[str | None] = mapped_column(VARCHAR(64), nullable=True)
    # calculate sha256 takes time, especially for large files lol
    #
    # there are also a lot of situations where sha256 in the database is null
    # or mismatch, so don't use it as a must

    path: Mapped[str] = mapped_column(Text, nullable=False)
    _size: Mapped[int | None] = mapped_column("size", BigInteger, nullable=True)
    created_time: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time()
    )
    tasks: Mapped[list["FileTask"]] = relationship(
        "FileTask", back_populates="file", cascade="all, delete-orphan"
    )
    active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    @property
    def size(self) -> int | None:
        """File size in bytes.

        The file size will be obtained from the database first;
        If not set, attempts to retrieve it from the storage provider.

        Users should note that if they want to obtain the current actual size
        of the physical file, they should directly call the
        StorageProvider().getsize() method, which is a function with high I/O
        overhead.
        """

        if self._size is not None:
            return self._size
        try:
            return ProviderManager().storage.getsize(self.path)
        except Exception:  # noqa: BLE001 - storage backends expose provider-specific failures.
            return None

    @size.setter
    def size(self, value: int | None) -> None:
        self._size = value

    @property
    def writeable(self):
        if not isinstance(ProviderManager().storage, LocalStorageProvider):
            return True

        if sys.platform == "win32":
            import pywintypes
            import win32file

            hFile = None
            try:
                if ProviderManager().storage.exists(self.path):
                    hFile = win32file.CreateFile(
                        self.path,
                        win32file.GENERIC_READ + win32file.GENERIC_WRITE,
                        win32file.FILE_SHARE_READ,
                        None,
                        win32file.OPEN_ALWAYS,
                        0,
                        None,
                    )
            except pywintypes.error:
                return False
            finally:
                if hFile:
                    hFile.Close()

        return True

    def delete(self):
        """Remove this file from disk and clean up its associated FileTask records.

        When called within a DB session the physical ``os.remove`` is deferred until
        after the session commits successfully (via ``_queue_deferred_file_deletion``),
        so a DB rollback never leaves the filesystem in an inconsistent state.

        For bulk deletions prefer batching the FileTask cleanup upstream (using
        ``FileTask.file_id.in_(chunk)`` across all files at once) and calling
        ``_queue_deferred_file_deletion`` directly — this method is intended for
        single-file standalone use.
        """
        session = object_session(self)
        if session is not None:
            upload_session_ids = tuple(
                upload_session_id
                for upload_session_id in session.scalars(
                    select(FileTask.upload_session_id).where(
                        FileTask.file_id == self.id,
                        FileTask.upload_session_id.is_not(None),
                    )
                ).all()
                if upload_session_id is not None
            )
            # Remove associated task records as part of the DB transaction.
            session.query(FileTask).filter(FileTask.file_id == self.id).delete(
                synchronize_session=False
            )  # be careful
            # Defer physical file removal until after a successful commit.
            _queue_deferred_file_deletion(session, self.path, upload_session_ids)
        else:
            # No session context — perform immediate deletion.
            try:
                ProviderManager().storage.remove(self.path)
            except FileNotFoundError:
                pass

    def get_latest_task(self):
        """
        Return the latest task that has not ended, including tasks not yet started.

        Tasks are ordered by their start time.
        """

        now = time.time()
        active_tasks = [
            task
            for task in self.tasks
            if (task.end_time and now < task.end_time) or not task.end_time
        ]

        return (
            max(active_tasks, key=lambda task: task.start_time)
            if active_tasks
            else None
        )

    def __repr__(self) -> str:
        return f"File(id={self.id!r}, file_path={self.path!r}, created_time={self.created_time!r})"


class FileTask(Base):
    __tablename__ = "file_tasks"
    __table_args__ = (
        CheckConstraint("status IN (0, 1, 2, 3, 4)", name="ck_file_tasks_status_value"),
        Index("ix_file_tasks_file_id_mode_status", "file_id", "mode", "status"),
        Index("ix_file_tasks_mode_status_end_time", "mode", "status", "end_time"),
    )
    id: Mapped[str] = mapped_column(
        VARCHAR(255), primary_key=True, default=lambda: secrets.token_hex(32)
    )
    file_id: Mapped[str] = mapped_column(
        VARCHAR(255), ForeignKey("files.id", ondelete="CASCADE"), nullable=False
    )
    status: Mapped[FileTaskStatus] = mapped_column(
        Integer, nullable=False, default=FileTaskStatus.PENDING
    )
    mode: Mapped[int] = mapped_column(
        Integer, nullable=False, comment="0: download, 1: upload"
    )
    start_time: Mapped[float] = mapped_column(Float, nullable=False)
    end_time: Mapped[float | None] = mapped_column(Float, nullable=True)

    issued_by_username: Mapped[str | None] = mapped_column(
        VARCHAR(256),
        ForeignKey("users.username", ondelete="SET NULL"),
        nullable=True,
    )

    # Attribution does not bind the bearer task to this account. A sufficiently
    # long random task ID remains the transfer credential and may be forwarded.

    # Encryption key will be generated when a download task is initiated for
    # the first time.
    encryption_key: Mapped[str | None] = mapped_column(
        VARCHAR(256), nullable=True, default=None
    )

    # A negotiated chunk size stays fixed for the lifetime of either upload or
    # download tasks so resume offsets retain one unambiguous alignment.
    chunk_size: Mapped[int | None] = mapped_column(Integer, nullable=True, default=None)

    upload_file_size: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    upload_sha256: Mapped[str | None] = mapped_column(VARCHAR(64), nullable=True)
    upload_session_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    upload_checkpoint_size: Mapped[int | None] = mapped_column(
        BigInteger, nullable=True
    )

    # encryption_mode: Mapped[str | None] = mapped_column(
    #     VARCHAR(32), nullable=True, default=None
    # )  # Encryption mode, such as 'AES' or 'RSA'; None means unencrypted.

    file: Mapped["File"] = relationship("File", back_populates="tasks")

    def __repr__(self) -> str:
        return (
            f"FileTask(id={self.id!r}, "
            f"file_id={self.file_id!r}, status={self.status!r})"
        )


class FileDeduplicationTask(Base):
    __tablename__ = "file_deduplication_tasks"
    __table_args__ = (
        CheckConstraint(
            "phase IN (0, 1)", name="ck_file_deduplication_tasks_phase_value"
        ),
        Index(
            "ix_file_deduplication_tasks_available_lease",
            "available_at",
            "lease_expires_at",
        ),
    )

    file_id: Mapped[str] = mapped_column(
        VARCHAR(255),
        ForeignKey("files.id", ondelete="CASCADE"),
        primary_key=True,
    )
    phase: Mapped[FileDeduplicationPhase] = mapped_column(
        Integer, nullable=False, default=FileDeduplicationPhase.MERGE
    )
    available_at: Mapped[float] = mapped_column(Float, nullable=False)
    lease_owner: Mapped[str | None] = mapped_column(VARCHAR(64), nullable=True)
    lease_expires_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_time: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time()
    )
