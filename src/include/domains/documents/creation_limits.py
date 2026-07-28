import math
import threading
import time
from dataclasses import dataclass

from sqlalchemy import delete, exists, func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from include.config.validation import DocumentUploadPolicy
from include.database.models.documents import (
    Document,
    DocumentMetadata,
    DocumentRevision,
    EntityStatus,
)
from include.database.models.files import File, FileTask, FileTaskStatus, TransferMode
from include.database.models.operations import DocumentCreationThrottle

_creation_limit_lock = threading.Lock()
_last_cleanup_monotonic = 0.0


@dataclass(frozen=True, slots=True)
class CreationLimitDecision:
    allowed: bool
    scope: str | None = None
    limit: int | None = None
    retry_after_seconds: int | None = None


def _lock_throttle_row(
    session: Session, scope: str, identity: str, now: float
) -> DocumentCreationThrottle:
    statement = select(DocumentCreationThrottle).where(
        DocumentCreationThrottle.scope == scope,
        DocumentCreationThrottle.identity == identity,
    )
    if session.get_bind().dialect.name != "sqlite":
        statement = statement.with_for_update()
    row = session.scalar(statement)
    if row is not None:
        return row
    try:
        with session.begin_nested():
            row = DocumentCreationThrottle(
                scope=scope,
                identity=identity,
                window_started_at=now,
                attempts=0,
                last_attempt=now,
            )
            session.add(row)
            session.flush()
        return row
    except IntegrityError:
        row = session.scalar(statement)
        if row is None:
            raise
        return row


def _consume_window(
    row: DocumentCreationThrottle,
    *,
    now: float,
    window_seconds: int,
    limit: int,
) -> CreationLimitDecision:
    if now >= row.window_started_at + window_seconds:
        row.window_started_at = now
        row.attempts = 1
    else:
        row.attempts += 1
    row.last_attempt = now
    if row.attempts <= limit:
        return CreationLimitDecision(True)
    return CreationLimitDecision(
        False,
        scope=row.scope,
        limit=limit,
        retry_after_seconds=max(
            1, math.ceil(row.window_started_at + window_seconds - now)
        ),
    )


def count_pending_documents(session: Session, creator_username: str, now: float) -> int:
    active_revision = exists(
        select(DocumentRevision.id)
        .join(File, File.id == DocumentRevision.file_id)
        .where(
            DocumentRevision.document_id == Document.id,
            File.active.is_(True),
        )
    )
    live_upload = exists(
        select(FileTask.id)
        .join(File, File.id == FileTask.file_id)
        .join(DocumentRevision, DocumentRevision.file_id == File.id)
        .where(
            DocumentRevision.document_id == Document.id,
            FileTask.mode == TransferMode.UPLOAD,
            FileTask.status.in_((FileTaskStatus.PENDING, FileTaskStatus.IN_PROGRESS)),
            (FileTask.end_time.is_(None) | (FileTask.end_time > now)),
        )
    )
    return int(
        session.scalar(
            select(func.count(Document.id))
            .join(
                DocumentMetadata,
                DocumentMetadata.document_id == Document.id,
            )
            .where(
                Document.status == EntityStatus.OK,
                DocumentMetadata.creator_username == creator_username,
                ~active_revision,
                live_upload,
            )
        )
        or 0
    )


def check_document_creation_limits(
    session: Session,
    username: str,
    ip_address: str,
    *,
    bypass_rate_limit: bool = False,
    now: float | None = None,
) -> CreationLimitDecision:
    global _last_cleanup_monotonic

    if now is None:
        now = time.time()
    policy = DocumentUploadPolicy.from_config()
    with _creation_limit_lock:
        if (
            time.monotonic() - _last_cleanup_monotonic
            >= policy.creation_rate_window_seconds
        ):
            cutoff = now - policy.creation_rate_window_seconds
            session.execute(
                delete(DocumentCreationThrottle).where(
                    DocumentCreationThrottle.last_attempt < cutoff
                )
            )
            _last_cleanup_monotonic = time.monotonic()

        account_row = _lock_throttle_row(session, "account", username, now)
        if not bypass_rate_limit:
            account_decision = _consume_window(
                account_row,
                now=now,
                window_seconds=policy.creation_rate_window_seconds,
                limit=policy.creation_rate_per_user,
            )
            ip_row = _lock_throttle_row(session, "ip", ip_address, now)
            ip_decision = _consume_window(
                ip_row,
                now=now,
                window_seconds=policy.creation_rate_window_seconds,
                limit=policy.creation_rate_per_ip,
            )
            session.flush()
            if not account_decision.allowed:
                return account_decision
            if not ip_decision.allowed:
                return ip_decision

        pending_count = count_pending_documents(session, username, now)
        if pending_count >= policy.max_pending_documents_per_creator:
            nearest_deadline = session.scalar(
                select(func.min(FileTask.end_time))
                .join(File, File.id == FileTask.file_id)
                .join(DocumentRevision, DocumentRevision.file_id == File.id)
                .join(Document, Document.id == DocumentRevision.document_id)
                .join(
                    DocumentMetadata,
                    DocumentMetadata.document_id == Document.id,
                )
                .where(
                    DocumentMetadata.creator_username == username,
                    FileTask.mode == TransferMode.UPLOAD,
                    FileTask.status.in_(
                        (FileTaskStatus.PENDING, FileTaskStatus.IN_PROGRESS)
                    ),
                    FileTask.end_time > now,
                )
            )
            return CreationLimitDecision(
                False,
                scope="pending_documents",
                limit=policy.max_pending_documents_per_creator,
                retry_after_seconds=max(
                    1, math.ceil((nearest_deadline or now + 1) - now)
                ),
            )
        return CreationLimitDecision(True)
