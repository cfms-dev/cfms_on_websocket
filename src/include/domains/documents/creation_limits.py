import math
import time
from dataclasses import dataclass

from loguru import logger
from sqlalchemy import exists, func, select
from sqlalchemy.orm import Session

from include.config.validation import (
    DocumentCreationRiskPolicy,
    DocumentUploadPolicy,
)
from include.database.models.documents import (
    Document,
    DocumentMetadata,
    DocumentRevision,
    EntityStatus,
)
from include.database.models.files import File, FileTask, FileTaskStatus, TransferMode
from include.domains.documents.creation_risk import (
    CreationRiskAssessment,
    CreationRiskLevel,
    CreationRiskSignals,
    assess_creation_risk,
)
from include.domains.security.guards.rate_limits import (
    cleanup_rate_limit_state,
    consume_bucket,
    count_ip_accounts,
    lock_rate_bucket,
    rate_limit_lock,
    record_denial,
    record_ip_account,
    refresh_denials,
    touch_rate_bucket,
)

_RISK_NAMESPACE = "document_creation"
_last_cleanup_monotonic = 0.0


@dataclass(frozen=True, slots=True)
class CreationLimitDecision:
    allowed: bool
    scope: str | None = None
    limit: int | None = None
    retry_after_seconds: int | None = None
    risk_level: CreationRiskLevel | None = None
    risk_reasons: tuple[str, ...] = ()
    would_block: bool = False


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


def _pending_limit_decision(
    session: Session,
    username: str,
    now: float,
    pending_count: int,
    limit: int,
) -> CreationLimitDecision | None:
    if pending_count < limit:
        return None
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
            FileTask.status.in_((FileTaskStatus.PENDING, FileTaskStatus.IN_PROGRESS)),
            FileTask.end_time > now,
        )
    )
    return CreationLimitDecision(
        False,
        scope="pending_documents",
        limit=limit,
        retry_after_seconds=max(1, math.ceil((nearest_deadline or now + 1) - now)),
    )


def _risk_cost(
    assessment: CreationRiskAssessment, policy: DocumentCreationRiskPolicy
) -> int:
    if assessment.level == CreationRiskLevel.HIGH:
        return policy.high_cost
    if assessment.level == CreationRiskLevel.ELEVATED:
        return policy.elevated_cost
    return 1


def _maybe_cleanup(
    session: Session,
    now: float,
    upload_policy: DocumentUploadPolicy,
    risk_policy: DocumentCreationRiskPolicy,
) -> None:
    global _last_cleanup_monotonic

    monotonic_now = time.monotonic()
    if monotonic_now - _last_cleanup_monotonic < upload_policy.cleanup_interval_seconds:
        return
    cleanup_rate_limit_state(
        session,
        _RISK_NAMESPACE,
        ip_account_cutoff=now - risk_policy.ip_account_window_seconds,
        bucket_cutoff=now - risk_policy.state_retention_seconds,
    )
    _last_cleanup_monotonic = monotonic_now


def check_document_creation_limits(
    session: Session,
    username: str,
    ip_address: str,
    *,
    account_created_at: float | None = None,
    bypass_rate_limit: bool = False,
    now: float | None = None,
) -> CreationLimitDecision:
    if now is None:
        now = time.time()
    upload_policy = DocumentUploadPolicy.from_config()
    risk_policy = DocumentCreationRiskPolicy.from_config()

    with rate_limit_lock:
        _maybe_cleanup(session, now, upload_policy, risk_policy)
        account_bucket = lock_rate_bucket(
            session,
            _RISK_NAMESPACE,
            "account",
            username,
            now,
            risk_policy.account_capacity,
        )
        touch_rate_bucket(session, account_bucket, now)
        session.flush()
        pending_count = count_pending_documents(session, username, now)
        pending_decision = _pending_limit_decision(
            session,
            username,
            now,
            pending_count,
            upload_policy.max_pending_documents_per_creator,
        )
        if bypass_rate_limit:
            return pending_decision or CreationLimitDecision(True)

        ip_bucket = lock_rate_bucket(
            session,
            _RISK_NAMESPACE,
            "ip",
            ip_address,
            now,
            risk_policy.ip_capacity,
        )
        record_ip_account(session, _RISK_NAMESPACE, ip_address, username, now)
        refresh_denials(account_bucket, now, risk_policy.denial_window_seconds)
        refresh_denials(ip_bucket, now, risk_policy.denial_window_seconds)
        ip_account_count = count_ip_accounts(
            session,
            _RISK_NAMESPACE,
            ip_address,
            now - risk_policy.ip_account_window_seconds,
        )
        assessment = assess_creation_risk(
            CreationRiskSignals(
                new_account=(
                    account_created_at is None
                    or now - account_created_at < risk_policy.new_account_seconds
                ),
                pending_ratio=(
                    pending_count / upload_policy.max_pending_documents_per_creator
                ),
                ip_account_count=ip_account_count,
                denial_count=max(
                    account_bucket.denial_count,
                    ip_bucket.denial_count,
                ),
            ),
            risk_policy,
        )
        cost = _risk_cost(assessment, risk_policy)
        account_decision = consume_bucket(
            account_bucket,
            now=now,
            capacity=risk_policy.account_capacity,
            refill_tokens=risk_policy.account_refill_tokens,
            refill_period_seconds=risk_policy.refill_period_seconds,
            cost=cost,
        )
        ip_decision = consume_bucket(
            ip_bucket,
            now=now,
            capacity=risk_policy.ip_capacity,
            refill_tokens=risk_policy.ip_refill_tokens,
            refill_period_seconds=risk_policy.refill_period_seconds,
            cost=cost,
        )
        denied = [
            decision
            for decision in (account_decision, ip_decision)
            if not decision.allowed
        ]
        would_block = bool(denied)
        if would_block:
            record_denial(account_bucket, now, risk_policy.denial_window_seconds)
            record_denial(ip_bucket, now, risk_policy.denial_window_seconds)
        session.flush()

        if assessment.level != CreationRiskLevel.NORMAL or would_block:
            log = logger.bind(
                name="document_creation_risk",
                username=username,
                remote_address=ip_address,
                risk_level=assessment.level.value,
                risk_reasons=assessment.reasons,
                mode=risk_policy.mode,
                would_block=would_block,
            )
            if would_block or assessment.level == CreationRiskLevel.HIGH:
                log.warning("Document creation risk evaluated")
            else:
                log.info("Document creation risk evaluated")

        if would_block and risk_policy.mode == "enforce":
            limiting = max(denied, key=lambda decision: decision.retry_after_seconds)
            return CreationLimitDecision(
                False,
                scope=limiting.scope,
                limit=limiting.effective_limit,
                retry_after_seconds=limiting.retry_after_seconds,
                risk_level=assessment.level,
                risk_reasons=assessment.reasons,
                would_block=True,
            )
        if pending_decision is not None:
            return pending_decision
        return CreationLimitDecision(
            True,
            risk_level=assessment.level,
            risk_reasons=assessment.reasons,
            would_block=would_block,
        )
