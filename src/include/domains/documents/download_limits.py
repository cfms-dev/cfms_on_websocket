import time
from dataclasses import dataclass

from loguru import logger
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from include.config.validation import DocumentDownloadRiskPolicy
from include.database.models.files import FileTask, FileTaskStatus, TransferMode
from include.domains.documents.download_risk import (
    DownloadRiskAssessment,
    DownloadRiskLevel,
    DownloadRiskSignals,
    assess_download_risk,
)
from include.domains.security.guards.rate_limits import (
    BucketDecision,
    RateLimitCleanupCounts,
    cleanup_rate_limit_state,
    consume_bucket,
    count_ip_accounts,
    lock_rate_bucket,
    record_denial,
    record_ip_account,
    refresh_denials,
)

_ISSUE_NAMESPACE = "download_issue"
_TRANSFER_NAMESPACE = "download_transfer"


@dataclass(frozen=True, slots=True)
class DownloadLimitDecision:
    allowed: bool
    scope: str | None = None
    limit: int | None = None
    retry_after_seconds: int | None = None
    risk_level: DownloadRiskLevel | None = None
    risk_reasons: tuple[str, ...] = ()
    would_block: bool = False
    active_downloads: int | None = None


def _risk_cost(
    assessment: DownloadRiskAssessment, policy: DocumentDownloadRiskPolicy
) -> int:
    if assessment.level == DownloadRiskLevel.HIGH:
        return policy.high_cost
    if assessment.level == DownloadRiskLevel.ELEVATED:
        return policy.elevated_cost
    return 1


def cleanup_document_download_risk_state(
    session: Session,
    *,
    now: float | None = None,
) -> RateLimitCleanupCounts:
    current_time = time.time() if now is None else now
    policy = DocumentDownloadRiskPolicy.from_config()
    counts = [
        cleanup_rate_limit_state(
            session,
            namespace,
            ip_account_cutoff=current_time - policy.ip_account_window_seconds,
            bucket_cutoff=current_time - policy.state_retention_seconds,
        )
        for namespace in (_ISSUE_NAMESPACE, _TRANSFER_NAMESPACE)
    ]
    return RateLimitCleanupCounts(
        ip_accounts=sum(item.ip_accounts for item in counts),
        buckets=sum(item.buckets for item in counts),
    )


def _active_download_count(session: Session, now: float) -> int:
    return int(
        session.scalar(
            select(func.count(FileTask.id)).where(
                FileTask.mode == TransferMode.DOWNLOAD,
                FileTask.status == FileTaskStatus.IN_PROGRESS,
                (FileTask.end_time.is_(None) | (FileTask.end_time > now)),
            )
        )
        or 0
    )


def _check_download_limits(
    session: Session,
    *,
    namespace: str,
    username: str | None,
    ip_address: str,
    account_created_at: float | None,
    task_id: str | None,
    bypass_rate_limit: bool,
    now: float,
) -> DownloadLimitDecision:
    policy = DocumentDownloadRiskPolicy.from_config()
    active_downloads = (
        _active_download_count(session, now)
        if namespace == _TRANSFER_NAMESPACE
        else None
    )
    if bypass_rate_limit:
        return DownloadLimitDecision(True, active_downloads=active_downloads)

    buckets = []
    account_bucket = None
    if username is not None:
        capacity = (
            policy.issue_account_capacity
            if namespace == _ISSUE_NAMESPACE
            else policy.transfer_account_capacity
        )
        account_bucket = lock_rate_bucket(
            session, namespace, "account", username, now, capacity
        )
        buckets.append(account_bucket)

    ip_capacity = (
        policy.issue_ip_capacity
        if namespace == _ISSUE_NAMESPACE
        else policy.transfer_ip_capacity
    )
    ip_bucket = lock_rate_bucket(session, namespace, "ip", ip_address, now, ip_capacity)
    buckets.append(ip_bucket)

    task_bucket = None
    if task_id is not None:
        task_bucket = lock_rate_bucket(
            session,
            namespace,
            "task",
            task_id,
            now,
            policy.task_capacity,
        )
        buckets.append(task_bucket)

    if username is not None:
        record_ip_account(session, namespace, ip_address, username, now)
    for bucket in buckets:
        refresh_denials(bucket, now, policy.denial_window_seconds)

    assessment = assess_download_risk(
        DownloadRiskSignals(
            new_account=(
                username is not None
                and (
                    account_created_at is None
                    or now - account_created_at < policy.new_account_seconds
                )
            ),
            ip_account_count=(
                count_ip_accounts(
                    session,
                    namespace,
                    ip_address,
                    now - policy.ip_account_window_seconds,
                )
                if username is not None
                else 0
            ),
            denial_count=max((bucket.denial_count for bucket in buckets), default=0),
        ),
        policy,
    )
    cost = _risk_cost(assessment, policy)
    decisions: list[BucketDecision] = []
    if account_bucket is not None:
        decisions.append(
            consume_bucket(
                account_bucket,
                now=now,
                capacity=(
                    policy.issue_account_capacity
                    if namespace == _ISSUE_NAMESPACE
                    else policy.transfer_account_capacity
                ),
                refill_tokens=(
                    policy.issue_account_refill_tokens
                    if namespace == _ISSUE_NAMESPACE
                    else policy.transfer_account_refill_tokens
                ),
                refill_period_seconds=policy.refill_period_seconds,
                cost=cost,
            )
        )
    decisions.append(
        consume_bucket(
            ip_bucket,
            now=now,
            capacity=ip_capacity,
            refill_tokens=(
                policy.issue_ip_refill_tokens
                if namespace == _ISSUE_NAMESPACE
                else policy.transfer_ip_refill_tokens
            ),
            refill_period_seconds=policy.refill_period_seconds,
            cost=cost,
        )
    )
    if task_bucket is not None:
        decisions.append(
            consume_bucket(
                task_bucket,
                now=now,
                capacity=policy.task_capacity,
                refill_tokens=policy.task_refill_tokens,
                refill_period_seconds=policy.task_refill_period_seconds,
                cost=1,
            )
        )

    denied = [decision for decision in decisions if not decision.allowed]
    would_block = bool(denied)
    if would_block:
        for bucket in buckets:
            record_denial(bucket, now, policy.denial_window_seconds)
    session.flush()

    phase = "issue" if namespace == _ISSUE_NAMESPACE else "transfer"
    if assessment.level != DownloadRiskLevel.NORMAL or would_block:
        log = logger.bind(
            name="document_download_risk",
            phase=phase,
            username=username,
            remote_address=ip_address,
            risk_level=assessment.level.value,
            risk_reasons=assessment.reasons,
            mode=policy.mode,
            would_block=would_block,
        )
        if would_block or assessment.level == DownloadRiskLevel.HIGH:
            log.warning("Document download risk evaluated")
        else:
            log.info("Document download risk evaluated")

    if would_block and policy.mode == "enforce":
        limiting = max(denied, key=lambda decision: decision.retry_after_seconds)
        return DownloadLimitDecision(
            False,
            scope=limiting.scope,
            limit=limiting.effective_limit,
            retry_after_seconds=limiting.retry_after_seconds,
            risk_level=assessment.level,
            risk_reasons=assessment.reasons,
            would_block=True,
            active_downloads=active_downloads,
        )
    return DownloadLimitDecision(
        True,
        risk_level=assessment.level,
        risk_reasons=assessment.reasons,
        would_block=would_block,
        active_downloads=active_downloads,
    )


def check_download_issue_limits(
    session: Session,
    username: str,
    ip_address: str,
    *,
    account_created_at: float | None,
    bypass_rate_limit: bool,
    now: float | None = None,
) -> DownloadLimitDecision:
    return _check_download_limits(
        session,
        namespace=_ISSUE_NAMESPACE,
        username=username,
        ip_address=ip_address,
        account_created_at=account_created_at,
        task_id=None,
        bypass_rate_limit=bypass_rate_limit,
        now=time.time() if now is None else now,
    )


def check_download_transfer_limits(
    session: Session,
    username: str | None,
    ip_address: str,
    task_id: str,
    *,
    account_created_at: float | None,
    bypass_rate_limit: bool,
    now: float | None = None,
) -> DownloadLimitDecision:
    return _check_download_limits(
        session,
        namespace=_TRANSFER_NAMESPACE,
        username=username,
        ip_address=ip_address,
        account_created_at=account_created_at,
        task_id=task_id,
        bypass_rate_limit=bypass_rate_limit,
        now=time.time() if now is None else now,
    )
