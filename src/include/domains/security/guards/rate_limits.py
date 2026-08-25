import math
import threading
from collections.abc import Iterator
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass

from sqlalchemy import delete, func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from include.database.models.operations import RateLimitBucket, RiskIPAccount

rate_limit_lock = threading.Lock()


@contextmanager
def risk_control_transaction(session: Session) -> Iterator[None]:
    lock = (
        rate_limit_lock
        if session.get_bind().dialect.name == "sqlite"
        else nullcontext()
    )
    with lock, session.begin():
        yield


@dataclass(frozen=True, slots=True)
class BucketDecision:
    allowed: bool
    scope: str
    effective_limit: int
    retry_after_seconds: int


def lock_rate_bucket(
    session: Session,
    namespace: str,
    scope: str,
    identity: str,
    now: float,
    capacity: int,
) -> RateLimitBucket:
    statement = select(RateLimitBucket).where(
        RateLimitBucket.namespace == namespace,
        RateLimitBucket.scope == scope,
        RateLimitBucket.identity == identity,
    )
    if session.get_bind().dialect.name != "sqlite":
        statement = statement.with_for_update()
    row = session.scalar(statement)
    if row is not None:
        return row
    try:
        with session.begin_nested():
            row = RateLimitBucket(
                namespace=namespace,
                scope=scope,
                identity=identity,
                tokens=float(capacity),
                last_refill_at=now,
                denial_count=0,
                last_denied_at=None,
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


def touch_rate_bucket(session: Session, row: RateLimitBucket, now: float) -> None:
    session.execute(
        update(RateLimitBucket)
        .where(
            RateLimitBucket.namespace == row.namespace,
            RateLimitBucket.scope == row.scope,
            RateLimitBucket.identity == row.identity,
        )
        .values(last_attempt=now)
    )
    row.last_attempt = now


def record_ip_account(
    session: Session,
    namespace: str,
    ip_address: str,
    username: str,
    now: float,
) -> None:
    identity = (namespace, ip_address, username)
    row = session.get(RiskIPAccount, identity)
    if row is not None:
        row.last_attempt = now
        return
    try:
        with session.begin_nested():
            session.add(
                RiskIPAccount(
                    namespace=namespace,
                    ip_address=ip_address,
                    username=username,
                    last_attempt=now,
                )
            )
            session.flush()
    except IntegrityError:
        row = session.get(RiskIPAccount, identity)
        if row is None:
            raise
        row.last_attempt = now


def count_ip_accounts(
    session: Session,
    namespace: str,
    ip_address: str,
    cutoff: float,
) -> int:
    return int(
        session.scalar(
            select(func.count(RiskIPAccount.username)).where(
                RiskIPAccount.namespace == namespace,
                RiskIPAccount.ip_address == ip_address,
                RiskIPAccount.last_attempt >= cutoff,
            )
        )
        or 0
    )


def refresh_denials(row: RateLimitBucket, now: float, window_seconds: int) -> None:
    if row.last_denied_at is None or now - row.last_denied_at > window_seconds:
        row.denial_count = 0
        row.last_denied_at = None


def record_denial(row: RateLimitBucket, now: float, window_seconds: int) -> None:
    refresh_denials(row, now, window_seconds)
    row.denial_count += 1
    row.last_denied_at = now
    row.last_attempt = now


def consume_bucket(
    row: RateLimitBucket,
    *,
    now: float,
    capacity: int,
    refill_tokens: int,
    refill_period_seconds: int,
    cost: int,
) -> BucketDecision:
    refill_rate = refill_tokens / refill_period_seconds
    if now > row.last_refill_at:
        row.tokens = min(
            float(capacity),
            row.tokens + (now - row.last_refill_at) * refill_rate,
        )
        row.last_refill_at = now
    row.tokens = min(row.tokens, float(capacity))
    row.last_attempt = now
    effective_limit = max(1, refill_tokens // cost)
    if row.tokens >= cost:
        row.tokens -= cost
        return BucketDecision(True, row.scope, effective_limit, 0)
    return BucketDecision(
        False,
        row.scope,
        effective_limit,
        max(1, math.ceil((cost - row.tokens) / refill_rate)),
    )


def cleanup_rate_limit_state(
    session: Session,
    namespace: str,
    *,
    ip_account_cutoff: float,
    bucket_cutoff: float,
) -> None:
    session.execute(
        delete(RiskIPAccount).where(
            RiskIPAccount.namespace == namespace,
            RiskIPAccount.last_attempt < ip_account_cutoff,
        )
    )
    session.execute(
        delete(RateLimitBucket).where(
            RateLimitBucket.namespace == namespace,
            RateLimitBucket.last_attempt < bucket_cutoff,
        )
    )
