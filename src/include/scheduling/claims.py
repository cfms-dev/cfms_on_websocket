"""Atomic execution claiming, cluster delivery recovery, and lease renewal."""

from typing import cast

from sqlalchemy import CursorResult, or_, select, update

from include.config.validation import SchedulingPolicy
from include.database.clock import database_now
from include.database.models.scheduling import Schedule, ScheduleExecution
from include.database.session import Session
from include.scheduling.commands import lock_schedule
from include.scheduling.contracts import ClaimedExecution, PendingDispatch
from include.scheduling.outcomes import cancel_expired_deleted_executions


def claim_execution(
    generation: int,
    lease_owner: str,
    policy: SchedulingPolicy,
    *,
    now: float | None = None,
) -> ClaimedExecution | None:
    """Atomically lease the oldest runnable execution for a local worker.

    Return an immutable task snapshot, or ``None`` when no execution is available
    or another worker wins the claim.
    """
    with Session() as session, session.begin():
        candidate_time = database_now(session) if now is None else now
        candidate = session.execute(
            select(ScheduleExecution.id, ScheduleExecution.schedule_id)
            .where(
                ScheduleExecution.provider_generation == generation,
                ScheduleExecution.state.in_(("pending", "running", "retry_wait")),
                ScheduleExecution.schedule_id.in_(
                    select(Schedule.id).where(Schedule.status != "deleted")
                ),
                or_(
                    ScheduleExecution.retry_at.is_(None),
                    ScheduleExecution.retry_at <= candidate_time,
                ),
                or_(
                    ScheduleExecution.lease_expires_at.is_(None),
                    ScheduleExecution.lease_expires_at <= candidate_time,
                ),
            )
            .order_by(ScheduleExecution.created_at, ScheduleExecution.id)
            .limit(1)
        ).one_or_none()
        if candidate is None:
            return None
        candidate_id, schedule_id = candidate
        return _claim_execution(
            session,
            candidate_id,
            schedule_id,
            generation,
            lease_owner,
            policy,
            now,
        )


def _claim_execution(
    session,
    execution_id: str,
    schedule_id: str,
    generation: int,
    lease_owner: str,
    policy: SchedulingPolicy,
    now: float | None,
) -> ClaimedExecution | None:
    """Lock the schedule and conditionally transition one execution lease."""
    schedule = lock_schedule(session, schedule_id)
    if (
        schedule is None
        or schedule.status == "deleted"
        or schedule.active_execution_id != execution_id
    ):
        return None

    current_time = database_now(session) if now is None else now
    # Candidate selection is advisory. This conditional update is the atomic claim
    # boundary shared by local polling and Redis delivery.
    claimed = cast(
        CursorResult,
        session.execute(
            update(ScheduleExecution)
            .where(
                ScheduleExecution.id == execution_id,
                ScheduleExecution.schedule_id == schedule_id,
                ScheduleExecution.provider_generation == generation,
                ScheduleExecution.state.in_(("pending", "running", "retry_wait")),
                or_(
                    ScheduleExecution.retry_at.is_(None),
                    ScheduleExecution.retry_at <= current_time,
                ),
                or_(
                    ScheduleExecution.lease_expires_at.is_(None),
                    ScheduleExecution.lease_expires_at <= current_time,
                ),
            )
            .values(
                state="running",
                dispatch_state="sent",
                dispatched_at=current_time,
                attempt=ScheduleExecution.attempt + 1,
                retry_at=None,
                lease_owner=lease_owner,
                lease_expires_at=current_time + policy.execution_lease_seconds,
                started_at=current_time,
            )
        ),
    )
    if claimed.rowcount != 1:
        return None

    execution = session.get(ScheduleExecution, execution_id)
    assert execution is not None
    return ClaimedExecution(
        id=execution.id,
        schedule_id=schedule.id,
        task_name=execution.task_name,
        task_contract_version=execution.task_contract_version,
        payload=execution.payload,
        scheduled_for=execution.scheduled_for,
        attempt=execution.attempt,
        lease_owner=lease_owner,
    )


def claim_execution_by_id(
    execution_id: str,
    generation: int,
    lease_owner: str,
    policy: SchedulingPolicy,
    *,
    now: float | None = None,
) -> ClaimedExecution | None:
    """Atomically lease the execution named by a cluster delivery message.

    Stale generations, retry delays, and live leases are rejected with ``None`` so
    the provider can decide whether the message should be retried or discarded.
    """
    with Session() as session, session.begin():
        schedule_id = session.scalar(
            select(ScheduleExecution.schedule_id).where(
                ScheduleExecution.id == execution_id
            )
        )
        if schedule_id is None:
            return None
        return _claim_execution(
            session,
            execution_id,
            schedule_id,
            generation,
            lease_owner,
            policy,
            now,
        )


def execution_delivery_state(
    execution_id: str, generation: int, *, now: float | None = None
) -> str:
    """Classify delivery as ``stale``, ``terminal``, ``busy``, or ``ready``."""
    with Session() as session:
        current_time = database_now(session) if now is None else now
        execution = session.get(ScheduleExecution, execution_id)
        if execution is None or execution.provider_generation != generation:
            return "stale"
        if execution.state in {"succeeded", "failed", "cancelled"}:
            return "terminal"
        if execution.retry_at is not None and execution.retry_at > current_time:
            return "busy"
        if (
            execution.lease_expires_at is not None
            and execution.lease_expires_at > current_time
        ):
            return "busy"
        return "ready"


def pending_dispatches(
    generation: int,
    batch_size: int,
    dispatch_timeout_seconds: int,
    *,
    now: float | None = None,
) -> tuple[PendingDispatch, ...]:
    """Recover expired cluster leases and return executions awaiting delivery."""
    if now is None:
        with Session() as session:
            current_time = database_now(session)
    else:
        current_time = now
    cancel_expired_deleted_executions(batch_size, now=current_time)
    with Session() as session, session.begin():
        session.execute(
            update(ScheduleExecution)
            .where(
                ScheduleExecution.provider_generation == generation,
                ScheduleExecution.state.in_(("pending", "retry_wait")),
                ScheduleExecution.dispatch_state == "sent",
                or_(
                    ScheduleExecution.dispatched_at.is_(None),
                    ScheduleExecution.dispatched_at
                    <= current_time - dispatch_timeout_seconds,
                ),
            )
            .values(dispatch_state="pending", dispatched_at=None)
        )
        session.execute(
            update(ScheduleExecution)
            .where(
                ScheduleExecution.provider_generation == generation,
                ScheduleExecution.state == "running",
                ScheduleExecution.lease_expires_at <= current_time,
                ScheduleExecution.schedule_id.in_(
                    select(Schedule.id).where(Schedule.status != "deleted")
                ),
            )
            .values(
                state="pending",
                dispatch_state="pending",
                dispatched_at=None,
                retry_at=None,
                lease_owner=None,
                lease_expires_at=None,
            )
        )
        return tuple(
            PendingDispatch(id=execution_id, attempt=attempt)
            for execution_id, attempt in session.execute(
                select(ScheduleExecution.id, ScheduleExecution.attempt)
                .where(
                    ScheduleExecution.provider_generation == generation,
                    ScheduleExecution.state.in_(("pending", "retry_wait")),
                    ScheduleExecution.dispatch_state == "pending",
                    or_(
                        ScheduleExecution.retry_at.is_(None),
                        ScheduleExecution.retry_at <= current_time,
                    ),
                )
                .order_by(ScheduleExecution.created_at, ScheduleExecution.id)
                .limit(batch_size)
            )
        )


def mark_dispatched(
    execution_id: str,
    generation: int,
    expected_attempt: int,
    *,
    now: float | None = None,
) -> bool:
    """Mark a cluster execution sent if its observed attempt is still current.

    Returning ``False`` means another transition won and the caller must not
    overwrite the newer dispatch state.
    """

    with Session() as session, session.begin():
        current_time = database_now(session) if now is None else now
        marked = cast(
            CursorResult,
            session.execute(
                update(ScheduleExecution)
                .where(
                    ScheduleExecution.id == execution_id,
                    ScheduleExecution.provider_generation == generation,
                    ScheduleExecution.attempt == expected_attempt,
                    ScheduleExecution.dispatch_state == "pending",
                    ScheduleExecution.state.in_(("pending", "retry_wait")),
                )
                .values(dispatch_state="sent", dispatched_at=current_time)
            ),
        )
        return marked.rowcount == 1


def refresh_execution_lease(
    execution_id: str,
    lease_owner: str,
    policy: SchedulingPolicy,
    *,
    now: float | None = None,
) -> bool:
    """Extend a running execution lease only for its current owner.

    The database clock is read after acquiring the execution lock so lock wait
    time cannot consume the newly issued lease.  ``False`` indicates lost
    ownership or a terminal transition.
    """

    with Session() as session, session.begin():
        criteria = (
            ScheduleExecution.id == execution_id,
            ScheduleExecution.state == "running",
            ScheduleExecution.lease_owner == lease_owner,
        )
        if session.get_bind().dialect.name == "sqlite":
            locked = cast(
                CursorResult,
                session.execute(
                    update(ScheduleExecution)
                    .where(*criteria)
                    .values(lease_expires_at=ScheduleExecution.lease_expires_at)
                ),
            )
            if locked.rowcount != 1:
                return False
        elif (
            session.scalar(
                select(ScheduleExecution.id).where(*criteria).with_for_update()
            )
            is None
        ):
            return False

        current_time = database_now(session) if now is None else now
        refreshed = cast(
            CursorResult,
            session.execute(
                update(ScheduleExecution)
                .where(*criteria)
                .values(lease_expires_at=current_time + policy.execution_lease_seconds)
            ),
        )
        return refreshed.rowcount == 1
