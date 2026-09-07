from typing import cast

from sqlalchemy import CursorResult, delete, select, update

from include.config.validation import SchedulingPolicy
from include.database.clock import database_now
from include.database.models.scheduling import Schedule, ScheduleExecution
from include.database.session import Session
from include.scheduling.commands import lock_schedule
from include.scheduling.contracts import ClaimedExecution
from include.scheduling.occurrences import create_execution


def cancel_expired_deleted_executions(
    batch_size: int,
    *,
    now: float | None = None,
) -> int:
    """Cancel one bounded batch of crashed work whose schedule was deleted."""
    with Session() as session:
        current_time = database_now(session) if now is None else now
        candidates = tuple(
            session.execute(
                select(ScheduleExecution.id, ScheduleExecution.schedule_id)
                .where(
                    ScheduleExecution.state == "running",
                    ScheduleExecution.lease_expires_at <= current_time,
                    ScheduleExecution.schedule_id.in_(
                        select(Schedule.id).where(Schedule.status == "deleted")
                    ),
                )
                .order_by(
                    ScheduleExecution.lease_expires_at,
                    ScheduleExecution.id,
                )
                .limit(batch_size)
            )
        )

    cancelled_count = 0
    for execution_id, schedule_id in candidates:
        with Session() as session, session.begin():
            schedule = lock_schedule(session, schedule_id)
            if schedule is None or schedule.status != "deleted":
                continue
            cancelled = cast(
                CursorResult,
                session.execute(
                    update(ScheduleExecution)
                    .where(
                        ScheduleExecution.id == execution_id,
                        ScheduleExecution.schedule_id == schedule_id,
                        ScheduleExecution.state == "running",
                        ScheduleExecution.lease_expires_at <= current_time,
                    )
                    .values(
                        state="cancelled",
                        retry_at=None,
                        lease_owner=None,
                        lease_expires_at=None,
                        completed_at=current_time,
                        error="Execution lease expired after schedule deletion",
                    )
                ),
            )
            if cancelled.rowcount != 1:
                continue
            if schedule.active_execution_id == execution_id:
                schedule.active_execution_id = None
            cancelled_count += 1
    return cancelled_count


def purge_execution_history(
    policy: SchedulingPolicy,
    *,
    now: float | None = None,
) -> int:
    """Delete one bounded batch of terminal executions past the retention cutoff."""
    with Session() as session, session.begin():
        current_time = database_now(session) if now is None else now
        cutoff = current_time - policy.history_retention_days * 86_400
        execution_ids = tuple(
            session.scalars(
                select(ScheduleExecution.id)
                .where(
                    ScheduleExecution.state.in_(("succeeded", "failed", "cancelled")),
                    ScheduleExecution.completed_at < cutoff,
                )
                .order_by(ScheduleExecution.completed_at, ScheduleExecution.id)
                .limit(policy.claim_batch_size)
            )
        )
        if not execution_ids:
            return 0
        deleted = cast(
            CursorResult,
            session.execute(
                delete(ScheduleExecution).where(ScheduleExecution.id.in_(execution_ids))
            ),
        )
        return deleted.rowcount


def _release_schedule_execution(
    session,
    schedule: Schedule,
    generation: int,
    terminal_status: str,
    current_time: float,
) -> None:
    """Release a schedule's slot and promote its latest coalesced occurrence."""
    schedule.active_execution_id = None
    if schedule.status == "deleted":
        return
    if schedule.pending_scheduled_for is not None:
        pending = schedule.pending_scheduled_for
        schedule.pending_scheduled_for = None
        create_execution(session, schedule, pending, generation, current_time)
    elif schedule.next_run_at is None:
        schedule.status = terminal_status


def complete_execution(
    claim: ClaimedExecution,
    generation: int,
    result: dict,
    *,
    now: float | None = None,
) -> bool:
    """Persist success if the caller still owns the execution lease.

    The schedule slot is released only for the execution currently attached to the
    schedule. ``False`` means ownership was lost and no state was changed.
    """
    with Session() as session, session.begin():
        schedule = lock_schedule(session, claim.schedule_id)
        if schedule is None:
            return False
        current_time = database_now(session) if now is None else now
        completed = cast(
            CursorResult,
            session.execute(
                update(ScheduleExecution)
                .where(
                    ScheduleExecution.id == claim.id,
                    ScheduleExecution.schedule_id == claim.schedule_id,
                    ScheduleExecution.provider_generation == generation,
                    ScheduleExecution.state == "running",
                    ScheduleExecution.lease_owner == claim.lease_owner,
                )
                .values(
                    state="succeeded",
                    completed_at=current_time,
                    result=result,
                    lease_owner=None,
                    lease_expires_at=None,
                )
            ),
        )
        if completed.rowcount != 1:
            return False
        if schedule.active_execution_id == claim.id:
            _release_schedule_execution(
                session,
                schedule,
                generation,
                "completed",
                current_time,
            )
        return True


def fail_execution(
    claim: ClaimedExecution,
    generation: int,
    max_attempts: int,
    initial_backoff_seconds: int,
    maximum_backoff_seconds: int,
    error: str,
    *,
    now: float | None = None,
) -> bool:
    """Persist a retry or terminal failure while the caller owns the lease.

    Retry delays use capped exponential backoff. A terminal failure releases the
    schedule slot so a coalesced recurring occurrence can proceed.
    """
    with Session() as session, session.begin():
        schedule = lock_schedule(session, claim.schedule_id)
        if schedule is None:
            return False
        current_time = database_now(session) if now is None else now
        retry = claim.attempt < max_attempts and schedule.status != "deleted"
        values = {
            "error": error[:1024],
            "lease_owner": None,
            "lease_expires_at": None,
        }
        if retry:
            delay = min(
                initial_backoff_seconds * 2 ** (claim.attempt - 1),
                maximum_backoff_seconds,
            )
            values.update(
                state="retry_wait",
                dispatch_state="pending",
                dispatched_at=None,
                retry_at=current_time + delay,
            )
        else:
            values.update(
                state="failed",
                completed_at=current_time,
            )
        failed = cast(
            CursorResult,
            session.execute(
                update(ScheduleExecution)
                .where(
                    ScheduleExecution.id == claim.id,
                    ScheduleExecution.schedule_id == claim.schedule_id,
                    ScheduleExecution.provider_generation == generation,
                    ScheduleExecution.state == "running",
                    ScheduleExecution.lease_owner == claim.lease_owner,
                )
                .values(**values)
            ),
        )
        if failed.rowcount != 1:
            return False
        if not retry and schedule.active_execution_id == claim.id:
            _release_schedule_execution(
                session,
                schedule,
                generation,
                "failed",
                current_time,
            )
        return True
