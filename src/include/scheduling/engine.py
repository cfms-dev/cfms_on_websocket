"""Provider-neutral runtime generation and due-occurrence creation."""

from typing import cast

from sqlalchemy import CursorResult, and_, or_, select, update
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert

from include.config.validation import SchedulingPolicy
from include.database.clock import database_now
from include.database.models.scheduling import (
    Schedule,
    ScheduleExecution,
    SchedulingRuntimeState,
)
from include.database.session import Session
from include.scheduling.commands import lock_schedule
from include.scheduling.occurrences import create_execution, execution_id
from include.scheduling.triggers import advance_trigger, build_trigger

__all__ = [
    "enqueue_due_schedules",
    "ensure_runtime_state",
]


def _build_runtime_state_upsert(
    dialect_name: str,
    provider: str,
    current_time: float,
    redis_namespace: str | None = None,
):
    """Build the dialect-specific insert-if-absent for the singleton runtime row."""

    values = {
        "id": 1,
        "provider": provider,
        "redis_namespace": redis_namespace,
        "generation": 1,
        "schema_version": 1,
        "updated_at": current_time,
    }
    if dialect_name == "sqlite":
        return (
            sqlite_insert(SchedulingRuntimeState)
            .values(**values)
            .on_conflict_do_nothing(index_elements=[SchedulingRuntimeState.id])
        )
    if dialect_name == "postgresql":
        return (
            postgresql_insert(SchedulingRuntimeState)
            .values(**values)
            .on_conflict_do_nothing(index_elements=[SchedulingRuntimeState.id])
        )
    if dialect_name == "mysql":
        return (
            mysql_insert(SchedulingRuntimeState)
            .values(**values)
            .on_duplicate_key_update(id=SchedulingRuntimeState.id)
        )
    raise ValueError(f"Unsupported database dialect: {dialect_name}")


def ensure_runtime_state(
    provider: str,
    redis_namespace: str | None = None,
    *,
    now: float | None = None,
) -> int:
    """Ensure the active scheduling provider state exists and return its generation.

    If the provider changes, active execution leases prevent the switch; otherwise
    pending work is reset and moved to the new provider generation.
    """
    if provider == "redis" and redis_namespace is None:
        raise ValueError("Redis scheduling requires a deployment namespace")
    desired_namespace = redis_namespace if provider == "redis" else None
    with Session() as session, session.begin():
        current_time = database_now(session) if now is None else now
        session.execute(
            _build_runtime_state_upsert(
                session.get_bind().dialect.name,
                provider,
                current_time,
                desired_namespace,
            )
        )
        state = session.scalar(
            select(SchedulingRuntimeState)
            .where(SchedulingRuntimeState.id == 1)
            .with_for_update()
            .execution_options(populate_existing=True)
        )
        assert state is not None
        if state.provider == provider and state.redis_namespace == desired_namespace:
            return state.generation

        active_execution = session.scalar(
            select(ScheduleExecution.id).where(
                ScheduleExecution.state == "running",
                ScheduleExecution.lease_expires_at > current_time,
            )
        )
        if active_execution is not None:
            raise RuntimeError(
                "Cannot switch scheduling provider while an execution lease is active"
            )

        state.provider = provider
        state.redis_namespace = desired_namespace
        state.generation += 1
        state.updated_at = current_time
        session.execute(
            update(ScheduleExecution)
            .where(
                ScheduleExecution.state.in_(("pending", "running", "retry_wait")),
                ScheduleExecution.schedule_id.in_(
                    select(Schedule.id).where(Schedule.status != "deleted")
                ),
            )
            .values(
                provider_generation=state.generation,
                state="pending",
                dispatch_state="pending",
                dispatched_at=None,
                retry_at=None,
                lease_owner=None,
                lease_expires_at=None,
            )
        )
        return state.generation


def _advance_schedule_if_current(
    session,
    schedule: Schedule,
    **values,
) -> bool:
    """Advance a schedule only if its observed aggregate state is unchanged.

    The compare-and-update protects against concurrent API mutations and other
    scheduler candidates after the advisory due shortlist was read.
    """
    advanced = cast(
        CursorResult,
        session.execute(
            update(Schedule)
            .where(
                Schedule.id == schedule.id,
                Schedule.revision == schedule.revision,
                Schedule.enabled.is_(True),
                Schedule.status == "active",
                Schedule.next_run_at == schedule.next_run_at,
                Schedule.pending_scheduled_for == schedule.pending_scheduled_for,
                Schedule.active_execution_id == schedule.active_execution_id,
            )
            .values(**values)
        ),
    )
    return advanced.rowcount == 1


def enqueue_due_schedules(
    generation: int,
    policy: SchedulingPolicy,
    *,
    now: float | None = None,
) -> int:
    """Create durable executions for schedules that are due.

    Eligible missed occurrences coalesce to the latest one. If a schedule already
    has an active execution, that occurrence is retained as its next pending run.
    """
    # The shortlist is intentionally advisory. Each candidate is rechecked in its
    # own transaction so concurrent schedule updates cannot enqueue stale work.
    with Session() as session:
        current_time = database_now(session) if now is None else now
        due_ids = session.scalars(
            select(Schedule.id)
            .where(
                Schedule.enabled.is_(True),
                Schedule.status == "active",
                or_(
                    Schedule.next_run_at <= current_time,
                    and_(
                        Schedule.active_execution_id.is_(None),
                        Schedule.pending_scheduled_for <= current_time,
                    ),
                ),
            )
            .order_by(
                Schedule.pending_scheduled_for,
                Schedule.next_run_at,
                Schedule.id,
            )
            .limit(policy.claim_batch_size)
        ).all()

    created = 0
    for schedule_id in due_ids:
        with Session() as session, session.begin():
            schedule = lock_schedule(session, schedule_id)
            if schedule is None or not schedule.enabled or schedule.status != "active":
                continue

            current_run_at = schedule.next_run_at
            due_run_at = (
                current_run_at
                if current_run_at is not None and current_run_at <= current_time
                else None
            )
            pending_due = (
                schedule.pending_scheduled_for is not None
                and schedule.pending_scheduled_for <= current_time
            )
            if due_run_at is None and not pending_due:
                continue

            next_run_at = current_run_at
            latest_due_at = schedule.pending_scheduled_for if pending_due else None
            if due_run_at is not None:
                trigger = build_trigger(
                    schedule.trigger_type, schedule.trigger_data, schedule.timezone
                )
                advance = advance_trigger(
                    trigger,
                    due_run_at,
                    current_time,
                    policy.misfire_grace_seconds,
                )
                next_run_at = advance.next_run_at
                if advance.latest_due_at is not None and (
                    latest_due_at is None or advance.latest_due_at > latest_due_at
                ):
                    latest_due_at = advance.latest_due_at

            if latest_due_at is None:
                values: dict[str, float | str | None] = {"next_run_at": next_run_at}
                if next_run_at is None and schedule.active_execution_id is None:
                    values["status"] = "completed"
                if not _advance_schedule_if_current(session, schedule, **values):
                    session.rollback()
                continue
            if schedule.active_execution_id is not None:
                # A schedule exposes only one execution slot; repeated polls replace
                # the pending timestamp with the latest eligible occurrence.
                if not _advance_schedule_if_current(
                    session,
                    schedule,
                    next_run_at=next_run_at,
                    pending_scheduled_for=latest_due_at,
                ):
                    session.rollback()
                continue
            reserved_execution_id = execution_id(schedule.id, latest_due_at)
            if not _advance_schedule_if_current(
                session,
                schedule,
                next_run_at=next_run_at,
                pending_scheduled_for=None,
                active_execution_id=reserved_execution_id,
            ):
                session.rollback()
                continue
            create_execution(
                session,
                schedule,
                latest_due_at,
                generation,
                current_time,
            )
            created += 1
    return created
