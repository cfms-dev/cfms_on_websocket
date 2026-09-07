from typing import Any, cast

from sqlalchemy import CursorResult, select, update
from sqlalchemy.orm import Session as OrmSession

from include.database.clock import database_now
from include.database.models.scheduling import Schedule, ScheduleExecution
from include.scheduling.registry import ScheduledTaskRegistry
from include.scheduling.triggers import build_trigger, first_run_at


class ScheduleNotFoundError(LookupError):
    pass


class ScheduleConflictError(RuntimeError):
    pass


def lock_schedule(session: OrmSession, schedule_id: str) -> Schedule | None:
    """Lock and refresh a schedule before mutating its execution aggregate."""
    if session.get_bind().dialect.name == "sqlite":
        locked = cast(
            CursorResult,
            session.execute(
                update(Schedule)
                .where(Schedule.id == schedule_id)
                .values(active_execution_id=Schedule.active_execution_id)
            ),
        )
        if locked.rowcount != 1:
            return None
    return session.scalar(
        select(Schedule)
        .where(Schedule.id == schedule_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    )


def create_schedule(
    session: OrmSession,
    registry: ScheduledTaskRegistry,
    *,
    username: str,
    task_name: str,
    payload: dict[str, Any],
    trigger_type: str,
    trigger_data: dict[str, Any],
    timezone: str,
    enabled: bool,
    now: float | None = None,
) -> Schedule:
    """Validate and add a user-managed schedule to the caller's transaction."""
    current_time = database_now(session) if now is None else now
    registration = registry.get(task_name)
    if registration is None:
        raise LookupError(f"Scheduled task type {task_name!r} is not registered")
    if not registration.user_schedulable:
        raise LookupError(f"Scheduled task type {task_name!r} is system managed")
    validated_payload = registry.validate_payload(
        task_name, registration.contract_version, payload
    ).model_dump(mode="json")
    trigger = build_trigger(trigger_type, trigger_data, timezone)
    schedule = Schedule(
        task_name=task_name,
        task_contract_version=registration.contract_version,
        payload=validated_payload,
        trigger_type=trigger_type,
        trigger_data=trigger_data,
        timezone=timezone,
        enabled=enabled,
        next_run_at=first_run_at(trigger, current_time),
        created_by=username,
        created_at=current_time,
        updated_by=username,
        updated_at=current_time,
    )
    session.add(schedule)
    session.flush()
    return schedule


def update_schedule(
    session: OrmSession,
    registry: ScheduledTaskRegistry,
    schedule_id: str,
    expected_revision: int,
    changes: dict[str, Any],
    *,
    username: str,
    now: float | None = None,
) -> Schedule:
    """Apply validated changes to a quiescent schedule using optimistic concurrency.

    The caller owns the transaction. A stale revision or an execution becoming
    active during the update raises :class:`ScheduleConflictError`.
    """
    schedule = lock_schedule(session, schedule_id)
    if schedule is None or schedule.status == "deleted":
        raise ScheduleNotFoundError(schedule_id)
    current_time = database_now(session) if now is None else now
    if schedule.system_managed:
        raise ScheduleConflictError("System-managed schedules cannot be updated")
    if schedule.revision != expected_revision:
        raise ScheduleConflictError("Schedule revision is stale")
    if schedule.active_execution_id is not None:
        raise ScheduleConflictError("Schedule has an active execution")

    task_name = changes.get("task_name", schedule.task_name)
    payload = changes.get("payload", schedule.payload)
    trigger_type = changes.get("trigger_type", schedule.trigger_type)
    trigger_data = changes.get("trigger_data", schedule.trigger_data)
    timezone = changes.get("timezone", schedule.timezone)
    registration = registry.get(task_name)
    if registration is None:
        raise LookupError(f"Scheduled task type {task_name!r} is not registered")
    if not registration.user_schedulable:
        raise LookupError(f"Scheduled task type {task_name!r} is system managed")
    validated_payload = registry.validate_payload(
        task_name, registration.contract_version, payload
    ).model_dump(mode="json")
    trigger = build_trigger(trigger_type, trigger_data, timezone)
    next_run_at = first_run_at(trigger, current_time)
    if (
        next_run_at is not None
        and session.scalar(
            select(ScheduleExecution.id).where(
                ScheduleExecution.schedule_id == schedule_id,
                ScheduleExecution.scheduled_for == next_run_at,
            )
        )
        is not None
    ):
        raise ScheduleConflictError(
            "Schedule occurrence has already been recorded; provide a new trigger time"
        )
    enabled = changes.get("enabled", schedule.enabled)
    values = {
        "task_name": task_name,
        "task_contract_version": registration.contract_version,
        "payload": validated_payload,
        "trigger_type": trigger_type,
        "trigger_data": trigger_data,
        "timezone": timezone,
        "enabled": enabled,
        "status": "active",
        "next_run_at": next_run_at,
        "pending_scheduled_for": None,
        "updated_by": username,
        "updated_at": current_time,
        "revision": expected_revision + 1,
    }
    changed = cast(
        CursorResult,
        session.execute(
            update(Schedule)
            .where(
                Schedule.id == schedule_id,
                Schedule.revision == expected_revision,
                Schedule.active_execution_id.is_(None),
            )
            .values(**values)
        ),
    )
    if changed.rowcount != 1:
        raise ScheduleConflictError("Schedule changed concurrently")
    session.flush()
    return schedule


def cancel_unstarted_schedule_execution(
    session: OrmSession,
    schedule: Schedule,
    *,
    now: float,
    reason: str,
) -> None:
    """Cancel queued work for a retired schedule in the caller's transaction."""
    active_execution_id = schedule.active_execution_id
    if active_execution_id is None:
        return

    cancelled = cast(
        CursorResult,
        session.execute(
            update(ScheduleExecution)
            .where(
                ScheduleExecution.id == active_execution_id,
                ScheduleExecution.state.in_(("pending", "retry_wait")),
            )
            .values(
                state="cancelled",
                retry_at=None,
                lease_owner=None,
                lease_expires_at=None,
                completed_at=now,
                error=reason,
            )
        ),
    )
    if cancelled.rowcount == 1:
        schedule.active_execution_id = None
        return

    execution_state = session.scalar(
        select(ScheduleExecution.state).where(
            ScheduleExecution.id == active_execution_id
        )
    )
    if execution_state is None or execution_state in {
        "succeeded",
        "failed",
        "cancelled",
    }:
        schedule.active_execution_id = None


def delete_schedule(
    session: OrmSession,
    schedule_id: str,
    expected_revision: int,
    *,
    username: str,
    now: float | None = None,
) -> None:
    """Logically delete a user schedule at the expected revision.

    Future and coalesced occurrences are cancelled without interrupting an
    execution that is already active. The caller owns the transaction.
    """
    schedule = lock_schedule(session, schedule_id)
    if schedule is None or schedule.status == "deleted":
        raise ScheduleNotFoundError(schedule_id)
    current_time = database_now(session) if now is None else now
    if schedule.system_managed:
        raise ScheduleConflictError("System-managed schedules cannot be deleted")
    if schedule.revision != expected_revision:
        raise ScheduleConflictError("Schedule revision is stale")
    schedule.enabled = False
    schedule.status = "deleted"
    schedule.next_run_at = None
    schedule.pending_scheduled_for = None
    schedule.revision = expected_revision + 1
    schedule.updated_by = username
    schedule.updated_at = current_time
    schedule.deleted_at = current_time
    cancel_unstarted_schedule_execution(
        session,
        schedule,
        now=current_time,
        reason="Schedule deleted before execution started",
    )


def schedule_response(
    schedule: Schedule, registry: ScheduledTaskRegistry
) -> dict[str, Any]:
    registration = registry.get(schedule.task_name)
    return {
        "id": schedule.id,
        "task_name": schedule.task_name,
        "task_contract_version": schedule.task_contract_version,
        "task_available": (
            registration is not None
            and registration.contract_version == schedule.task_contract_version
        ),
        "payload": schedule.payload,
        "trigger": {
            "type": schedule.trigger_type,
            "data": schedule.trigger_data,
            "timezone": schedule.timezone,
        },
        "enabled": schedule.enabled,
        "status": schedule.status,
        "revision": schedule.revision,
        "next_run_at": schedule.next_run_at,
        "active_execution_id": schedule.active_execution_id,
        "pending_scheduled_for": schedule.pending_scheduled_for,
        "created_by": schedule.created_by,
        "created_at": schedule.created_at,
        "updated_by": schedule.updated_by,
        "updated_at": schedule.updated_at,
    }
