import time
from typing import Any

from sqlalchemy import update
from sqlalchemy.orm import Session as OrmSession

from include.database.models.scheduling import Schedule
from include.scheduling.registry import ScheduledTaskRegistry
from include.scheduling.triggers import build_trigger, first_run_at


class ScheduleNotFoundError(LookupError):
    pass


class ScheduleConflictError(RuntimeError):
    pass


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
    current_time = time.time() if now is None else now
    registration = registry.get(task_name)
    if registration is None:
        raise LookupError(f"Scheduled task type {task_name!r} is not registered")
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
    current_time = time.time() if now is None else now
    schedule = session.get(Schedule, schedule_id)
    if schedule is None or schedule.status == "deleted":
        raise ScheduleNotFoundError(schedule_id)
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
    validated_payload = registry.validate_payload(
        task_name, registration.contract_version, payload
    ).model_dump(mode="json")
    trigger = build_trigger(trigger_type, trigger_data, timezone)
    enabled = changes.get("enabled", schedule.enabled)
    values = {
        "task_name": task_name,
        "task_contract_version": registration.contract_version,
        "payload": validated_payload,
        "trigger_type": trigger_type,
        "trigger_data": trigger_data,
        "timezone": timezone,
        "enabled": enabled,
        "next_run_at": first_run_at(trigger, current_time),
        "pending_scheduled_for": None,
        "updated_by": username,
        "updated_at": current_time,
        "revision": expected_revision + 1,
    }
    changed = session.execute(
        update(Schedule)
        .where(
            Schedule.id == schedule_id,
            Schedule.revision == expected_revision,
            Schedule.active_execution_id.is_(None),
        )
        .values(**values)
    )
    if changed.rowcount != 1:
        raise ScheduleConflictError("Schedule changed concurrently")
    session.flush()
    return session.get(Schedule, schedule_id)


def delete_schedule(
    session: OrmSession,
    schedule_id: str,
    expected_revision: int,
    *,
    username: str,
    now: float | None = None,
) -> None:
    current_time = time.time() if now is None else now
    deleted = session.execute(
        update(Schedule)
        .where(
            Schedule.id == schedule_id,
            Schedule.status != "deleted",
            Schedule.revision == expected_revision,
        )
        .values(
            enabled=False,
            status="deleted",
            next_run_at=None,
            pending_scheduled_for=None,
            revision=expected_revision + 1,
            updated_by=username,
            updated_at=current_time,
            deleted_at=current_time,
        )
    )
    if deleted.rowcount == 1:
        return
    schedule = session.get(Schedule, schedule_id)
    if schedule is None or schedule.status == "deleted":
        raise ScheduleNotFoundError(schedule_id)
    raise ScheduleConflictError("Schedule revision is stale")


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
