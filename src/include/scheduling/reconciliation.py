import datetime as dt
from typing import Any

from sqlalchemy import or_, select

from include.database.clock import database_now
from include.database.models.scheduling import Schedule
from include.database.session import Session
from include.scheduling.commands import (
    cancel_unstarted_schedule_execution,
    lock_schedule,
)
from include.scheduling.contracts import (
    ScheduledTaskRegistration,
    SystemScheduleDefinition,
)
from include.scheduling.registry import ScheduledTaskRegistry
from include.scheduling.triggers import build_trigger, first_run_at


def _system_schedule_values(
    registration: ScheduledTaskRegistration,
    definition: SystemScheduleDefinition,
    payload: dict[str, Any],
    configured_trigger_data: dict[str, Any],
    schedule: Schedule | None,
    current_time: float,
) -> tuple[dict[str, Any], float | None, float | None]:
    trigger_data = dict(configured_trigger_data)
    if definition.trigger_type == "interval" and "start_at" not in trigger_data:
        if (
            schedule is not None
            and schedule.trigger_type == "interval"
            and "start_at" in schedule.trigger_data
        ):
            trigger_data["start_at"] = schedule.trigger_data["start_at"]
        else:
            trigger_data["start_at"] = dt.datetime.fromtimestamp(
                current_time, dt.UTC
            ).isoformat()
    trigger = build_trigger(
        definition.trigger_type,
        trigger_data,
        definition.timezone,
    )
    values = {
        "task_name": registration.name,
        "task_contract_version": registration.contract_version,
        "payload": payload,
        "trigger_type": definition.trigger_type,
        "trigger_data": trigger_data,
        "timezone": definition.timezone,
        "created_by": None,
        "updated_by": None,
    }
    return (
        values,
        first_run_at(trigger, current_time),
        current_time if definition.run_immediately else None,
    )


def _matches_system_schedule(schedule: Schedule, values: dict[str, Any]) -> bool:
    return (
        all(getattr(schedule, name) == value for name, value in values.items())
        and schedule.enabled
        and schedule.status == "active"
    )


def synchronize_system_schedules(
    registry: ScheduledTaskRegistry,
    *,
    now: float | None = None,
) -> int:
    """Reconcile registered system schedules with their persisted desired state.

    Missing registrations retire their schedules, while new or changed definitions
    are created or updated. The return value is the number of schedules changed.
    """
    desired: dict[str, tuple] = {}
    for registration in registry.all():
        if registration.system_schedule is None:
            continue
        definition = registration.system_schedule()
        if definition.id in desired:
            raise ValueError(f"Duplicate system schedule ID {definition.id!r}")
        payload = registry.validate_payload(
            registration.name,
            registration.contract_version,
            definition.payload,
        ).model_dump(mode="json")
        desired[definition.id] = (
            registration,
            definition,
            payload,
            dict(definition.trigger_data),
        )

    changed = 0
    with Session() as session, session.begin():
        current_time = database_now(session) if now is None else now
        orphaned = session.scalars(
            select(Schedule).where(
                Schedule.system_managed.is_(True),
                Schedule.id.not_in(desired),
                or_(Schedule.enabled.is_(True), Schedule.status != "deleted"),
            )
        ).all()
        for candidate in orphaned:
            schedule = lock_schedule(session, candidate.id)
            if (
                schedule is None
                or not schedule.system_managed
                or schedule.id in desired
                or (not schedule.enabled and schedule.status == "deleted")
            ):
                continue
            schedule.enabled = False
            schedule.status = "deleted"
            schedule.next_run_at = None
            schedule.pending_scheduled_for = None
            schedule.revision += 1
            schedule.updated_at = current_time
            schedule.deleted_at = current_time
            cancel_unstarted_schedule_execution(
                session,
                schedule,
                now=current_time,
                reason="System schedule retired before execution started",
            )
            changed += 1

        for schedule_id, item in desired.items():
            registration, definition, payload, configured_trigger_data = item
            candidate = session.get(Schedule, schedule_id)
            if candidate is not None and not candidate.system_managed:
                raise RuntimeError(
                    f"System schedule ID {schedule_id!r} is already user managed"
                )
            if candidate is not None:
                candidate_values, _, _ = _system_schedule_values(
                    registration,
                    definition,
                    payload,
                    configured_trigger_data,
                    candidate,
                    current_time,
                )
                if _matches_system_schedule(candidate, candidate_values):
                    continue

            schedule = lock_schedule(session, schedule_id)
            if schedule is not None and not schedule.system_managed:
                raise RuntimeError(
                    f"System schedule ID {schedule_id!r} is already user managed"
                )
            values, next_run_at, pending_scheduled_for = _system_schedule_values(
                registration,
                definition,
                payload,
                configured_trigger_data,
                schedule,
                current_time,
            )
            if schedule is None:
                session.add(
                    Schedule(
                        id=schedule_id,
                        **values,
                        system_managed=True,
                        enabled=True,
                        status="active",
                        next_run_at=next_run_at,
                        pending_scheduled_for=pending_scheduled_for,
                        created_at=current_time,
                        updated_at=current_time,
                    )
                )
                changed += 1
                continue

            if _matches_system_schedule(schedule, values):
                continue
            for name, value in values.items():
                setattr(schedule, name, value)
            schedule.enabled = True
            schedule.status = "active"
            schedule.next_run_at = next_run_at
            schedule.pending_scheduled_for = pending_scheduled_for
            schedule.revision += 1
            schedule.updated_at = current_time
            schedule.deleted_at = None
            changed += 1
    return changed
