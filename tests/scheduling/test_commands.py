import pytest
from pydantic import BaseModel
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from include.database.models.scheduling import Schedule
from include.domains.access.permissions import Permissions
from include.scheduling import ScheduledTaskRegistration, ScheduledTaskRegistry
from include.scheduling.commands import (
    ScheduleConflictError,
    create_schedule,
    delete_schedule,
    schedule_response,
    update_schedule,
)


class _Payload(BaseModel):
    value: int


def _registry():
    return ScheduledTaskRegistry(
        [
            ScheduledTaskRegistration(
                name="test.record",
                contract_version=2,
                payload_model=_Payload,
                execute=lambda _context, _payload: None,
                required_permission=Permissions.MANAGE_SYSTEM,
            )
        ]
    )


def _factory():
    database = create_engine("sqlite://")
    Schedule.__table__.create(database)
    return sessionmaker(bind=database, expire_on_commit=False)


def test_schedule_create_update_and_delete_use_revisions():
    factory = _factory()
    registry = _registry()
    with factory() as session, session.begin():
        schedule = create_schedule(
            session,
            registry,
            username="admin",
            task_name="test.record",
            payload={"value": 1},
            trigger_type="date",
            trigger_data={"run_at": "2026-01-01T00:00:00+00:00"},
            timezone="UTC",
            enabled=True,
            now=100.0,
        )
        schedule_id = schedule.id
        assert schedule.task_contract_version == 2
        assert schedule_response(schedule, registry)["task_available"] is True

    with factory() as session, session.begin():
        updated = update_schedule(
            session,
            registry,
            schedule_id,
            1,
            {"payload": {"value": 2}, "enabled": False},
            username="admin",
            now=200.0,
        )
        assert updated.revision == 2
        assert updated.payload == {"value": 2}
        assert updated.enabled is False

    with factory() as session, session.begin():
        delete_schedule(session, schedule_id, 2, username="admin", now=300.0)
        deleted = session.get(Schedule, schedule_id)
        assert deleted.status == "deleted"
        assert deleted.revision == 3


def test_schedule_update_rejects_stale_revision():
    factory = _factory()
    registry = _registry()
    with factory() as session, session.begin():
        schedule = create_schedule(
            session,
            registry,
            username="admin",
            task_name="test.record",
            payload={"value": 1},
            trigger_type="interval",
            trigger_data={"seconds": 60, "start_at": "2026-01-01T00:00:00+00:00"},
            timezone="UTC",
            enabled=True,
            now=100.0,
        )
        schedule_id = schedule.id

    with factory() as session, session.begin():
        with pytest.raises(ScheduleConflictError, match="stale"):
            update_schedule(
                session,
                registry,
                schedule_id,
                2,
                {},
                username="admin",
            )
