import pytest
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from include.database.models.scheduling import Schedule
from include.domains.access.permissions import Permissions
from include.scheduling import ScheduledTaskRegistration, ScheduledTaskRegistry
from include.scheduling import commands as scheduling_commands
from include.scheduling.commands import (
    ScheduleConflictError,
    create_schedule,
    delete_schedule,
    schedule_response,
    update_schedule,
)

pytestmark = pytest.mark.component


class _Payload(BaseModel):
    value: int


@pytest.fixture
def registry():
    return ScheduledTaskRegistry(
        [
            ScheduledTaskRegistration(
                name="test.record",
                contract_version=2,
                payload_model=_Payload,
                execute=lambda _context, _payload: None,
                required_permission=Permissions.MANAGE_SYSTEM,
            ),
            ScheduledTaskRegistration(
                name="test.system_cleanup",
                contract_version=1,
                payload_model=_Payload,
                execute=lambda _context, _payload: None,
                user_schedulable=False,
            ),
        ]
    )


@pytest.fixture
def schedule_sessions(schedule_database):
    return sessionmaker(bind=schedule_database, expire_on_commit=False)


@pytest.fixture
def user_schedule_id(schedule_sessions, registry):
    with schedule_sessions.begin() as session:
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
        return schedule.id


def test_schedule_creation_persists_contract_and_initial_revision(
    schedule_sessions, registry
):
    with schedule_sessions.begin() as session:
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

    with schedule_sessions() as session:
        persisted = session.get(Schedule, schedule_id)
        assert persisted.task_contract_version == 2
        assert persisted.revision == 1
        assert persisted.payload == {"value": 1}
        assert schedule_response(persisted, registry)["task_available"] is True


def test_schedule_update_persists_changes_and_increments_revision(
    schedule_sessions, registry, user_schedule_id
):
    with schedule_sessions.begin() as session:
        update_schedule(
            session,
            registry,
            user_schedule_id,
            1,
            {"payload": {"value": 2}, "enabled": False},
            username="admin",
            now=200.0,
        )

    with schedule_sessions() as session:
        updated = session.get(Schedule, user_schedule_id)
        assert updated.revision == 2
        assert updated.payload == {"value": 2}
        assert updated.enabled is False


def test_schedule_deletion_persists_terminal_status_and_increments_revision(
    schedule_sessions, user_schedule_id
):
    with schedule_sessions.begin() as session:
        delete_schedule(session, user_schedule_id, 1, username="admin", now=300.0)

    with schedule_sessions() as session:
        deleted = session.get(Schedule, user_schedule_id)
        assert deleted.status == "deleted"
        assert deleted.revision == 2


def test_schedule_creation_uses_database_clock(
    monkeypatch, schedule_sessions, registry
):
    monkeypatch.setattr(scheduling_commands, "database_now", lambda _session: 100.0)

    with schedule_sessions.begin() as session:
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
        )
        schedule_id = schedule.id

    with schedule_sessions() as session:
        schedule = session.get(Schedule, schedule_id)
        assert schedule.created_at == 100.0
        assert schedule.updated_at == 100.0


def test_schedule_update_uses_database_clock(
    monkeypatch, schedule_sessions, registry, user_schedule_id
):
    monkeypatch.setattr(scheduling_commands, "database_now", lambda _session: 200.0)

    with schedule_sessions.begin() as session:
        update_schedule(
            session,
            registry,
            user_schedule_id,
            1,
            {"payload": {"value": 2}},
            username="admin",
        )

    with schedule_sessions() as session:
        assert session.get(Schedule, user_schedule_id).updated_at == 200.0


def test_schedule_deletion_uses_database_clock(
    monkeypatch, schedule_sessions, user_schedule_id
):
    monkeypatch.setattr(scheduling_commands, "database_now", lambda _session: 300.0)

    with schedule_sessions.begin() as session:
        delete_schedule(session, user_schedule_id, 1, username="admin")

    with schedule_sessions() as session:
        schedule = session.get(Schedule, user_schedule_id)
        assert schedule.updated_at == 300.0
        assert schedule.deleted_at == 300.0


def test_schedule_update_rejects_stale_revision(
    schedule_sessions, registry, user_schedule_id
):
    with (
        schedule_sessions.begin() as session,
        pytest.raises(ScheduleConflictError, match="Schedule revision is stale"),
    ):
        update_schedule(
            session,
            registry,
            user_schedule_id,
            2,
            {},
            username="admin",
            now=200.0,
        )

    with schedule_sessions() as session:
        schedule = session.get(Schedule, user_schedule_id)
        assert schedule.revision == 1
        assert schedule.payload == {"value": 1}


def test_system_task_cannot_be_scheduled_by_users(schedule_sessions, registry):
    with (
        schedule_sessions.begin() as session,
        pytest.raises(LookupError, match="test.system_cleanup.*system managed"),
    ):
        create_schedule(
            session,
            registry,
            username="admin",
            task_name="test.system_cleanup",
            payload={"value": 1},
            trigger_type="date",
            trigger_data={"run_at": "2026-01-01T00:00:00+00:00"},
            timezone="UTC",
            enabled=True,
            now=100.0,
        )

    with schedule_sessions() as session:
        assert session.scalars(select(Schedule)).all() == []


@pytest.mark.parametrize("operation", ["update", "delete"])
def test_system_schedule_rejects_user_mutations(schedule_sessions, registry, operation):
    with schedule_sessions.begin() as session:
        session.add(
            Schedule(
                id="test.system_cleanup",
                task_name="test.system_cleanup",
                task_contract_version=1,
                payload={"value": 1},
                trigger_type="interval",
                trigger_data={"seconds": 60, "start_at": "2026-01-01T00:00:00+00:00"},
                timezone="UTC",
                system_managed=True,
                next_run_at=100.0,
                created_by=None,
                updated_by=None,
            )
        )

    with schedule_sessions.begin() as session:
        if operation == "update":
            with pytest.raises(ScheduleConflictError, match="cannot be updated"):
                update_schedule(
                    session,
                    registry,
                    "test.system_cleanup",
                    1,
                    {},
                    username="admin",
                    now=200.0,
                )
        else:
            with pytest.raises(ScheduleConflictError, match="cannot be deleted"):
                delete_schedule(
                    session, "test.system_cleanup", 1, username="admin", now=200.0
                )

    with schedule_sessions() as session:
        schedule = session.get(Schedule, "test.system_cleanup")
        assert schedule.revision == 1
        assert schedule.status == "active"
        assert schedule.system_managed is True
