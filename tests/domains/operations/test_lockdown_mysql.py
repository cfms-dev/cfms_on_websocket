import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from include.database.clock import database_now
from include.database.models.files import File, FileTask, FileTaskStatus, TransferMode
from include.database.models.operations import SystemStateEntry
from include.domains.operations.lockdown import (
    LockdownSource,
    LockdownTransitionOutcome,
    apply_scheduled_lockdown,
    expire_scheduled_lockdown,
)
from include.domains.operations.lockdown import commands as lockdown
from include.domains.operations.lockdown import state as lockdown_state

pytestmark = pytest.mark.integration


@pytest.fixture
def mysql_lockdown_sessions(monkeypatch, mysql_pure_engine):
    metadata = SystemStateEntry.metadata
    metadata.drop_all(mysql_pure_engine)
    try:
        metadata.create_all(mysql_pure_engine)
        sessions = sessionmaker(bind=mysql_pure_engine)
        monkeypatch.setattr(lockdown, "Session", sessions)
        monkeypatch.setattr(lockdown_state, "Session", sessions)
        monkeypatch.setattr(lockdown, "publish_cancelled_file_tasks", lambda _ids: None)
        monkeypatch.setattr(lockdown, "_publish_lockdown_state", lambda _state: None)
        monkeypatch.setattr(lockdown, "_notify_schedule_change", lambda: None)
        yield sessions
    finally:
        metadata.drop_all(mysql_pure_engine)


@pytest.mark.parametrize("existing_disabled_state", [False, True])
def test_mysql_scheduled_lockdown_window_persists_and_expires(
    mysql_lockdown_sessions, existing_disabled_state
):
    with mysql_lockdown_sessions.begin() as session:
        now = database_now(session)
        if existing_disabled_state:
            session.add(
                SystemStateEntry(
                    owner="core",
                    state_key="lockdown",
                    schema_version=2,
                    revision=4,
                    payload={
                        "enabled": False,
                        "reason": None,
                        "source": None,
                        "last_disabled_at": 1.0,
                    },
                    updated_at=1.0,
                )
            )
        file = File(id="file", path="pending-file")
        session.add(file)
        session.add_all(
            FileTask(
                id=status.name,
                file=file,
                mode=TransferMode.UPLOAD,
                status=status,
                start_time=now,
                end_time=now + 300,
            )
            for status in (
                FileTaskStatus.PENDING,
                FileTaskStatus.IN_PROGRESS,
                FileTaskStatus.COMPLETED,
            )
        )

    expires_at = now + 60
    activated = apply_scheduled_lockdown("mysql-execution", expires_at, "Maintenance")

    assert activated.outcome is LockdownTransitionOutcome.APPLIED
    assert activated.source is LockdownSource.SCHEDULED
    assert activated.cancelled_file_tasks == 2
    expected_revision = 5 if existing_disabled_state else 1
    with mysql_lockdown_sessions() as session:
        state = session.get(SystemStateEntry, ("core", "lockdown"))
        activation = session.get(SystemStateEntry, ("core", "lockdown_activation"))
        assert state is not None
        assert state.revision == expected_revision
        assert state.payload == {
            "enabled": True,
            "reason": "Maintenance",
            "source": "scheduled",
            "last_disabled_at": 1.0 if existing_disabled_state else 0.0,
        }
        assert activation is not None
        assert activation.revision == 1
        assert activation.payload == {
            "activation_id": "mysql-execution",
            "expires_at": expires_at,
            "lockdown_revision": expected_revision,
        }
        tasks = dict(session.execute(select(FileTask.id, FileTask.status)).all())
        assert tasks == {
            "PENDING": FileTaskStatus.CANCELLED,
            "IN_PROGRESS": FileTaskStatus.CANCELLED,
            "COMPLETED": FileTaskStatus.COMPLETED,
        }

    repeated = apply_scheduled_lockdown("mysql-execution", expires_at, "Maintenance")
    assert repeated.outcome is LockdownTransitionOutcome.UNCHANGED
    assert repeated.cancelled_file_tasks == 0
    assert (
        expire_scheduled_lockdown("mysql-execution").outcome
        is LockdownTransitionOutcome.CONDITION_NOT_MET
    )

    with mysql_lockdown_sessions.begin() as session:
        state = session.get(SystemStateEntry, ("core", "lockdown"))
        activation = session.get(SystemStateEntry, ("core", "lockdown_activation"))
        assert state.revision == expected_revision
        assert activation.revision == 1
        activation.payload = {
            **activation.payload,
            "expires_at": database_now(session) - 1,
        }

    expired = expire_scheduled_lockdown("mysql-execution")
    assert expired.outcome is LockdownTransitionOutcome.APPLIED
    assert expired.state.enabled is False
    assert expired.source is None
    with mysql_lockdown_sessions() as session:
        state = session.get(SystemStateEntry, ("core", "lockdown"))
        assert state.revision == expected_revision + 1
        assert state.payload["enabled"] is False
        assert state.payload["source"] is None
        assert state.payload["last_disabled_at"] >= expires_at - 60
        assert session.get(SystemStateEntry, ("core", "lockdown_activation")) is None
