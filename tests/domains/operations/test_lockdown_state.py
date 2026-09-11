import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from threading import Event

import orjson
import pytest
import tomlkit
from pydantic import ValidationError
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from include.database.models.files import File, FileTask, FileTaskStatus, TransferMode
from include.database.models.operations import SystemStateEntry
from include.domains.operations.handlers.system import RequestLockdownHandler
from include.domains.operations.lockdown import (
    LockdownSource,
    LockdownState,
    LockdownTransitionOutcome,
    ScheduledLockdownActivation,
    apply_automatic_lockdown,
    apply_lockdown,
    apply_scheduled_lockdown,
    disable_scheduled_lockdown,
    expire_scheduled_lockdown,
    lockdown_state_manager,
)
from include.domains.operations.lockdown import commands as lockdown
from include.domains.operations.lockdown import state as lockdown_state

_REAL_CANCEL_PENDING_FILE_TASKS = lockdown._cancel_pending_file_tasks


@pytest.fixture
def lockdown_database(monkeypatch, tmp_path):
    database_path = tmp_path / "lockdown.db"
    engine = create_engine(f"sqlite:///{database_path}", connect_args={"timeout": 30})

    @event.listens_for(engine, "connect")
    def _configure_sqlite(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

    SystemStateEntry.metadata.create_all(
        engine,
        tables=[SystemStateEntry.__table__, File.__table__, FileTask.__table__],
    )
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(lockdown, "Session", sessions)
    monkeypatch.setattr(lockdown_state, "Session", sessions)
    monkeypatch.setattr(
        lockdown, "_cancel_pending_file_tasks", lambda _session: ([], 0)
    )
    monkeypatch.setattr(lockdown, "publish_cancelled_file_tasks", lambda _ids: None)
    monkeypatch.setattr(lockdown, "_publish_lockdown_state", lambda _state: None)
    monkeypatch.setattr(lockdown, "_notify_schedule_change", lambda: None)
    yield sessions, database_path
    engine.dispose()


def test_lockdown_reason_is_replaced_and_persisted(lockdown_database) -> None:
    sessions, database_path = lockdown_database

    apply_lockdown(True, "First maintenance window")
    assert lockdown_state_manager.get_state() == LockdownState(
        enabled=True, reason="First maintenance window"
    )
    apply_lockdown(False)
    assert lockdown_state_manager.get_state() == LockdownState()
    apply_lockdown(True)
    assert lockdown_state_manager.get_state() == LockdownState(enabled=True)

    sessions.kw["bind"].dispose()
    reopened_engine = create_engine(f"sqlite:///{database_path}")
    reopened_sessions = sessionmaker(bind=reopened_engine)
    lockdown_state.Session = reopened_sessions
    try:
        assert lockdown_state_manager.get_state() == LockdownState(enabled=True)
    finally:
        reopened_engine.dispose()


def test_active_lockdown_reason_update_skips_transition_side_effects(
    monkeypatch, lockdown_database
) -> None:
    cancellations = []
    broadcasts = []

    monkeypatch.setattr(
        lockdown,
        "_cancel_pending_file_tasks",
        lambda _session: (cancellations.append(True) or [], 0),
    )
    monkeypatch.setattr(
        lockdown,
        "_publish_lockdown_state",
        broadcasts.append,
    )
    apply_lockdown(True, "Initial reason")
    cancellations.clear()
    broadcasts.clear()

    transition = apply_lockdown(True, "Corrected reason")

    assert transition.applied is True
    assert transition.previous_state == LockdownState(
        enabled=True, reason="Initial reason"
    )
    assert transition.state == LockdownState(enabled=True, reason="Corrected reason")
    assert transition.cancelled_file_tasks == 0
    assert cancellations == []
    assert broadcasts == [transition.state]


def test_active_lockdown_reason_can_be_cleared(lockdown_database) -> None:
    apply_lockdown(True, "Temporary reason")

    transition = apply_lockdown(True, None)

    assert transition.applied is True
    assert transition.state == LockdownState(enabled=True)
    assert lockdown_state_manager.get_state() == transition.state


def test_repeated_lockdown_requests_are_idempotent(
    monkeypatch, lockdown_database
) -> None:
    broadcasts = []
    apply_lockdown(True, "Stable reason")
    monkeypatch.setattr(lockdown, "_publish_lockdown_state", broadcasts.append)

    repeated_enable = apply_lockdown(True)
    assert repeated_enable.applied is False
    assert repeated_enable.state == LockdownState(enabled=True, reason="Stable reason")
    assert broadcasts == []

    monkeypatch.setattr(lockdown.time, "time", lambda: 100.0)
    apply_lockdown(False)
    monkeypatch.setattr(lockdown.time, "time", lambda: 200.0)
    repeated_disable = apply_lockdown(False)
    assert repeated_disable.applied is False
    assert lockdown_state_manager.get_last_disabled_at() == 100.0


def test_unlocked_state_rejects_a_reason() -> None:
    with pytest.raises(ValidationError) as error:
        LockdownState(reason="Invalid")

    assert error.value.errors()[0]["loc"] == ()
    assert error.value.errors()[0]["type"] == "value_error"


@pytest.mark.parametrize(
    ("values", "location", "error_type"),
    [
        ({"enabled": 1}, ("enabled",), "bool_type"),
        ({"enabled": True, "reason": 1}, ("reason",), "string_type"),
        (
            {"enabled": True, "reason": ""},
            ("reason",),
            "string_too_short",
        ),
        (
            {"enabled": True, "reason": "x" * 1025},
            ("reason",),
            "string_too_long",
        ),
    ],
)
def test_lockdown_state_uses_strict_validation(values, location, error_type) -> None:
    with pytest.raises(ValidationError) as error:
        LockdownState(**values)

    validation_error = error.value.errors()[0]
    assert validation_error["loc"] == location
    assert validation_error["type"] == error_type


@pytest.mark.parametrize(
    "data",
    [
        {"status": True},
        {"status": True, "reason": "Maintenance"},
        {"status": True, "reason": None},
        {"status": False},
    ],
)
def test_lockdown_request_model_accepts_valid_data(data) -> None:
    RequestLockdownHandler.request_model.model_validate(data)


@pytest.mark.parametrize(
    "data",
    [
        {"status": 1},
        {"status": True, "reason": ""},
        {"status": True, "reason": "x" * 1025},
        {"status": False, "reason": "Maintenance"},
        {"status": False, "reason": None},
        {"status": True, "unknown": True},
    ],
)
def test_lockdown_request_model_rejects_invalid_data(data) -> None:
    with pytest.raises(ValidationError):
        RequestLockdownHandler.request_model.model_validate(data)


def test_lockdown_payload_shape_is_stable(lockdown_database) -> None:
    sessions, _database_path = lockdown_database

    apply_lockdown(True, "Maintenance")

    with sessions() as session:
        entry = session.get(SystemStateEntry, ("core", "lockdown"))

    assert entry is not None
    assert entry.schema_version == 2
    assert entry.payload == {
        "enabled": True,
        "reason": "Maintenance",
        "source": "manual",
        "last_disabled_at": 0.0,
    }


@pytest.mark.parametrize(
    "payload",
    [
        [True, None, "manual", 0.0],
        {"enabled": True, "reason": None},
        {"enabled": True, "last_disabled_at": 0.0},
        {
            "enabled": True,
            "reason": None,
            "source": "manual",
            "last_disabled_at": 0.0,
            "unknown": True,
        },
        {
            "enabled": 1,
            "reason": None,
            "source": "manual",
            "last_disabled_at": 0.0,
        },
        {
            "enabled": False,
            "reason": "Invalid",
            "source": None,
            "last_disabled_at": 0.0,
        },
        {
            "enabled": True,
            "reason": None,
            "source": None,
            "last_disabled_at": 0.0,
        },
        {
            "enabled": False,
            "reason": None,
            "source": "manual",
            "last_disabled_at": 0.0,
        },
        {
            "enabled": True,
            "reason": None,
            "source": "unknown",
            "last_disabled_at": 0.0,
        },
        {
            "enabled": True,
            "reason": None,
            "source": "manual",
            "last_disabled_at": -1.0,
        },
        {
            "enabled": True,
            "reason": None,
            "source": "manual",
            "last_disabled_at": float("inf"),
        },
    ],
)
def test_invalid_persisted_lockdown_payload_is_rejected(
    lockdown_database, payload
) -> None:
    sessions, _database_path = lockdown_database
    with sessions.begin() as session:
        session.add(
            SystemStateEntry(
                owner="core",
                state_key="lockdown",
                schema_version=2,
                revision=1,
                payload=payload,
                updated_at=1.0,
            )
        )

    with pytest.raises(RuntimeError, match="Invalid persisted lockdown state"):
        lockdown_state_manager.get_state()


def test_unknown_lockdown_schema_version_is_rejected(lockdown_database) -> None:
    sessions, _database_path = lockdown_database
    with sessions.begin() as session:
        session.add(
            SystemStateEntry(
                owner="core",
                state_key="lockdown",
                schema_version=3,
                revision=1,
                payload={
                    "enabled": True,
                    "reason": None,
                    "last_disabled_at": 0.0,
                },
                updated_at=1.0,
            )
        )

    with pytest.raises(RuntimeError, match="Unsupported lockdown state schema"):
        lockdown_state_manager.get_state()


def test_enable_if_inactive_preserves_existing_reason(lockdown_database) -> None:
    initial = apply_lockdown(True, "Automatic", only_if_inactive=True)
    existing = apply_lockdown(True, "Replacement", only_if_inactive=True)

    assert initial.applied is True
    assert initial.state == LockdownState(enabled=True, reason="Automatic")
    assert existing.applied is False
    assert existing.state == initial.state


def test_legacy_lockdown_source_is_inferred_conservatively(lockdown_database) -> None:
    sessions, _database_path = lockdown_database
    with sessions.begin() as session:
        session.add(
            SystemStateEntry(
                owner="core",
                state_key="lockdown",
                schema_version=1,
                revision=1,
                payload={
                    "enabled": True,
                    "reason": "Legacy",
                    "last_disabled_at": 0.0,
                },
                updated_at=1.0,
            )
        )

    assert lockdown_state_manager.get_source() is LockdownSource.UNKNOWN
    assert (
        disable_scheduled_lockdown().outcome
        is LockdownTransitionOutcome.CONDITION_NOT_MET
    )


def test_legacy_scheduled_activation_is_inferred_as_scheduled(
    lockdown_database,
) -> None:
    sessions, _database_path = lockdown_database
    with sessions.begin() as session:
        session.add_all(
            [
                SystemStateEntry(
                    owner="core",
                    state_key="lockdown",
                    schema_version=1,
                    revision=2,
                    payload={
                        "enabled": True,
                        "reason": "Legacy window",
                        "last_disabled_at": 0.0,
                    },
                    updated_at=1.0,
                ),
                SystemStateEntry(
                    owner="core",
                    state_key="lockdown_activation",
                    schema_version=1,
                    revision=1,
                    payload={
                        "activation_id": "legacy-execution",
                        "expires_at": 200.0,
                        "lockdown_revision": 2,
                    },
                    updated_at=1.0,
                ),
            ]
        )

    assert lockdown_state_manager.get_source() is LockdownSource.SCHEDULED


def test_scheduled_lockdown_expires_only_after_its_deadline(
    monkeypatch, lockdown_database
) -> None:
    now = 100.0
    monkeypatch.setattr(lockdown, "database_now", lambda _session: now)
    monkeypatch.setattr(lockdown_state, "database_now", lambda _session: now)

    activated = apply_scheduled_lockdown("execution-1", 200.0, "Maintenance")

    assert activated.outcome is LockdownTransitionOutcome.APPLIED
    assert lockdown_state_manager.get_scheduled_activation() == (
        ScheduledLockdownActivation(
            activation_id="execution-1",
            expires_at=200.0,
            observed_at=100.0,
        )
    )
    assert (
        expire_scheduled_lockdown("execution-1").outcome
        is LockdownTransitionOutcome.CONDITION_NOT_MET
    )

    now = 200.0
    expired = expire_scheduled_lockdown("execution-1")

    assert expired.outcome is LockdownTransitionOutcome.APPLIED
    assert expired.state == LockdownState()
    assert lockdown_state_manager.get_scheduled_activation() is None
    assert lockdown_state_manager.get_last_disabled_at() == 200.0


def test_scheduled_lockdown_without_deadline_keeps_owned_activation(
    monkeypatch, lockdown_database
) -> None:
    sessions, _database_path = lockdown_database
    monkeypatch.setattr(lockdown, "database_now", lambda _session: 100.0)
    monkeypatch.setattr(lockdown_state, "database_now", lambda _session: 100.0)

    activated = apply_scheduled_lockdown("execution-1", None, "Maintenance")
    repeated = apply_scheduled_lockdown("execution-1", None, "Maintenance")

    assert activated.outcome is LockdownTransitionOutcome.APPLIED
    assert repeated.outcome is LockdownTransitionOutcome.UNCHANGED
    assert lockdown_state_manager.get_source() is LockdownSource.SCHEDULED
    assert lockdown_state_manager.get_scheduled_activation() == (
        ScheduledLockdownActivation(
            activation_id="execution-1",
            expires_at=None,
            observed_at=100.0,
        )
    )
    assert (
        expire_scheduled_lockdown("execution-1").outcome
        is LockdownTransitionOutcome.CONDITION_NOT_MET
    )
    with sessions() as session:
        activation = session.get(
            SystemStateEntry,
            ("core", "lockdown_activation"),
        )
    assert activation.schema_version == 2
    assert activation.payload["expires_at"] is None


def test_inconsistent_scheduled_source_is_treated_as_unknown(
    lockdown_database,
) -> None:
    sessions, _database_path = lockdown_database
    apply_scheduled_lockdown("execution-1", None, "Maintenance")
    with sessions.begin() as session:
        session.delete(
            session.get(
                SystemStateEntry,
                ("core", "lockdown_activation"),
            )
        )

    assert lockdown_state_manager.get_source() is LockdownSource.UNKNOWN
    assert (
        disable_scheduled_lockdown().outcome
        is LockdownTransitionOutcome.CONDITION_NOT_MET
    )


def test_scheduled_disable_applies_only_to_releasable_sources(
    monkeypatch, lockdown_database
) -> None:
    now = 100.0
    monkeypatch.setattr(lockdown, "database_now", lambda _session: now)
    monkeypatch.setattr(lockdown_state, "database_now", lambda _session: now)

    assert disable_scheduled_lockdown().outcome is LockdownTransitionOutcome.UNCHANGED

    apply_lockdown(True, "Manual")
    manual = disable_scheduled_lockdown()
    assert manual.outcome is LockdownTransitionOutcome.APPLIED
    assert manual.previous_source is LockdownSource.MANUAL

    apply_scheduled_lockdown("execution-1", 200.0, "Window")
    scheduled = disable_scheduled_lockdown()
    assert scheduled.outcome is LockdownTransitionOutcome.APPLIED
    assert scheduled.previous_source is LockdownSource.SCHEDULED
    assert lockdown_state_manager.get_scheduled_activation() is None

    apply_automatic_lockdown("Automatic")
    automatic = disable_scheduled_lockdown()
    assert automatic.outcome is LockdownTransitionOutcome.CONDITION_NOT_MET
    assert automatic.source is LockdownSource.AUTOMATIC
    assert lockdown_state_manager.get_state().enabled is True


def test_scheduled_lockdown_cannot_replace_or_expire_another_activation(
    monkeypatch, lockdown_database
) -> None:
    monkeypatch.setattr(lockdown, "database_now", lambda _session: 100.0)
    monkeypatch.setattr(lockdown_state, "database_now", lambda _session: 100.0)
    apply_scheduled_lockdown("execution-1", 200.0, "First")

    competing = apply_scheduled_lockdown("execution-2", 300.0, "Second")
    wrong_expiry = expire_scheduled_lockdown("execution-2")

    assert competing.outcome is LockdownTransitionOutcome.CONDITION_NOT_MET
    assert wrong_expiry.outcome is LockdownTransitionOutcome.CONDITION_NOT_MET
    assert lockdown_state_manager.get_state() == LockdownState(
        enabled=True,
        reason="First",
    )


def test_manual_reason_change_takes_over_scheduled_lockdown(
    monkeypatch, lockdown_database
) -> None:
    monkeypatch.setattr(lockdown, "database_now", lambda _session: 100.0)
    monkeypatch.setattr(lockdown_state, "database_now", lambda _session: 100.0)
    apply_scheduled_lockdown("execution-1", 200.0, "Maintenance")

    unchanged = apply_lockdown(True, "Maintenance")
    assert unchanged.outcome is LockdownTransitionOutcome.UNCHANGED
    assert lockdown_state_manager.get_scheduled_activation() is not None

    changed = apply_lockdown(True, "Emergency maintenance")

    assert changed.outcome is LockdownTransitionOutcome.APPLIED
    assert lockdown_state_manager.get_scheduled_activation() is None
    assert (
        expire_scheduled_lockdown("execution-1").outcome
        is LockdownTransitionOutcome.CONDITION_NOT_MET
    )


@pytest.mark.parametrize("expires_at", [None, 200.0])
def test_protective_lockdown_takes_over_without_replacing_public_reason(
    monkeypatch, lockdown_database, expires_at
) -> None:
    monkeypatch.setattr(lockdown, "database_now", lambda _session: 100.0)
    monkeypatch.setattr(lockdown_state, "database_now", lambda _session: 100.0)
    apply_scheduled_lockdown("execution-1", expires_at, "Maintenance")

    transition = apply_automatic_lockdown("Automatic security lockdown")

    assert transition.outcome is LockdownTransitionOutcome.APPLIED
    assert (
        transition.previous_state
        == transition.state
        == LockdownState(
            enabled=True,
            reason="Maintenance",
        )
    )
    assert transition.previous_source is LockdownSource.SCHEDULED
    assert transition.source is LockdownSource.AUTOMATIC
    assert lockdown_state_manager.get_scheduled_activation() is None


def test_automatic_lockdown_takes_over_manual_source(lockdown_database) -> None:
    apply_lockdown(True, "Operator maintenance")

    transition = apply_automatic_lockdown("Automatic security lockdown")

    assert transition.outcome is LockdownTransitionOutcome.APPLIED
    assert transition.previous_source is LockdownSource.MANUAL
    assert transition.source is LockdownSource.AUTOMATIC
    assert transition.state == LockdownState(
        enabled=True,
        reason="Operator maintenance",
    )
    assert lockdown_state_manager.get_source() is LockdownSource.AUTOMATIC


def test_reason_change_does_not_release_automatic_protection(
    lockdown_database,
) -> None:
    apply_automatic_lockdown("Automatic security lockdown")

    changed = apply_lockdown(True, "Investigating security incident")
    scheduled_disable = disable_scheduled_lockdown()

    assert changed.outcome is LockdownTransitionOutcome.APPLIED
    assert changed.source is LockdownSource.AUTOMATIC
    assert scheduled_disable.outcome is LockdownTransitionOutcome.CONDITION_NOT_MET
    assert lockdown_state_manager.get_state() == LockdownState(
        enabled=True,
        reason="Investigating security incident",
    )


def test_automatic_takeover_wins_race_with_scheduled_disable(
    monkeypatch,
    lockdown_database,
) -> None:
    apply_lockdown(True, "Operator maintenance")
    disable_reached_write = Event()
    allow_disable_retry = Event()
    persist_lockdown_state = lockdown._persist_lockdown_state
    disable_conflicted = False

    def persist_with_controlled_conflict(session, current, state, source, disabled_at):
        nonlocal disable_conflicted
        if not state.enabled and not disable_conflicted:
            disable_conflicted = True
            disable_reached_write.set()
            assert allow_disable_retry.wait(timeout=5)
            raise lockdown._LockdownCasConflict
        return persist_lockdown_state(session, current, state, source, disabled_at)

    monkeypatch.setattr(
        lockdown,
        "_persist_lockdown_state",
        persist_with_controlled_conflict,
    )

    with ThreadPoolExecutor(max_workers=1) as executor:
        disable_future = executor.submit(disable_scheduled_lockdown)
        assert disable_reached_write.wait(timeout=5)

        automatic = apply_automatic_lockdown("Automatic security lockdown")
        allow_disable_retry.set()
        scheduled_disable = disable_future.result(timeout=5)

    assert automatic.outcome is LockdownTransitionOutcome.APPLIED
    assert scheduled_disable.outcome is LockdownTransitionOutcome.CONDITION_NOT_MET
    assert lockdown_state_manager.get_state().enabled is True
    assert lockdown_state_manager.get_source() is LockdownSource.AUTOMATIC


def test_lockdown_cas_retries_are_bounded(monkeypatch, lockdown_database) -> None:
    attempts = []
    delays = []

    def lose_revision_race(*_args, **_kwargs):
        attempts.append(True)
        return False

    monkeypatch.setattr(lockdown_state, "create_system_state", lose_revision_race)
    monkeypatch.setattr(lockdown.time, "sleep", delays.append)

    with pytest.raises(
        RuntimeError,
        match="Failed to apply lockdown after repeated concurrent updates",
    ):
        apply_lockdown(True, "Contended")

    assert len(attempts) == lockdown._LOCKDOWN_CAS_MAX_ATTEMPTS
    assert delays == [
        lockdown._LOCKDOWN_CAS_RETRY_BASE_SECONDS * 2**attempt
        for attempt in range(lockdown._LOCKDOWN_CAS_MAX_ATTEMPTS - 1)
    ]
    assert lockdown_state_manager.get_state() == LockdownState()


def test_enable_if_inactive_has_single_concurrent_winner(
    monkeypatch, lockdown_database
) -> None:
    cancellations = []
    broadcasts = []

    def cancel(_session):
        cancellations.append(True)
        return [], 0

    monkeypatch.setattr(
        lockdown,
        "_cancel_pending_file_tasks",
        cancel,
    )
    monkeypatch.setattr(
        lockdown,
        "_publish_lockdown_state",
        lambda state: broadcasts.append(state),
    )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda reason: apply_lockdown(True, reason, only_if_inactive=True),
                [f"reason-{index}" for index in range(16)],
            )
        )

    assert sum(result.applied for result in results) == 1
    winning_states = [result.state for result in results if result.applied]
    assert lockdown_state_manager.get_state() == winning_states[0]
    assert cancellations == [True]
    assert broadcasts == winning_states


def test_transition_effects_are_published_after_commit(
    monkeypatch, lockdown_database
) -> None:
    observations = []
    monkeypatch.setattr(
        lockdown,
        "_cancel_pending_file_tasks",
        lambda _session: (["task-1"], 1),
    )
    monkeypatch.setattr(
        lockdown,
        "publish_cancelled_file_tasks",
        lambda task_ids: observations.append(
            ("tasks", task_ids, lockdown_state_manager.get_state())
        ),
    )
    monkeypatch.setattr(
        lockdown,
        "_publish_lockdown_state",
        lambda state: observations.append(
            ("lockdown", state, lockdown_state_manager.get_state())
        ),
    )

    transition = apply_lockdown(True, "Atomic")

    expected = LockdownState(enabled=True, reason="Atomic")
    assert transition.cancelled_file_tasks == 1
    assert observations == [
        ("tasks", ["task-1"], expected),
        ("lockdown", expected, expected),
    ]


def test_lockdown_cancels_active_file_tasks_in_its_transaction(
    monkeypatch, lockdown_database
) -> None:
    sessions, _database_path = lockdown_database
    with sessions.begin() as session:
        session.add(File(id="file", path="unused", size=1, active=True))
        session.add_all(
            [
                FileTask(
                    id="pending",
                    file_id="file",
                    status=FileTaskStatus.PENDING,
                    mode=TransferMode.DOWNLOAD,
                    start_time=1.0,
                ),
                FileTask(
                    id="running",
                    file_id="file",
                    status=FileTaskStatus.IN_PROGRESS,
                    mode=TransferMode.UPLOAD,
                    start_time=1.0,
                ),
                FileTask(
                    id="complete",
                    file_id="file",
                    status=FileTaskStatus.COMPLETED,
                    mode=TransferMode.DOWNLOAD,
                    start_time=1.0,
                ),
            ]
        )
    published = []
    monkeypatch.setattr(
        lockdown, "_cancel_pending_file_tasks", _REAL_CANCEL_PENDING_FILE_TASKS
    )
    monkeypatch.setattr(
        lockdown,
        "publish_cancelled_file_tasks",
        lambda task_ids: published.extend(task_ids),
    )

    transition = apply_lockdown(True, "Maintenance")

    assert transition.cancelled_file_tasks == 2
    assert set(published) == {"pending", "running"}
    with sessions() as session:
        assert session.get(FileTask, "pending").status == FileTaskStatus.CANCELLED
        assert session.get(FileTask, "running").status == FileTaskStatus.CANCELLED
        assert session.get(FileTask, "complete").status == FileTaskStatus.COMPLETED


def test_transition_rolls_back_when_task_cancellation_fails(
    monkeypatch, lockdown_database
) -> None:
    monkeypatch.setattr(
        lockdown,
        "_cancel_pending_file_tasks",
        lambda _session: (_ for _ in ()).throw(RuntimeError("cancel failed")),
    )

    with pytest.raises(RuntimeError, match="cancel failed"):
        apply_lockdown(True, "Atomic")

    assert lockdown_state_manager.get_state() == LockdownState()


def test_disable_persists_timestamp(monkeypatch, lockdown_database) -> None:
    apply_lockdown(True, "Automatic")
    monkeypatch.setattr(lockdown.time, "time", lambda: 1234.5)

    transition = apply_lockdown(False)

    assert transition.state == LockdownState()
    assert lockdown_state_manager.get_last_disabled_at() == 1234.5
    assert lockdown_state_manager.get_state() == LockdownState()


def _run_lockdown_process(runtime_dir: Path, action: str) -> dict:
    source_dir = Path(__file__).resolve().parents[3] / "src"
    script = """
import sys
import orjson
import include.database.models
from include.config.settings import global_config
from include.database.session import Base, engine
from include.domains.operations.lockdown import apply_lockdown, lockdown_state_manager
from include.providers.bootstrap import initialize_providers

Base.metadata.create_all(engine)
initialize_providers()
if sys.argv[1] == "enable":
    apply_lockdown(True, "Restart persistence")
elif sys.argv[1] == "disable":
    apply_lockdown(False)
print(orjson.dumps(lockdown_state_manager.get_state().as_response_data()).decode())
global_config.stop()
"""
    environment = os.environ.copy()
    environment["PYTHONPATH"] = str(source_dir)
    result = subprocess.run(
        [sys.executable, "-c", script, action],
        cwd=runtime_dir,
        env=environment,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return orjson.loads(result.stdout.strip().splitlines()[-1])


def test_lockdown_persists_across_process_restarts(tmp_path) -> None:
    runtime_dir = tmp_path / "runtime"
    runtime_dir.mkdir()
    source_dir = Path(__file__).resolve().parents[3] / "src"
    config = tomlkit.parse(
        (source_dir / "config.toml.sample").read_text(encoding="utf-8")
    )
    config["database"]["type"] = "sqlite"
    config["database"]["file"] = (runtime_dir / "app.db").as_posix()
    config["provider"]["storage"] = "local"
    config["provider"]["caching"] = "memory"
    config["provider"]["event_bus"] = "local"
    (runtime_dir / "config.toml").write_text(tomlkit.dumps(config), encoding="utf-8")
    (runtime_dir / "init").write_text("initialized\n", encoding="utf-8")

    assert _run_lockdown_process(runtime_dir, "enable") == {
        "status": True,
        "reason": "Restart persistence",
    }
    assert _run_lockdown_process(runtime_dir, "read") == {
        "status": True,
        "reason": "Restart persistence",
    }
    assert _run_lockdown_process(runtime_dir, "disable") == {
        "status": False,
        "reason": None,
    }
    assert _run_lockdown_process(runtime_dir, "read") == {
        "status": False,
        "reason": None,
    }
