import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace

import orjson
import pytest
import tomlkit
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from include.database.models.files import File, FileTask, FileTaskStatus, TransferMode
from include.database.models.operations import SystemStateEntry
from include.database.system_states import create_system_state
from include.domains.operations import lockdown
from include.domains.operations.lockdown import (
    LockdownState,
    apply_lockdown,
    initialize_lockdown_state,
    lockdown_state_manager,
)
from include.providers.caching.memory import MemoryCachingProvider

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
    monkeypatch.setattr(
        lockdown, "_cancel_pending_file_tasks", lambda _session: ([], 0)
    )
    monkeypatch.setattr(lockdown, "publish_cancelled_file_tasks", lambda _ids: None)
    monkeypatch.setattr(lockdown, "_publish_lockdown_state", lambda _state: None)
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
    lockdown.Session = reopened_sessions
    try:
        assert lockdown_state_manager.get_state() == LockdownState(enabled=True)
    finally:
        reopened_engine.dispose()


def test_legacy_lockdown_state_is_imported(monkeypatch, lockdown_database) -> None:
    cache = MemoryCachingProvider()
    cache.set("system:lockdown", "1")
    cache.set("system:lockdown:last_disabled", 123.5)
    monkeypatch.setattr(
        lockdown, "ProviderManager", lambda: SimpleNamespace(caching=cache)
    )

    initialize_lockdown_state()

    assert lockdown_state_manager.get_state() == LockdownState(enabled=True)
    assert lockdown_state_manager.get_last_disabled_at() == 123.5
    assert cache.get("system:lockdown") is None
    assert cache.get("system:lockdown:last_disabled") is None


def test_invalid_legacy_state_imports_locked(monkeypatch, lockdown_database) -> None:
    cache = MemoryCachingProvider()
    cache.set("system:lockdown", b"invalid")
    monkeypatch.setattr(
        lockdown, "ProviderManager", lambda: SimpleNamespace(caching=cache)
    )

    initialize_lockdown_state()

    assert lockdown_state_manager.get_state() == LockdownState(enabled=True)


@pytest.mark.parametrize(
    ("schema_version", "payload", "message"),
    [
        (
            2,
            {"enabled": True, "reason": None, "last_disabled_at": 0.0},
            "schema version",
        ),
        (1, {"enabled": True, "reason": None}, "fields"),
        (
            1,
            {"enabled": False, "reason": "invalid", "last_disabled_at": 0.0},
            "persisted lockdown state",
        ),
    ],
)
def test_invalid_persisted_lockdown_state_fails_startup(
    monkeypatch,
    lockdown_database,
    schema_version,
    payload,
    message,
) -> None:
    cache = MemoryCachingProvider()
    monkeypatch.setattr(
        lockdown, "ProviderManager", lambda: SimpleNamespace(caching=cache)
    )
    sessions, _database_path = lockdown_database
    with sessions.begin() as session:
        assert create_system_state(
            session,
            "core",
            "lockdown",
            schema_version=schema_version,
            payload=payload,
        )

    with pytest.raises(RuntimeError, match=message):
        initialize_lockdown_state()


def test_unlocked_state_rejects_a_reason() -> None:
    with pytest.raises(ValueError, match="reason requires lockdown"):
        LockdownState(reason="Invalid")


def test_lockdown_reason_length_is_validated() -> None:
    with pytest.raises(ValueError, match="1 to 1024"):
        LockdownState(enabled=True, reason="")
    with pytest.raises(ValueError, match="1 to 1024"):
        LockdownState(enabled=True, reason="x" * 1025)


def test_enable_if_inactive_preserves_existing_reason(lockdown_database) -> None:
    initial = apply_lockdown(True, "Automatic", only_if_inactive=True)
    existing = apply_lockdown(True, "Replacement", only_if_inactive=True)

    assert initial.applied is True
    assert initial.state == LockdownState(enabled=True, reason="Automatic")
    assert existing.applied is False
    assert existing.state == initial.state


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
