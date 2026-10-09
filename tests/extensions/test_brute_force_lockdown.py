import time
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from types import SimpleNamespace

import orjson
import pytest
from pydantic import ValidationError
from sqlalchemy import ColumnDefault, select
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker

from include.config.constants import (
    FILE_TASK_EVENT_CHANNEL,
    GLOBAL_BROADCAST_EVENT_CHANNEL,
)
from include.config.validation import ConfigValidationError, SchedulingPolicy
from include.database import system_states
from include.database.models.files import File, FileTask, FileTaskStatus, TransferMode
from include.database.models.identity import User
from include.database.models.operations import AuditEntry, SystemStateEntry
from include.database.session import Base
from include.domains.documents.file_task_signals import watch_file_task
from include.domains.operations.commands import audit
from include.domains.operations.lockdown import (
    LockdownSource,
    LockdownState,
    LockdownTransitionOutcome,
    apply_automatic_lockdown,
    apply_lockdown,
    apply_scheduled_lockdown,
    disable_scheduled_lockdown,
    lockdown_state_manager,
)
from include.domains.operations.lockdown import commands as lockdown_commands
from include.domains.operations.lockdown import state as lockdown_state
from include.extensions.brute_force_lockdown import _extension as extension
from include.providers.events.local import LocalEventBusProvider
from include.providers.manager import ProviderManager
from include.providers.scheduling.local import LocalSchedulingProvider
from include.transport.request_handler import Result


def _config(**overrides):
    settings = {
        "window_seconds": 600,
        "failure_threshold": 50,
        "distinct_account_threshold": 10,
        "distinct_ip_threshold": 10,
        "reason": extension.DEFAULT_REASON,
    }
    settings.update(overrides)
    return {
        "extensions": {
            "enabled": ["brute_force_lockdown"],
            "brute_force_lockdown": settings,
        }
    }


@pytest.mark.unit
def test_policy_uses_defaults_when_extension_table_is_missing():
    policy = extension.BruteForceLockdownPolicy.from_config(
        {"extensions": {"enabled": ["brute_force_lockdown"]}}
    )

    assert policy == extension.BruteForceLockdownPolicy()


@pytest.mark.unit
@pytest.mark.parametrize(
    ("overrides", "field"),
    [
        ({"unknown": 1}, "unknown"),
        ({"window_seconds": True}, "window_seconds"),
        ({"failure_threshold": 0}, "failure_threshold"),
        ({"distinct_account_threshold": 51}, "distinct_account_threshold"),
        ({"distinct_ip_threshold": 51}, "distinct_ip_threshold"),
        ({"reason": "   "}, "reason"),
        ({"reason": " " + "x" * 1024}, "reason"),
    ],
)
def test_policy_rejects_invalid_values(overrides, field):
    with pytest.raises(ConfigValidationError) as error:
        extension.BruteForceLockdownPolicy.from_config(_config(**overrides))

    message = str(error.value)
    assert "extensions.brute_force_lockdown" in message
    assert field in message


@pytest.mark.unit
def test_policy_normalizes_configured_reason():
    policy = extension.BruteForceLockdownPolicy.from_config(
        _config(reason="  Automatic maintenance  ")
    )

    assert policy.reason == "Automatic maintenance"


@pytest.mark.unit
def test_policy_direct_construction_uses_pydantic_validation():
    with pytest.raises(ValidationError) as error:
        extension.BruteForceLockdownPolicy(window_seconds=True)

    validation_error = error.value.errors()[0]
    assert validation_error["loc"] == ("window_seconds",)
    assert validation_error["type"] == "int_type"


@pytest.fixture
def detector_context(monkeypatch, tmp_path, sqlite_engine_factory):
    engine = sqlite_engine_factory(tmp_path / "detector.db")

    clock = SimpleNamespace(now=1000.0)
    fixed_time = SimpleNamespace(time=lambda: clock.now, sleep=time.sleep)
    for module in (extension, lockdown_commands, system_states):
        monkeypatch.setattr(module, "time", fixed_time)
    for module in (lockdown_commands, lockdown_state):
        monkeypatch.setattr(module, "database_now", lambda _session: clock.now)
    monkeypatch.setattr(
        AuditEntry.__table__.c.logged_time,
        "default",
        ColumnDefault(lambda: clock.now),
    )
    monkeypatch.setattr(extension, "_STARTED_AT", 0.0)
    monkeypatch.setattr(
        extension,
        "global_config",
        _config(
            window_seconds=100,
            failure_threshold=3,
            distinct_account_threshold=2,
            distinct_ip_threshold=3,
        ),
    )

    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    for module in (extension, lockdown_commands, lockdown_state, audit):
        monkeypatch.setattr(module, "Session", sessions)

    provider_manager = ProviderManager()
    monkeypatch.setattr(provider_manager, "_providers", {})
    event_bus = LocalEventBusProvider()
    scheduling = LocalSchedulingProvider(SchedulingPolicy())
    provider_manager.register(event_bus)
    provider_manager.register(scheduling)
    events = []
    for channel in (GLOBAL_BROADCAST_EVENT_CHANNEL, FILE_TASK_EVENT_CHANNEL):
        event_bus.subscribe(
            channel,
            lambda message, channel=channel: events.append(
                (channel, orjson.loads(message))
            ),
        )

    try:
        with sessions.begin() as session:
            session.add_all(
                User(
                    username=username,
                    pass_hash="unused",
                    passwd_last_modified=0.0,
                    created_time=0.0,
                )
                for username in ("alice", "bob")
            )
        yield SimpleNamespace(sessions=sessions, clock=clock, events=events)
    finally:
        scheduling.shutdown()


def _audit_failure(session, username, ip_address, logged_time):
    session.add(
        AuditEntry(
            action="login",
            result=401,
            target=username,
            remote_address=ip_address,
            logged_time=logged_time,
        )
    )


@pytest.mark.component
@pytest.mark.parametrize(
    ("failures", "expected_counts"),
    [
        (
            [("alice", "192.0.2.1"), ("bob", "192.0.2.2")],
            None,
        ),
        (
            [("alice", "192.0.2.1")] * 3,
            None,
        ),
        (
            [
                ("alice", "192.0.2.1"),
                ("bob", "192.0.2.1"),
                ("alice", "192.0.2.1"),
            ],
            (3, 2, 1),
        ),
        (
            [
                ("alice", "192.0.2.1"),
                ("alice", "192.0.2.2"),
                ("alice", "192.0.2.3"),
            ],
            (3, 1, 3),
        ),
    ],
    ids=["below-failure-threshold", "below-distinct-thresholds", "accounts", "ips"],
)
def test_detector_uses_failure_and_either_distinct_threshold(
    detector_context, failures, expected_counts
):
    with detector_context.sessions.begin() as session:
        for username, ip_address in failures:
            _audit_failure(session, username, ip_address, 1000.0)

    extension.ext_post_request(
        "login",
        SimpleNamespace(data={}, remote_address="192.0.2.1"),
        Result(code=401, target="alice"),
        0.1,
    )

    with detector_context.sessions() as session:
        automatic_audit = session.scalars(
            select(AuditEntry).where(AuditEntry.action == "automatic_lockdown")
        ).one_or_none()
        if expected_counts is None:
            assert lockdown_state_manager.get_state() == LockdownState()
            assert automatic_audit is None
            assert detector_context.events == []
        else:
            assert lockdown_state_manager.get_state() == LockdownState(
                enabled=True, reason=extension.DEFAULT_REASON
            )
            assert lockdown_state_manager.get_source() is LockdownSource.AUTOMATIC
            assert automatic_audit is not None
            assert (
                automatic_audit.data["failure_count"],
                automatic_audit.data["distinct_accounts"],
                automatic_audit.data["distinct_ip_addresses"],
            ) == expected_counts
            assert detector_context.events == [
                (
                    GLOBAL_BROADCAST_EVENT_CHANNEL,
                    {
                        "event": "lockdown",
                        "data": {
                            "status": True,
                            "reason": extension.DEFAULT_REASON,
                        },
                    },
                )
            ]


@pytest.mark.component
@pytest.mark.parametrize(
    ("boundary", "window_started_at"),
    [("rolling", 900.0), ("startup", 930.0), ("unlock", 950.0)],
)
def test_detector_excludes_failures_before_its_window(
    detector_context, monkeypatch, boundary, window_started_at
):
    if boundary == "startup":
        monkeypatch.setattr(extension, "_STARTED_AT", window_started_at)
    elif boundary == "unlock":
        apply_lockdown(True, "Earlier maintenance")
        detector_context.clock.now = window_started_at
        apply_lockdown(False)
        assert lockdown_state_manager.get_last_disabled_at() == window_started_at
        detector_context.clock.now = 1000.0
        detector_context.events.clear()

    with detector_context.sessions.begin() as session:
        _audit_failure(session, "alice", "192.0.2.1", window_started_at - 1)
        _audit_failure(session, "alice", "192.0.2.1", window_started_at)
        _audit_failure(session, "alice", "192.0.2.2", 1000.0)
        _audit_failure(session, "unknown", "192.0.2.3", 1000.0)
        for action, result in (
            ("sso_oidc_callback", 401),
            ("login", 200),
            ("login", 429),
        ):
            session.add(
                AuditEntry(
                    action=action,
                    result=result,
                    target="bob",
                    remote_address="192.0.2.3",
                    logged_time=1000.0,
                )
            )

    extension.ext_post_request(
        "login",
        SimpleNamespace(data={}, remote_address="192.0.2.2"),
        Result(code=401, target="alice"),
        0.1,
    )

    assert lockdown_state_manager.get_state() == LockdownState()
    assert detector_context.events == []
    with detector_context.sessions.begin() as session:
        assert (
            session.scalars(
                select(AuditEntry).where(AuditEntry.action == "automatic_lockdown")
            ).one_or_none()
            is None
        )
        _audit_failure(session, "bob", "192.0.2.3", 1000.0)

    extension.ext_post_request(
        "login",
        SimpleNamespace(data={}, remote_address="192.0.2.3"),
        Result(code=401, target="bob"),
        0.1,
    )

    assert lockdown_state_manager.get_source() is LockdownSource.AUTOMATIC
    with detector_context.sessions() as session:
        automatic_audit = session.scalars(
            select(AuditEntry).where(AuditEntry.action == "automatic_lockdown")
        ).one()
        assert automatic_audit.data["failure_count"] == 3
        assert automatic_audit.data["window_started_at"] == window_started_at
        assert automatic_audit.data["observed_at"] == 1000.0


@pytest.mark.component
@pytest.mark.parametrize(
    ("action", "callback"),
    [
        ("login", None),
        ("login", Result(code=200, target="alice")),
        ("login", Result(code=202, target="alice")),
        ("login", Result(code=429, target="alice")),
        ("login", Result(code=401)),
        ("login", Result(code=401, target="")),
        ("login", Result(code=401, target="unknown")),
        ("sso_oidc_callback", Result(code=401, target="alice")),
    ],
)
def test_detector_ignores_non_credential_failures(detector_context, action, callback):
    with detector_context.sessions.begin() as session:
        _audit_failure(session, "alice", "192.0.2.1", 1000.0)
        _audit_failure(session, "bob", "192.0.2.2", 1000.0)
        _audit_failure(session, "alice", "192.0.2.3", 1000.0)

    extension.ext_post_request(
        action,
        SimpleNamespace(data={}, remote_address="192.0.2.1"),
        callback,
        0.1,
    )

    assert lockdown_state_manager.get_state() == LockdownState()
    assert detector_context.events == []
    with detector_context.sessions() as session:
        assert (
            session.scalars(
                select(AuditEntry).where(AuditEntry.action == "automatic_lockdown")
            ).one_or_none()
            is None
        )


@pytest.mark.component
def test_detector_cancels_file_tasks_and_audits_once(detector_context):
    with detector_context.sessions.begin() as session:
        _audit_failure(session, "alice", "192.0.2.1", 950.0)
        _audit_failure(session, "bob", "192.0.2.2", 960.0)
        _audit_failure(session, "alice", "192.0.2.3", 1000.0)
        session.add(File(id="file", path="unused", size=1, created_time=1.0))
        session.add_all(
            FileTask(
                id=task_id,
                file_id="file",
                status=status,
                mode=TransferMode.DOWNLOAD,
                start_time=1.0,
            )
            for task_id, status in (
                ("pending", FileTaskStatus.PENDING),
                ("running", FileTaskStatus.IN_PROGRESS),
                ("complete", FileTaskStatus.COMPLETED),
            )
        )

    with watch_file_task("pending") as pending, watch_file_task("running") as running:
        for _ in range(2):
            extension.ext_post_request(
                "login",
                SimpleNamespace(data={}, remote_address="192.0.2.3"),
                Result(code=401, target="alice"),
                0.1,
            )
        assert pending.is_set()
        assert running.is_set()

    assert lockdown_state_manager.get_state() == LockdownState(
        enabled=True, reason=extension.DEFAULT_REASON
    )
    assert lockdown_state_manager.get_source() is LockdownSource.AUTOMATIC
    with detector_context.sessions() as session:
        assert session.get(FileTask, "pending").status == FileTaskStatus.CANCELLED
        assert session.get(FileTask, "running").status == FileTaskStatus.CANCELLED
        assert session.get(FileTask, "complete").status == FileTaskStatus.COMPLETED
        automatic_audit = session.scalars(
            select(AuditEntry).where(AuditEntry.action == "automatic_lockdown")
        ).one()
        assert automatic_audit.result == 0
        assert automatic_audit.logged_time == 1000.0
        assert automatic_audit.username is None
        assert automatic_audit.target is None
        assert automatic_audit.remote_address is None
        assert automatic_audit.data == {
            "source_extension": "brute_force_lockdown",
            "window_seconds": 100,
            "window_started_at": 900.0,
            "observed_at": 1000.0,
            "failure_count": 3,
            "distinct_accounts": 2,
            "distinct_ip_addresses": 3,
            "failure_threshold": 3,
            "distinct_account_threshold": 2,
            "distinct_ip_threshold": 3,
            "cancelled_file_tasks": 2,
            "scheduled_takeover": False,
            "previous_lockdown_source": None,
        }

    cancellation_events = [
        payload
        for channel, payload in detector_context.events
        if channel == FILE_TASK_EVENT_CHANNEL
    ]
    assert len(cancellation_events) == 1
    assert set(cancellation_events[0]["cancelled"]) == {"pending", "running"}
    assert [
        payload
        for channel, payload in detector_context.events
        if channel == GLOBAL_BROADCAST_EVENT_CHANNEL
    ] == [
        {
            "event": "lockdown",
            "data": {"status": True, "reason": extension.DEFAULT_REASON},
        }
    ]


@pytest.mark.component
def test_concurrent_detector_callbacks_have_one_transition_and_audit(detector_context):
    with detector_context.sessions.begin() as session:
        _audit_failure(session, "alice", "192.0.2.1", 950.0)
        _audit_failure(session, "bob", "192.0.2.2", 960.0)
        _audit_failure(session, "alice", "192.0.2.3", 1000.0)
    barrier = Barrier(4)

    def detect():
        barrier.wait(timeout=5)
        extension.ext_post_request(
            "login",
            SimpleNamespace(data={}, remote_address="192.0.2.3"),
            Result(code=401, target="alice"),
            0.1,
        )

    with ThreadPoolExecutor(max_workers=4) as executor:
        futures = [executor.submit(detect) for _ in range(4)]
        for future in futures:
            future.result(timeout=10)

    assert lockdown_state_manager.get_source() is LockdownSource.AUTOMATIC
    assert len(detector_context.events) == 1
    assert detector_context.events[0][0] == GLOBAL_BROADCAST_EVENT_CHANNEL
    with detector_context.sessions() as session:
        assert (
            session.scalars(
                select(AuditEntry).where(AuditEntry.action == "automatic_lockdown")
            )
            .one()
            .data["failure_count"]
            == 3
        )


@pytest.mark.component
@pytest.mark.parametrize("source", [LockdownSource.MANUAL, LockdownSource.SCHEDULED])
def test_detector_takes_over_releasable_lockdown_without_changing_reason(
    detector_context, source
):
    if source is LockdownSource.MANUAL:
        apply_lockdown(True, "Existing maintenance")
    else:
        apply_scheduled_lockdown(
            "scheduled-maintenance", 1100.0, "Existing maintenance"
        )
    detector_context.events.clear()
    with detector_context.sessions.begin() as session:
        _audit_failure(session, "alice", "192.0.2.1", 950.0)
        _audit_failure(session, "bob", "192.0.2.2", 960.0)
        _audit_failure(session, "alice", "192.0.2.3", 1000.0)

    extension.ext_post_request(
        "login",
        SimpleNamespace(data={}, remote_address="192.0.2.3"),
        Result(code=401, target="alice"),
        0.1,
    )

    assert lockdown_state_manager.get_state() == LockdownState(
        enabled=True, reason="Existing maintenance"
    )
    assert lockdown_state_manager.get_source() is LockdownSource.AUTOMATIC
    assert lockdown_state_manager.get_scheduled_activation() is None
    assert detector_context.events == []
    assert (
        disable_scheduled_lockdown().outcome
        is LockdownTransitionOutcome.CONDITION_NOT_MET
    )
    assert lockdown_state_manager.get_source() is LockdownSource.AUTOMATIC
    with detector_context.sessions() as session:
        automatic_audit = session.scalars(
            select(AuditEntry).where(AuditEntry.action == "automatic_lockdown")
        ).one()
        assert automatic_audit.data["previous_lockdown_source"] == source.value
        assert automatic_audit.data["scheduled_takeover"] is (
            source is LockdownSource.SCHEDULED
        )
        assert automatic_audit.data["cancelled_file_tasks"] == 0


@pytest.mark.component
@pytest.mark.parametrize("source", [LockdownSource.AUTOMATIC, LockdownSource.UNKNOWN])
def test_detector_preserves_existing_protected_lockdown(detector_context, source):
    if source is LockdownSource.AUTOMATIC:
        apply_automatic_lockdown("Existing protection")
    else:
        with detector_context.sessions.begin() as session:
            session.add(
                SystemStateEntry(
                    owner="core",
                    state_key="lockdown",
                    schema_version=1,
                    revision=1,
                    payload={
                        "enabled": True,
                        "reason": "Existing protection",
                        "last_disabled_at": 0.0,
                    },
                    updated_at=1.0,
                )
            )
    detector_context.events.clear()
    with detector_context.sessions.begin() as session:
        _audit_failure(session, "alice", "192.0.2.1", 950.0)
        _audit_failure(session, "bob", "192.0.2.2", 960.0)
        _audit_failure(session, "alice", "192.0.2.3", 1000.0)

    extension.ext_post_request(
        "login",
        SimpleNamespace(data={}, remote_address="192.0.2.3"),
        Result(code=401, target="alice"),
        0.1,
    )

    assert lockdown_state_manager.get_state() == LockdownState(
        enabled=True, reason="Existing protection"
    )
    assert lockdown_state_manager.get_source() is source
    assert detector_context.events == []
    with detector_context.sessions() as session:
        assert (
            session.scalars(
                select(AuditEntry).where(AuditEntry.action == "automatic_lockdown")
            ).one_or_none()
            is None
        )


@pytest.mark.component
def test_detector_database_failure_does_not_break_login(detector_context, monkeypatch):
    callback = Result(code=401, target="alice")
    records = []
    sink = extension.logger.add(lambda message: records.append(message.record))

    def unavailable_session():
        raise OperationalError("SELECT", {}, RuntimeError("database unavailable"))

    try:
        monkeypatch.setattr(extension, "Session", unavailable_session)
        extension.ext_post_request(
            "login",
            SimpleNamespace(data={}, remote_address="192.0.2.1"),
            callback,
            0.1,
        )
    finally:
        extension.logger.remove(sink)

    assert callback == Result(code=401, target="alice")
    assert lockdown_state_manager.get_state() == LockdownState()
    assert detector_context.events == []
    assert any(
        record["message"] == "Failed to evaluate automatic brute-force lockdown"
        and record["exception"].type is OperationalError
        for record in records
    )
    with detector_context.sessions() as session:
        assert (
            session.scalars(
                select(AuditEntry).where(AuditEntry.action == "automatic_lockdown")
            ).one_or_none()
            is None
        )
