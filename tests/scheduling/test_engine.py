import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest
from pydantic import BaseModel
from sqlalchemy import create_engine, event, select, update
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from include.config.validation import SchedulingPolicy
from include.database.models.scheduling import (
    Schedule,
    ScheduleExecution,
    SchedulingRuntimeState,
)
from include.domains.access.permissions import Permissions
from include.scheduling import (
    ScheduledTaskRegistration,
    ScheduledTaskRegistry,
    ScheduledTaskResult,
    SystemScheduleDefinition,
)
from include.scheduling import engine as scheduling_engine
from include.scheduling.commands import (
    ScheduleConflictError,
    delete_schedule,
    update_schedule,
)


class _Payload(BaseModel):
    value: int


class _EmptyPayload(BaseModel):
    pass


def _session_factory(monkeypatch):
    database = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SchedulingRuntimeState.__table__.create(database)
    Schedule.__table__.create(database)
    ScheduleExecution.__table__.create(database)
    factory = sessionmaker(bind=database)
    monkeypatch.setattr(scheduling_engine, "Session", factory)
    return factory


def _file_session_factory(monkeypatch, tmp_path):
    database = create_engine(
        f"sqlite:///{tmp_path / 'scheduling.db'}",
        connect_args={"timeout": 10},
    )
    SchedulingRuntimeState.__table__.create(database)
    Schedule.__table__.create(database)
    ScheduleExecution.__table__.create(database)
    factory = sessionmaker(bind=database)
    monkeypatch.setattr(scheduling_engine, "Session", factory)
    return database, factory


def _assert_concurrent_runtime_initialization(monkeypatch, database) -> None:
    factory = sessionmaker(bind=database)
    monkeypatch.setattr(scheduling_engine, "Session", factory)
    insert_barrier = threading.Barrier(2)

    @event.listens_for(database, "before_cursor_execute")
    def synchronize_runtime_inserts(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        if (
            statement.lstrip()
            .upper()
            .startswith("INSERT INTO SCHEDULING_RUNTIME_STATE")
        ):
            insert_barrier.wait(timeout=10)

    try:
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(
                    scheduling_engine.ensure_runtime_state,
                    "redis",
                    "test-cluster",
                    now=100.0,
                )
                for _ in range(2)
            ]
            generations = tuple(future.result(timeout=15) for future in futures)
    finally:
        event.remove(database, "before_cursor_execute", synchronize_runtime_inserts)

    with factory() as session:
        states = tuple(session.scalars(select(SchedulingRuntimeState)))
        assert generations == (1, 1)
        assert [(state.provider, state.generation) for state in states] == [
            ("redis", 1)
        ]


@pytest.mark.parametrize(
    ("dialect_name", "expected_clause"),
    [
        ("sqlite", "ON CONFLICT (id) DO NOTHING"),
        ("postgresql", "ON CONFLICT (id) DO NOTHING"),
        ("mysql", "ON DUPLICATE KEY UPDATE id = scheduling_runtime_state.id"),
    ],
)
def test_runtime_state_upsert_uses_supported_dialect_syntax(
    dialect_name,
    expected_clause,
) -> None:
    from sqlalchemy.dialects import mysql, postgresql, sqlite

    dialects = {
        "sqlite": sqlite.dialect(),
        "postgresql": postgresql.dialect(),
        "mysql": mysql.dialect(),
    }
    statement = scheduling_engine._build_runtime_state_upsert(
        dialect_name,
        "redis",
        100.0,
    )

    assert expected_clause in str(statement.compile(dialect=dialects[dialect_name]))


def test_runtime_state_initialization_is_atomic(monkeypatch, tmp_path) -> None:
    database = create_engine(
        f"sqlite:///{tmp_path / 'runtime-state.db'}",
        connect_args={"timeout": 10},
    )
    SchedulingRuntimeState.__table__.create(database)
    try:
        _assert_concurrent_runtime_initialization(monkeypatch, database)
    finally:
        database.dispose()


@pytest.mark.parametrize(
    "database_url_environment",
    ["CFMS_TEST_MYSQL_URL", "CFMS_TEST_POSTGRESQL_URL"],
)
def test_runtime_state_initialization_is_atomic_on_shared_database(
    monkeypatch,
    database_url_environment,
) -> None:
    database_url = os.environ.get(database_url_environment)
    if database_url is None:
        pytest.skip(f"{database_url_environment} is required")

    database = create_engine(database_url)
    table = SchedulingRuntimeState.__table__
    table.drop(database, checkfirst=True)
    table.create(database)
    try:
        _assert_concurrent_runtime_initialization(monkeypatch, database)
    finally:
        table.drop(database)
        database.dispose()


def _schedule(factory, next_run_at=100.0):
    with factory() as session, session.begin():
        session.add(
            Schedule(
                id="schedule-1",
                task_name="test.record",
                task_contract_version=1,
                payload={"value": 7},
                trigger_type="interval",
                trigger_data={
                    "seconds": 60,
                    "start_at": "1970-01-01T00:01:40+00:00",
                },
                timezone="UTC",
                next_run_at=next_run_at,
                created_by="admin",
                updated_by="admin",
            )
        )


def _system_registry(system_schedule):
    return ScheduledTaskRegistry(
        [
            ScheduledTaskRegistration(
                name="test.system_cleanup",
                contract_version=1,
                payload_model=_EmptyPayload,
                execute=lambda _context, _payload: None,
                user_schedulable=False,
                system_schedule=system_schedule,
            )
        ]
    )


def test_due_execution_is_durable_and_completed(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy(misfire_grace_seconds=300)
    calls = []
    audits = []
    monkeypatch.setattr(
        scheduling_engine,
        "log_audit",
        lambda action, result, **values: audits.append((action, result, values)),
    )
    registry = ScheduledTaskRegistry(
        [
            ScheduledTaskRegistration(
                name="test.record",
                contract_version=1,
                payload_model=_Payload,
                execute=lambda context, payload: (
                    calls.append((context.execution_id, payload.value))
                    or ScheduledTaskResult(data={"recorded": payload.value})
                ),
                required_permission=Permissions.MANAGE_SYSTEM,
                max_attempts=1,
            )
        ]
    )

    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    assert scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0) == 1
    claim = scheduling_engine.claim_execution(generation, "worker", policy, now=100.0)
    assert claim is not None

    monkeypatch.setattr(scheduling_engine, "database_now", lambda _session: 100.0)
    scheduling_engine.run_claimed_execution(claim, generation, registry, policy)

    with factory() as session:
        execution = session.scalar(select(ScheduleExecution))
        schedule = session.get(Schedule, "schedule-1")
        assert execution.state == "succeeded"
        assert execution.created_at == 100.0
        assert execution.result == {"recorded": 7}
        assert schedule.active_execution_id is None
        assert calls == [(execution.id, 7)]
        assert audits[0][0:2] == ("scheduled_task_execute", 0)
        assert audits[0][2]["data"]["execution_id"] == execution.id


def test_execution_logs_when_lease_refresh_is_lost(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy(
        execution_lease_seconds=3,
        lease_refresh_seconds=1,
    )
    refresh_attempted = threading.Event()
    warnings = []

    def lose_lease(_execution_id, _lease_owner, _policy):
        refresh_attempted.set()
        return False

    def execute(_context, _payload):
        assert refresh_attempted.wait(3)
        return None

    registry = ScheduledTaskRegistry(
        [
            ScheduledTaskRegistration(
                name="test.record",
                contract_version=1,
                payload_model=_Payload,
                execute=execute,
                required_permission=Permissions.MANAGE_SYSTEM,
                max_attempts=1,
            )
        ]
    )
    monkeypatch.setattr(scheduling_engine, "refresh_execution_lease", lose_lease)
    monkeypatch.setattr(
        scheduling_engine,
        "logger",
        SimpleNamespace(
            warning=lambda message, *args: warnings.append((message, args)),
            exception=lambda *_args, **_kwargs: None,
        ),
    )
    monkeypatch.setattr(scheduling_engine, "log_audit", lambda *_args, **_kwargs: None)

    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    claim = scheduling_engine.claim_execution(generation, "worker", policy, now=100.0)
    assert claim is not None

    scheduling_engine.run_claimed_execution(claim, generation, registry, policy)

    assert warnings == [("Scheduled execution {} lost its lease", (claim.id,))]


@pytest.mark.parametrize("terminal_status", ["completed", "failed"])
def test_updating_terminal_schedule_reactivates_and_enqueues(
    monkeypatch, terminal_status
):
    factory = _session_factory(monkeypatch)
    registry = ScheduledTaskRegistry(
        [
            ScheduledTaskRegistration(
                name="test.record",
                contract_version=1,
                payload_model=_Payload,
                execute=lambda _context, _payload: None,
                required_permission=Permissions.MANAGE_SYSTEM,
            )
        ]
    )
    with factory() as session, session.begin():
        session.add(
            Schedule(
                id="terminal-schedule",
                task_name="test.record",
                task_contract_version=1,
                payload={"value": 7},
                trigger_type="date",
                trigger_data={"run_at": "1970-01-01T00:01:00+00:00"},
                timezone="UTC",
                status=terminal_status,
                next_run_at=None,
                created_by="admin",
                updated_by="admin",
            )
        )

    with factory() as session, session.begin():
        schedule = update_schedule(
            session,
            registry,
            "terminal-schedule",
            1,
            {
                "trigger_type": "date",
                "trigger_data": {"run_at": "1970-01-01T00:03:20+00:00"},
            },
            username="admin",
            now=100.0,
        )
        assert schedule.status == "active"
        assert schedule.next_run_at == 200.0

    policy = SchedulingPolicy()
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    assert scheduling_engine.enqueue_due_schedules(generation, policy, now=200.0) == 1
    assert (
        scheduling_engine.claim_execution(generation, "worker", policy, now=200.0)
        is not None
    )


def test_updating_terminal_date_schedule_rejects_recorded_occurrence(monkeypatch):
    factory = _session_factory(monkeypatch)
    registry = ScheduledTaskRegistry(
        [
            ScheduledTaskRegistration(
                name="test.record",
                contract_version=1,
                payload_model=_Payload,
                execute=lambda _context, _payload: None,
                required_permission=Permissions.MANAGE_SYSTEM,
            )
        ]
    )
    scheduled_for = 200.0
    with factory() as session, session.begin():
        session.add(
            Schedule(
                id="terminal-schedule",
                task_name="test.record",
                task_contract_version=1,
                payload={"value": 7},
                trigger_type="date",
                trigger_data={"run_at": "1970-01-01T00:03:20+00:00"},
                timezone="UTC",
                status="completed",
                next_run_at=None,
                created_by="admin",
                updated_by="admin",
            )
        )
        session.add(
            ScheduleExecution(
                id=scheduling_engine.execution_id("terminal-schedule", scheduled_for),
                schedule_id="terminal-schedule",
                task_name="test.record",
                task_contract_version=1,
                payload={"value": 7},
                provider_generation=1,
                scheduled_for=scheduled_for,
                state="succeeded",
                completed_at=scheduled_for,
            )
        )

    with (
        factory() as session,
        session.begin(),
        pytest.raises(
            ScheduleConflictError, match="occurrence has already been recorded"
        ),
    ):
        update_schedule(
            session,
            registry,
            "terminal-schedule",
            1,
            {"payload": {"value": 8}},
            username="admin",
            now=201.0,
        )

    with factory() as session:
        schedule = session.get(Schedule, "terminal-schedule")
        assert schedule.status == "completed"
        assert schedule.payload == {"value": 7}
        assert schedule.revision == 1


def test_system_schedule_is_created_updated_and_retired(monkeypatch):
    factory = _session_factory(monkeypatch)
    interval_seconds = 60

    def system_schedule():
        return SystemScheduleDefinition(
            id="test.system_cleanup",
            payload={},
            trigger_type="interval",
            trigger_data={"seconds": interval_seconds},
        )

    registry = _system_registry(system_schedule)

    assert scheduling_engine.synchronize_system_schedules(registry, now=100.0) == 1
    with factory() as session:
        schedule = session.get(Schedule, "test.system_cleanup")
        first_anchor = schedule.trigger_data["start_at"]
        assert schedule.system_managed is True
        assert schedule.created_by is None
        assert schedule.updated_by is None
        assert schedule.next_run_at == 100.0
        assert schedule.pending_scheduled_for == 100.0

    assert scheduling_engine.synchronize_system_schedules(registry, now=150.0) == 0
    interval_seconds = 120
    assert scheduling_engine.synchronize_system_schedules(registry, now=200.0) == 1
    with factory() as session:
        schedule = session.get(Schedule, "test.system_cleanup")
        assert schedule.trigger_data == {
            "seconds": 120,
            "start_at": first_anchor,
        }
        assert schedule.next_run_at == 220.0
        assert schedule.pending_scheduled_for == 200.0
        assert schedule.revision == 2

    assert (
        scheduling_engine.synchronize_system_schedules(
            ScheduledTaskRegistry(), now=300.0
        )
        == 1
    )
    with factory() as session:
        schedule = session.get(Schedule, "test.system_cleanup")
        assert schedule.enabled is False
        assert schedule.status == "deleted"


def test_unchanged_system_schedule_does_not_acquire_write_lock(monkeypatch):
    _session_factory(monkeypatch)

    def system_schedule():
        return SystemScheduleDefinition(
            id="test.system_cleanup",
            payload={},
            trigger_type="interval",
            trigger_data={"seconds": 60},
        )

    registry = _system_registry(system_schedule)
    scheduling_engine.synchronize_system_schedules(registry, now=100.0)
    locked_schedule_ids = []
    original_lock_schedule = scheduling_engine.lock_schedule

    def record_lock(session, schedule_id):
        locked_schedule_ids.append(schedule_id)
        return original_lock_schedule(session, schedule_id)

    monkeypatch.setattr(scheduling_engine, "lock_schedule", record_lock)

    assert scheduling_engine.synchronize_system_schedules(registry, now=101.0) == 0
    assert locked_schedule_ids == []


def test_system_schedule_immediate_reconciliation_preserves_interval_cadence(
    monkeypatch,
):
    factory = _session_factory(monkeypatch)
    interval_seconds = 60

    def system_schedule():
        return SystemScheduleDefinition(
            id="test.system_cleanup",
            payload={},
            trigger_type="interval",
            trigger_data={"seconds": interval_seconds},
        )

    registry = _system_registry(system_schedule)
    policy = SchedulingPolicy()
    scheduling_engine.synchronize_system_schedules(registry, now=100.0)
    interval_seconds = 120

    assert scheduling_engine.synchronize_system_schedules(registry, now=200.0) == 1
    generation = scheduling_engine.ensure_runtime_state("local", now=200.0)
    assert scheduling_engine.enqueue_due_schedules(generation, policy, now=200.0) == 1
    claim = scheduling_engine.claim_execution(generation, "worker", policy, now=200.0)
    assert claim is not None
    assert claim.scheduled_for == 200.0
    assert (
        scheduling_engine.complete_execution(claim, generation, {}, now=201.0) is True
    )

    with factory() as session:
        schedule = session.get(Schedule, "test.system_cleanup")
        assert schedule.trigger_data["start_at"] == "1970-01-01T00:01:40+00:00"
        assert schedule.next_run_at == 220.0


def test_system_schedule_update_preserves_queued_execution_contract(monkeypatch):
    factory = _session_factory(monkeypatch)

    def registry(contract_version, value):
        return ScheduledTaskRegistry(
            [
                ScheduledTaskRegistration(
                    name="test.system_cleanup",
                    contract_version=contract_version,
                    payload_model=_Payload,
                    execute=lambda _context, _payload: None,
                    user_schedulable=False,
                    system_schedule=lambda: SystemScheduleDefinition(
                        id="test.system_cleanup",
                        payload={"value": value},
                        trigger_type="interval",
                        trigger_data={"seconds": 60},
                    ),
                )
            ]
        )

    original_registry = registry(1, 1)
    policy = SchedulingPolicy()
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    scheduling_engine.synchronize_system_schedules(original_registry, now=100.0)
    assert scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0) == 1

    updated_registry = registry(2, 2)
    scheduling_engine.synchronize_system_schedules(updated_registry, now=101.0)
    claim = scheduling_engine.claim_execution(generation, "worker", policy, now=101.0)

    assert claim is not None
    assert claim.task_contract_version == 1
    assert claim.payload == {"value": 1}
    with factory() as session:
        schedule = session.get(Schedule, "test.system_cleanup")
        execution = session.get(ScheduleExecution, claim.id)
        assert schedule.task_contract_version == 2
        assert schedule.payload == {"value": 2}
        assert execution.task_contract_version == 1
        assert execution.payload == {"value": 1}


def test_system_schedule_reconciliation_clears_user_attribution(monkeypatch):
    factory = _session_factory(monkeypatch)

    def system_schedule():
        return SystemScheduleDefinition(
            id="test.system_cleanup",
            payload={},
            trigger_type="interval",
            trigger_data={"seconds": 60},
        )

    registry = _system_registry(system_schedule)
    scheduling_engine.synchronize_system_schedules(registry, now=100.0)
    with factory() as session, session.begin():
        schedule = session.get(Schedule, "test.system_cleanup")
        schedule.created_by = "unexpected-user"
        schedule.updated_by = "unexpected-user"

    assert scheduling_engine.synchronize_system_schedules(registry, now=101.0) == 1
    with factory() as session:
        schedule = session.get(Schedule, "test.system_cleanup")
        assert schedule.created_by is None
        assert schedule.updated_by is None


@pytest.mark.parametrize("execution_state", ["pending", "retry_wait"])
def test_retiring_system_schedule_cancels_unstarted_execution(
    monkeypatch, execution_state
):
    factory = _session_factory(monkeypatch)

    def system_schedule():
        return SystemScheduleDefinition(
            id="test.system_cleanup",
            payload={},
            trigger_type="interval",
            trigger_data={"seconds": 60},
        )

    registry = _system_registry(system_schedule)
    policy = SchedulingPolicy()
    assert scheduling_engine.synchronize_system_schedules(registry, now=100.0) == 1
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    assert scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0) == 1
    with factory() as session, session.begin():
        execution = session.scalar(select(ScheduleExecution))
        assert execution is not None
        execution_id = execution.id
        if execution_state == "retry_wait":
            execution.state = "retry_wait"
            execution.retry_at = 200.0

    assert (
        scheduling_engine.synchronize_system_schedules(
            ScheduledTaskRegistry(), now=101.0
        )
        == 1
    )
    with factory() as session:
        schedule = session.get(Schedule, "test.system_cleanup")
        execution = session.get(ScheduleExecution, execution_id)
        assert schedule.status == "deleted"
        assert schedule.active_execution_id is None
        assert execution.state == "cancelled"
        assert execution.retry_at is None
        assert execution.completed_at == 101.0
        assert execution.error == "System schedule retired before execution started"

    assert (
        scheduling_engine.claim_execution(generation, "worker", policy, now=201.0)
        is None
    )
    assert scheduling_engine.synchronize_system_schedules(registry, now=202.0) == 1
    with factory() as session:
        schedule = session.get(Schedule, "test.system_cleanup")
        execution = session.get(ScheduleExecution, execution_id)
        assert schedule.status == "active"
        assert schedule.active_execution_id is None
        assert execution.state == "cancelled"


def test_retiring_system_schedule_allows_running_execution_to_finish(monkeypatch):
    factory = _session_factory(monkeypatch)

    def system_schedule():
        return SystemScheduleDefinition(
            id="test.system_cleanup",
            payload={},
            trigger_type="interval",
            trigger_data={"seconds": 60},
        )

    registry = _system_registry(system_schedule)
    policy = SchedulingPolicy()
    scheduling_engine.synchronize_system_schedules(registry, now=100.0)
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    claim = scheduling_engine.claim_execution(generation, "worker", policy, now=100.0)
    assert claim is not None

    scheduling_engine.synchronize_system_schedules(ScheduledTaskRegistry(), now=101.0)
    with factory() as session:
        schedule = session.get(Schedule, "test.system_cleanup")
        execution = session.get(ScheduleExecution, claim.id)
        assert schedule.status == "deleted"
        assert schedule.active_execution_id == claim.id
        assert execution.state == "running"

    assert (
        scheduling_engine.fail_execution(
            claim,
            generation,
            max_attempts=3,
            initial_backoff_seconds=10,
            maximum_backoff_seconds=60,
            error="task failed",
            now=102.0,
        )
        is True
    )
    with factory() as session:
        schedule = session.get(Schedule, "test.system_cleanup")
        execution = session.get(ScheduleExecution, claim.id)
        assert schedule.active_execution_id is None
        assert execution.state == "failed"
        assert execution.retry_at is None
        assert execution.completed_at == 102.0


@pytest.mark.parametrize("execution_state", [None, "succeeded"])
def test_retiring_system_schedule_clears_stale_execution_slot(
    monkeypatch, execution_state
):
    factory = _session_factory(monkeypatch)

    def system_schedule():
        return SystemScheduleDefinition(
            id="test.system_cleanup",
            payload={},
            trigger_type="interval",
            trigger_data={"seconds": 60},
        )

    registry = _system_registry(system_schedule)
    scheduling_engine.synchronize_system_schedules(registry, now=100.0)
    with factory() as session, session.begin():
        schedule = session.get(Schedule, "test.system_cleanup")
        schedule.active_execution_id = "stale-execution"
        if execution_state is not None:
            session.add(
                ScheduleExecution(
                    id="stale-execution",
                    schedule_id=schedule.id,
                    task_name=schedule.task_name,
                    task_contract_version=schedule.task_contract_version,
                    payload=schedule.payload,
                    provider_generation=1,
                    scheduled_for=100.0,
                    state=execution_state,
                    completed_at=100.0,
                )
            )

    scheduling_engine.synchronize_system_schedules(ScheduledTaskRegistry(), now=101.0)
    with factory() as session:
        schedule = session.get(Schedule, "test.system_cleanup")
        assert schedule.active_execution_id is None


def test_due_occurrences_coalesce_while_execution_is_active(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy(misfire_grace_seconds=300)
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)

    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    scheduling_engine.enqueue_due_schedules(generation, policy, now=220.0)

    with factory() as session:
        schedule = session.get(Schedule, "schedule-1")
        executions = session.scalars(select(ScheduleExecution)).all()
        assert len(executions) == 1
        assert schedule.pending_scheduled_for == 220.0
        assert schedule.next_run_at == 280.0


@pytest.mark.parametrize("management_change", ["update", "delete"])
def test_enqueue_rejects_schedule_changed_after_candidate_read(
    monkeypatch,
    management_change,
):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy()
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    registry = ScheduledTaskRegistry(
        [
            ScheduledTaskRegistration(
                name="test.record",
                contract_version=1,
                payload_model=_Payload,
                execute=lambda _context, _payload: None,
                required_permission=Permissions.MANAGE_SYSTEM,
            )
        ]
    )
    original_advance_trigger = scheduling_engine.advance_trigger
    changed = False

    def change_schedule_before_reservation(*args):
        nonlocal changed
        advance = original_advance_trigger(*args)
        with factory() as session, session.begin():
            if management_change == "update":
                update_schedule(
                    session,
                    registry,
                    "schedule-1",
                    1,
                    {
                        "trigger_type": "date",
                        "trigger_data": {"run_at": "1970-01-01T00:08:20+00:00"},
                        "timezone": "UTC",
                    },
                    username="admin",
                    now=101.0,
                )
            else:
                delete_schedule(
                    session,
                    "schedule-1",
                    1,
                    username="admin",
                    now=101.0,
                )
        changed = True
        return advance

    monkeypatch.setattr(
        scheduling_engine, "advance_trigger", change_schedule_before_reservation
    )

    assert scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0) == 0
    assert changed is True
    with factory() as session:
        schedule = session.get(Schedule, "schedule-1")
        assert session.scalar(select(ScheduleExecution.id)) is None
        assert schedule.active_execution_id is None
        assert schedule.revision == 2
        if management_change == "update":
            assert schedule.status == "active"
            assert schedule.trigger_type == "date"
            assert schedule.next_run_at == 500.0
        else:
            assert schedule.status == "deleted"
            assert schedule.enabled is False
            assert schedule.next_run_at is None


def test_provider_switch_requeues_unfinished_execution(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy()
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)

    new_generation = scheduling_engine.ensure_runtime_state(
        "redis", "test-cluster", now=101.0
    )

    with factory() as session:
        execution = session.scalar(select(ScheduleExecution))
        assert new_generation == 2
        assert execution.provider_generation == 2
        assert execution.state == "pending"
        assert execution.dispatch_state == "pending"


def test_redis_namespace_switch_requeues_sent_execution(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy()
    generation = scheduling_engine.ensure_runtime_state(
        "redis", "first-cluster", now=100.0
    )
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    with factory() as session:
        execution_id = session.scalar(select(ScheduleExecution.id))
    assert execution_id is not None
    assert scheduling_engine.mark_dispatched(execution_id, generation, 0) is True
    assert (
        scheduling_engine.ensure_runtime_state("redis", "first-cluster", now=101.0)
        == generation
    )

    new_generation = scheduling_engine.ensure_runtime_state(
        "redis", "second-cluster", now=102.0
    )

    with factory() as session:
        state = session.get(SchedulingRuntimeState, 1)
        execution = session.get(ScheduleExecution, execution_id)
        assert new_generation == generation + 1
        assert state.redis_namespace == "second-cluster"
        assert execution.provider_generation == new_generation
        assert execution.state == "pending"
        assert execution.dispatch_state == "pending"


def test_redis_namespace_switch_rejects_live_execution_lease(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy()
    generation = scheduling_engine.ensure_runtime_state(
        "redis", "first-cluster", now=100.0
    )
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    claim = scheduling_engine.claim_execution(generation, "worker", policy, now=100.0)
    assert claim is not None

    with pytest.raises(RuntimeError, match="execution lease is active"):
        scheduling_engine.ensure_runtime_state("redis", "second-cluster", now=101.0)


def test_cluster_dispatch_claims_the_requested_execution(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy()
    generation = scheduling_engine.ensure_runtime_state(
        "redis", "test-cluster", now=100.0
    )
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    pending = scheduling_engine.pending_dispatches(generation, 10, 60, now=100.0)

    assert len(pending) == 1
    dispatch = pending[0]
    assert (
        scheduling_engine.mark_dispatched(dispatch.id, generation, dispatch.attempt)
        is True
    )
    claim = scheduling_engine.claim_execution_by_id(
        dispatch.id, generation, "cluster-worker", policy, now=100.0
    )

    assert claim is not None
    assert claim.id == dispatch.id
    assert (
        scheduling_engine.execution_delivery_state(dispatch.id, generation, now=100.0)
        == "busy"
    )


def test_cluster_dispatch_recovers_sent_execution_that_was_never_claimed(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy(
        execution_lease_seconds=60,
        lease_refresh_seconds=20,
    )
    generation = scheduling_engine.ensure_runtime_state(
        "redis", "test-cluster", now=100.0
    )
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    (dispatch,) = scheduling_engine.pending_dispatches(
        generation, 10, policy.execution_lease_seconds, now=100.0
    )
    execution_id = dispatch.id
    assert scheduling_engine.mark_dispatched(
        execution_id, generation, dispatch.attempt, now=100.0
    )

    assert (
        scheduling_engine.pending_dispatches(
            generation, 10, policy.execution_lease_seconds, now=159.0
        )
        == ()
    )
    assert scheduling_engine.pending_dispatches(
        generation, 10, policy.execution_lease_seconds, now=160.0
    ) == (scheduling_engine.PendingDispatch(id=execution_id, attempt=0),)

    with factory() as session:
        execution = session.get(ScheduleExecution, execution_id)
        assert execution.state == "pending"
        assert execution.dispatch_state == "pending"
        assert execution.dispatched_at is None


def test_late_dispatch_acknowledgement_does_not_hide_a_new_retry(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy(
        execution_lease_seconds=60,
        lease_refresh_seconds=20,
    )
    generation = scheduling_engine.ensure_runtime_state(
        "redis", "test-cluster", now=100.0
    )
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    (dispatch,) = scheduling_engine.pending_dispatches(
        generation, 10, policy.execution_lease_seconds, now=100.0
    )
    claim = scheduling_engine.claim_execution_by_id(
        dispatch.id,
        generation,
        "cluster-worker",
        policy,
        now=100.0,
    )
    assert claim is not None
    assert scheduling_engine.fail_execution(
        claim,
        generation,
        max_attempts=3,
        initial_backoff_seconds=5,
        maximum_backoff_seconds=30,
        error="task failed",
        now=101.0,
    )

    assert (
        scheduling_engine.mark_dispatched(
            dispatch.id,
            generation,
            dispatch.attempt,
            now=101.0,
        )
        is False
    )
    assert scheduling_engine.pending_dispatches(
        generation,
        10,
        policy.execution_lease_seconds,
        now=106.0,
    ) == (scheduling_engine.PendingDispatch(id=dispatch.id, attempt=1),)


def test_dense_misfire_does_not_block_other_due_schedules(monkeypatch):
    factory = _session_factory(monkeypatch)
    with factory() as session, session.begin():
        session.add_all(
            [
                Schedule(
                    id="dense-interval",
                    task_name="test.record",
                    task_contract_version=1,
                    payload={"value": 1},
                    trigger_type="interval",
                    trigger_data={
                        "seconds": 1,
                        "start_at": "1970-01-01T00:00:00+00:00",
                    },
                    timezone="UTC",
                    next_run_at=0.0,
                    created_by="admin",
                    updated_by="admin",
                ),
                Schedule(
                    id="ordinary-date",
                    task_name="test.record",
                    task_contract_version=1,
                    payload={"value": 2},
                    trigger_type="date",
                    trigger_data={"run_at": "1970-01-02T03:46:41+00:00"},
                    timezone="UTC",
                    next_run_at=100_001.0,
                    created_by="admin",
                    updated_by="admin",
                ),
            ]
        )
    policy = SchedulingPolicy(
        misfire_grace_seconds=100_002,
        claim_batch_size=10,
    )
    generation = scheduling_engine.ensure_runtime_state("local", now=100_001.0)

    assert (
        scheduling_engine.enqueue_due_schedules(
            generation,
            policy,
            now=100_001.0,
        )
        == 2
    )
    with factory() as session:
        assert set(session.scalars(select(ScheduleExecution.schedule_id))) == {
            "dense-interval",
            "ordinary-date",
        }


def test_cluster_dispatch_recovers_execution_after_long_lease_expires(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy(
        poll_interval_seconds=1.0,
        execution_lease_seconds=300,
        lease_refresh_seconds=100,
    )
    generation = scheduling_engine.ensure_runtime_state(
        "redis", "test-cluster", now=100.0
    )
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    (dispatch,) = scheduling_engine.pending_dispatches(
        generation, 10, policy.execution_lease_seconds, now=100.0
    )
    execution_id = dispatch.id
    assert (
        scheduling_engine.mark_dispatched(execution_id, generation, dispatch.attempt)
        is True
    )
    first_claim = scheduling_engine.claim_execution_by_id(
        execution_id, generation, "failed-worker", policy, now=100.0
    )
    assert first_claim is not None

    # A 100-retry delivery budget at the one-second poll interval is exhausted
    # well before this lease, so recovery must not depend on that delivery surviving.
    assert (
        scheduling_engine.pending_dispatches(
            generation, 10, policy.execution_lease_seconds, now=201.0
        )
        == ()
    )
    assert scheduling_engine.pending_dispatches(
        generation, 10, policy.execution_lease_seconds, now=401.0
    ) == (scheduling_engine.PendingDispatch(id=execution_id, attempt=1),)

    with factory() as session:
        execution = session.get(ScheduleExecution, execution_id)
        assert execution.state == "pending"
        assert execution.dispatch_state == "pending"
        assert execution.attempt == 1
        assert execution.lease_owner is None
        assert execution.lease_expires_at is None

    assert scheduling_engine.mark_dispatched(execution_id, generation, 1) is True
    second_claim = scheduling_engine.claim_execution_by_id(
        execution_id, generation, "replacement-worker", policy, now=401.0
    )
    assert second_claim is not None
    assert second_claim.attempt == 2


def test_cluster_lease_uses_database_clock_when_node_clocks_disagree(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy(
        execution_lease_seconds=60,
        lease_refresh_seconds=20,
    )
    generation = scheduling_engine.ensure_runtime_state(
        "redis", "test-cluster", now=100.0
    )
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    (dispatch,) = scheduling_engine.pending_dispatches(
        generation, 10, policy.execution_lease_seconds, now=100.0
    )
    execution_id = dispatch.id
    assert (
        scheduling_engine.mark_dispatched(execution_id, generation, dispatch.attempt)
        is True
    )

    database_time = [100.0]
    monkeypatch.setattr(
        scheduling_engine,
        "database_now",
        lambda _session: database_time[0],
    )
    with monkeypatch.context() as slow_node:
        slow_node.setattr(time, "time", lambda: -3_600.0)
        first_claim = scheduling_engine.claim_execution_by_id(
            execution_id,
            generation,
            "slow-node",
            policy,
        )
    assert first_claim is not None

    database_time[0] = 120.0
    with monkeypatch.context() as fast_node:
        fast_node.setattr(time, "time", lambda: 3_600.0)
        assert (
            scheduling_engine.claim_execution_by_id(
                execution_id,
                generation,
                "fast-node",
                policy,
            )
            is None
        )
    assert scheduling_engine.refresh_execution_lease(
        execution_id,
        first_claim.lease_owner,
        policy,
    )

    database_time[0] = 161.0
    with monkeypatch.context() as fast_node:
        fast_node.setattr(time, "time", lambda: 3_600.0)
        assert (
            scheduling_engine.claim_execution_by_id(
                execution_id,
                generation,
                "fast-node",
                policy,
            )
            is None
        )

    database_time[0] = 181.0
    replacement = scheduling_engine.claim_execution_by_id(
        execution_id,
        generation,
        "replacement-node",
        policy,
    )
    assert replacement is not None
    assert replacement.attempt == 2

    database_time[0] = 182.0
    with monkeypatch.context() as fast_node:
        fast_node.setattr(time, "time", lambda: 3_600.0)
        assert scheduling_engine.fail_execution(
            replacement,
            generation,
            max_attempts=3,
            initial_backoff_seconds=5,
            maximum_backoff_seconds=30,
            error="task failed",
        )
    with factory() as session:
        execution = session.get(ScheduleExecution, execution_id)
        assert execution.state == "retry_wait"
        assert execution.retry_at == 192.0
        assert execution.lease_owner is None
        assert execution.lease_expires_at is None


@pytest.mark.parametrize("claim_by_id", [False, True])
def test_execution_lease_starts_after_schedule_lock_is_acquired(
    monkeypatch, claim_by_id
):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy(
        execution_lease_seconds=60,
        lease_refresh_seconds=20,
    )
    generation = scheduling_engine.ensure_runtime_state(
        "redis" if claim_by_id else "local",
        "test-cluster" if claim_by_id else None,
        now=100.0,
    )
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    with factory() as session:
        execution_id = session.scalar(select(ScheduleExecution.id))
    assert execution_id is not None
    if claim_by_id:
        assert scheduling_engine.mark_dispatched(execution_id, generation, 0) is True

    database_time = [100.0]
    original_lock_schedule = scheduling_engine.lock_schedule

    def lock_after_time_advances(session, schedule_id):
        schedule = original_lock_schedule(session, schedule_id)
        database_time[0] = 150.0
        return schedule

    monkeypatch.setattr(scheduling_engine, "lock_schedule", lock_after_time_advances)
    monkeypatch.setattr(
        scheduling_engine,
        "database_now",
        lambda _session: database_time[0],
    )

    if claim_by_id:
        claim = scheduling_engine.claim_execution_by_id(
            execution_id,
            generation,
            "worker",
            policy,
        )
    else:
        claim = scheduling_engine.claim_execution(
            generation,
            "worker",
            policy,
        )

    assert claim is not None
    with factory() as session:
        execution = session.get(ScheduleExecution, execution_id)
        assert execution.started_at == 150.0
        assert execution.lease_expires_at == 210.0


def test_execution_lease_refresh_uses_time_after_execution_lock(monkeypatch, tmp_path):
    database, factory = _file_session_factory(monkeypatch, tmp_path)
    _schedule(factory)
    policy = SchedulingPolicy(
        execution_lease_seconds=60,
        lease_refresh_seconds=20,
    )
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    claim = scheduling_engine.claim_execution(
        generation, "original-worker", policy, now=100.0
    )
    assert claim is not None

    database_time = [100.0]
    refresh_update_started = threading.Event()
    monkeypatch.setattr(
        scheduling_engine,
        "database_now",
        lambda _session: database_time[0],
    )
    blocker = factory()
    blocker.begin()
    blocker.execute(
        update(ScheduleExecution)
        .where(ScheduleExecution.id == claim.id)
        .values(error="blocking refresh")
    )

    @event.listens_for(database, "before_cursor_execute")
    def observe_refresh_update(
        _connection,
        _cursor,
        statement,
        _parameters,
        _context,
        _executemany,
    ) -> None:
        if (
            threading.current_thread() is not threading.main_thread()
            and statement.lstrip().upper().startswith("UPDATE SCHEDULE_EXECUTIONS")
        ):
            refresh_update_started.set()

    try:
        with ThreadPoolExecutor(max_workers=1) as executor:
            refreshed = executor.submit(
                scheduling_engine.refresh_execution_lease,
                claim.id,
                claim.lease_owner,
                policy,
            )
            assert refresh_update_started.wait(5)
            database_time[0] = 150.0
            blocker.commit()
            assert refreshed.result(timeout=5) is True
        with factory() as session:
            execution = session.get(ScheduleExecution, claim.id)
            assert execution.lease_expires_at == 210.0
    finally:
        event.remove(database, "before_cursor_execute", observe_refresh_update)
        blocker.close()
        database.dispose()


@pytest.mark.parametrize("provider", ["local", "redis"])
def test_consecutive_lease_recovery_cannot_execute_past_max_attempts(
    monkeypatch, provider
):
    factory = _session_factory(monkeypatch)
    with factory() as session, session.begin():
        session.add(
            Schedule(
                id="schedule-1",
                task_name="test.record",
                task_contract_version=1,
                payload={"value": 7},
                trigger_type="date",
                trigger_data={"run_at": "1970-01-01T00:01:40+00:00"},
                timezone="UTC",
                next_run_at=100.0,
                created_by="admin",
                updated_by="admin",
            )
        )
    policy = SchedulingPolicy(
        execution_lease_seconds=60,
        lease_refresh_seconds=20,
    )
    generation = scheduling_engine.ensure_runtime_state(
        provider,
        "test-cluster" if provider == "redis" else None,
        now=100.0,
    )
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    with factory() as session:
        execution_id = session.scalar(select(ScheduleExecution.id))
    assert execution_id is not None

    claims = []
    for attempt, current_time in enumerate((100.0, 160.0, 220.0), start=1):
        if provider == "redis":
            (dispatch,) = scheduling_engine.pending_dispatches(
                generation,
                10,
                policy.execution_lease_seconds,
                now=current_time,
            )
            assert dispatch == scheduling_engine.PendingDispatch(
                id=execution_id, attempt=attempt - 1
            )
            assert (
                scheduling_engine.mark_dispatched(
                    execution_id, generation, dispatch.attempt
                )
                is True
            )
            claim = scheduling_engine.claim_execution_by_id(
                execution_id,
                generation,
                f"worker-{attempt}",
                policy,
                now=current_time,
            )
        else:
            claim = scheduling_engine.claim_execution(
                generation,
                f"worker-{attempt}",
                policy,
                now=current_time,
            )
        assert claim is not None
        assert claim.attempt == attempt
        claims.append(claim)

    calls = []
    registry = ScheduledTaskRegistry(
        [
            ScheduledTaskRegistration(
                name="test.record",
                contract_version=1,
                payload_model=_Payload,
                execute=lambda context, payload: calls.append((context, payload)),
                required_permission=Permissions.MANAGE_SYSTEM,
                max_attempts=1,
            )
        ]
    )

    scheduling_engine.run_claimed_execution(claims[-1], generation, registry, policy)

    assert calls == []
    with factory() as session:
        schedule = session.get(Schedule, "schedule-1")
        execution = session.get(ScheduleExecution, execution_id)
        assert schedule.active_execution_id is None
        assert schedule.status == "failed"
        assert execution.state == "failed"
        assert execution.attempt == 3
        assert execution.retry_at is None
        assert execution.lease_owner is None
        assert execution.lease_expires_at is None
        assert execution.completed_at is not None
        assert execution.error == "Scheduled task maximum attempts exceeded"

    if provider == "redis":
        assert (
            scheduling_engine.claim_execution_by_id(
                execution_id,
                generation,
                "worker-4",
                policy,
                now=280.0,
            )
            is None
        )
    else:
        assert (
            scheduling_engine.claim_execution(
                generation,
                "worker-4",
                policy,
                now=280.0,
            )
            is None
        )


@pytest.mark.parametrize(
    ("new_state", "retry_at"),
    (("succeeded", None), ("retry_wait", 200.0)),
)
@pytest.mark.parametrize("claim_by_id", [False, True])
def test_claim_rechecks_candidate_state_at_atomic_update(
    monkeypatch, new_state, retry_at, claim_by_id
):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy()
    generation = scheduling_engine.ensure_runtime_state(
        "redis" if claim_by_id else "local",
        "test-cluster" if claim_by_id else None,
        now=100.0,
    )
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    with factory() as session:
        execution_id = session.scalar(select(ScheduleExecution.id))
    assert execution_id is not None
    if claim_by_id:
        assert scheduling_engine.mark_dispatched(execution_id, generation, 0) is True

    transitioned = False

    def transition_candidate(orm_execute_state):
        nonlocal transitioned
        if transitioned or not orm_execute_state.is_update:
            return
        values = {"state": new_state, "retry_at": retry_at}
        if new_state == "succeeded":
            values["completed_at"] = 100.5
        orm_execute_state.session.connection().execute(
            update(ScheduleExecution)
            .where(ScheduleExecution.id == execution_id)
            .values(**values)
        )
        transitioned = True

    event.listen(factory.class_, "do_orm_execute", transition_candidate)
    try:
        if claim_by_id:
            claim = scheduling_engine.claim_execution_by_id(
                execution_id, generation, "worker", policy, now=101.0
            )
        else:
            claim = scheduling_engine.claim_execution(
                generation, "worker", policy, now=101.0
            )
    finally:
        event.remove(factory.class_, "do_orm_execute", transition_candidate)

    assert transitioned is True
    assert claim is None
    with factory() as session:
        execution = session.get(ScheduleExecution, execution_id)
        assert execution.state == new_state
        assert execution.retry_at == retry_at
        assert execution.attempt == 0


def test_deleting_schedule_cancels_unclaimed_execution(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy()
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)

    with factory() as session, session.begin():
        execution_id = session.scalar(select(ScheduleExecution.id))
        delete_schedule(session, "schedule-1", 1, username="admin", now=101.0)

    assert execution_id is not None
    assert (
        scheduling_engine.claim_execution(generation, "worker", policy, now=102.0)
        is None
    )
    assert (
        scheduling_engine.execution_delivery_state(execution_id, generation, now=102.0)
        == "terminal"
    )
    with factory() as session:
        schedule = session.get(Schedule, "schedule-1")
        execution = session.get(ScheduleExecution, execution_id)
        assert schedule.status == "deleted"
        assert schedule.active_execution_id is None
        assert execution.state == "cancelled"
        assert execution.completed_at == 101.0


def test_claim_rejects_execution_if_schedule_was_deleted_concurrently(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy()
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)

    with factory() as session, session.begin():
        session.execute(
            update(Schedule)
            .where(Schedule.id == "schedule-1")
            .values(status="deleted", enabled=False, next_run_at=None)
        )

    assert (
        scheduling_engine.claim_execution(generation, "worker", policy, now=101.0)
        is None
    )


def test_deleting_schedule_allows_running_execution_to_finish_without_retry(
    monkeypatch,
):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy()
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    claim = scheduling_engine.claim_execution(generation, "worker", policy, now=100.0)
    assert claim is not None

    with factory() as session, session.begin():
        delete_schedule(session, "schedule-1", 1, username="admin", now=101.0)
        assert session.get(ScheduleExecution, claim.id).state == "running"

    assert (
        scheduling_engine.fail_execution(
            claim,
            generation,
            max_attempts=3,
            initial_backoff_seconds=10,
            maximum_backoff_seconds=60,
            error="task failed",
            now=102.0,
        )
        is True
    )
    with factory() as session:
        schedule = session.get(Schedule, "schedule-1")
        execution = session.get(ScheduleExecution, claim.id)
        assert schedule.status == "deleted"
        assert schedule.active_execution_id is None
        assert execution.state == "failed"
        assert execution.retry_at is None
        assert execution.completed_at == 102.0


def test_expired_deleted_execution_is_cancelled_and_releases_schedule(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy(execution_lease_seconds=60, lease_refresh_seconds=20)
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    claim = scheduling_engine.claim_execution(generation, "worker", policy, now=100.0)
    assert claim is not None

    with factory() as session, session.begin():
        delete_schedule(session, "schedule-1", 1, username="admin", now=101.0)

    assert (
        scheduling_engine.cancel_expired_deleted_executions(
            policy.claim_batch_size, now=159.0
        )
        == 0
    )
    assert (
        scheduling_engine.cancel_expired_deleted_executions(
            policy.claim_batch_size, now=160.0
        )
        == 1
    )
    with factory() as session:
        schedule = session.get(Schedule, "schedule-1")
        execution = session.get(ScheduleExecution, claim.id)
        assert schedule.status == "deleted"
        assert schedule.revision == 2
        assert schedule.active_execution_id is None
        assert execution.state == "cancelled"
        assert execution.completed_at == 160.0
        assert execution.error == "Execution lease expired after schedule deletion"
        assert execution.attempt == 1
        assert execution.started_at == 100.0
        assert execution.dispatch_state == "sent"
        assert execution.retry_at is None
        assert execution.lease_owner is None
        assert execution.lease_expires_at is None

    retention_policy = SchedulingPolicy(history_retention_days=1)
    assert (
        scheduling_engine.purge_execution_history(retention_policy, now=160.0 + 86_401)
        == 1
    )
    with factory() as session:
        assert session.get(ScheduleExecution, claim.id) is None


def test_pending_dispatches_cancels_expired_deleted_execution_across_generations(
    monkeypatch,
):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy(execution_lease_seconds=60, lease_refresh_seconds=20)
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    claim = scheduling_engine.claim_execution(generation, "worker", policy, now=100.0)
    assert claim is not None

    with factory() as session, session.begin():
        delete_schedule(session, "schedule-1", 1, username="admin", now=101.0)

    redis_generation = scheduling_engine.ensure_runtime_state(
        "redis", "test-cluster", now=160.0
    )
    with factory() as session:
        execution = session.get(ScheduleExecution, claim.id)
        assert execution.provider_generation == generation
        assert execution.state == "running"

    assert (
        scheduling_engine.pending_dispatches(
            redis_generation, 10, policy.execution_lease_seconds, now=160.0
        )
        == ()
    )
    with factory() as session:
        schedule = session.get(Schedule, "schedule-1")
        execution = session.get(ScheduleExecution, claim.id)
        assert schedule.active_execution_id is None
        assert execution.state == "cancelled"
        assert execution.completed_at == 160.0


def test_expired_deleted_execution_cancellation_is_bounded(monkeypatch):
    factory = _session_factory(monkeypatch)
    with factory() as session, session.begin():
        for index in range(2):
            schedule_id = f"deleted-{index}"
            execution_id = f"execution-{index}"
            session.add(
                Schedule(
                    id=schedule_id,
                    task_name="test.record",
                    task_contract_version=1,
                    payload={"value": index},
                    trigger_type="date",
                    trigger_data={"run_at": "1970-01-01T00:00:01+00:00"},
                    timezone="UTC",
                    enabled=False,
                    status="deleted",
                    active_execution_id=execution_id,
                    created_at=1.0,
                    updated_at=1.0,
                    deleted_at=1.0,
                )
            )
            session.add(
                ScheduleExecution(
                    id=execution_id,
                    schedule_id=schedule_id,
                    task_name="test.record",
                    task_contract_version=1,
                    payload={"value": index},
                    provider_generation=1,
                    scheduled_for=1.0,
                    state="running",
                    dispatch_state="sent",
                    attempt=1,
                    lease_owner="worker",
                    lease_expires_at=2.0,
                    started_at=1.0,
                    created_at=1.0,
                )
            )

    assert scheduling_engine.cancel_expired_deleted_executions(1, now=3.0) == 1
    with factory() as session:
        states = tuple(
            session.scalars(
                select(ScheduleExecution.state).order_by(ScheduleExecution.id)
            )
        )
        assert states == ("cancelled", "running")
    assert scheduling_engine.cancel_expired_deleted_executions(1, now=3.0) == 1


def test_completion_after_schedule_deletion_preserves_deleted_status(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy()
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    claim = scheduling_engine.claim_execution(generation, "worker", policy, now=100.0)
    assert claim is not None

    with factory() as session, session.begin():
        delete_schedule(session, "schedule-1", 1, username="admin", now=101.0)

    assert scheduling_engine.complete_execution(
        claim, generation, {"completed": True}, now=102.0
    )
    with factory() as session:
        schedule = session.get(Schedule, "schedule-1")
        execution = session.get(ScheduleExecution, claim.id)
        assert schedule.status == "deleted"
        assert schedule.active_execution_id is None
        assert execution.state == "succeeded"
        assert execution.result == {"completed": True}


def test_concurrent_completion_and_deletion_serialize_without_deadlock(
    monkeypatch,
    tmp_path,
):
    database, factory = _file_session_factory(monkeypatch, tmp_path)
    try:
        _schedule(factory)
        policy = SchedulingPolicy()
        generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
        scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
        claim = scheduling_engine.claim_execution(
            generation, "worker", policy, now=100.0
        )
        assert claim is not None
        barrier = threading.Barrier(2)

        def complete():
            barrier.wait(timeout=10)
            return scheduling_engine.complete_execution(
                claim, generation, {"completed": True}, now=102.0
            )

        def delete():
            barrier.wait(timeout=10)
            with factory() as session, session.begin():
                delete_schedule(
                    session,
                    "schedule-1",
                    1,
                    username="admin",
                    now=101.0,
                )

        with ThreadPoolExecutor(max_workers=2) as executor:
            completed = executor.submit(complete)
            deleted = executor.submit(delete)
            assert completed.result(timeout=15) is True
            assert deleted.result(timeout=15) is None

        with factory() as session:
            schedule = session.get(Schedule, "schedule-1")
            execution = session.get(ScheduleExecution, claim.id)
            assert schedule.status == "deleted"
            assert schedule.active_execution_id is None
            assert execution.state == "succeeded"
    finally:
        database.dispose()


def test_concurrent_claim_and_deletion_have_one_complete_outcome(
    monkeypatch,
    tmp_path,
):
    database, factory = _file_session_factory(monkeypatch, tmp_path)
    try:
        _schedule(factory)
        policy = SchedulingPolicy()
        generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
        scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
        with factory() as session:
            execution_id = session.scalar(select(ScheduleExecution.id))
        assert execution_id is not None
        barrier = threading.Barrier(2)

        def claim():
            barrier.wait(timeout=10)
            return scheduling_engine.claim_execution(
                generation, "worker", policy, now=101.0
            )

        def delete():
            barrier.wait(timeout=10)
            with factory() as session, session.begin():
                delete_schedule(
                    session,
                    "schedule-1",
                    1,
                    username="admin",
                    now=101.0,
                )

        with ThreadPoolExecutor(max_workers=2) as executor:
            claimed = executor.submit(claim)
            deleted = executor.submit(delete)
            claim_result = claimed.result(timeout=15)
            assert deleted.result(timeout=15) is None

        with factory() as session:
            schedule = session.get(Schedule, "schedule-1")
            execution = session.get(ScheduleExecution, execution_id)
            assert schedule.status == "deleted"
            if claim_result is None:
                assert schedule.active_execution_id is None
                assert execution.state == "cancelled"
            else:
                assert schedule.active_execution_id == execution_id
                assert execution.state == "running"
                assert execution.lease_owner == "worker"
    finally:
        database.dispose()


@pytest.mark.parametrize("lost_condition", ["owner", "generation"])
def test_terminal_transition_rejects_lost_execution_lease(
    monkeypatch,
    lost_condition,
):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy()
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    claim = scheduling_engine.claim_execution(
        generation, "original-worker", policy, now=100.0
    )
    assert claim is not None

    if lost_condition == "owner":
        replacement = scheduling_engine.claim_execution(
            generation,
            "replacement-worker",
            policy,
            now=100.0 + policy.execution_lease_seconds,
        )
        assert replacement is not None
        rejected_generation = generation
    else:
        rejected_generation = generation + 1

    assert (
        scheduling_engine.complete_execution(
            claim,
            rejected_generation,
            {"stale": True},
            now=200.0,
        )
        is False
    )
    assert (
        scheduling_engine.fail_execution(
            claim,
            rejected_generation,
            max_attempts=1,
            initial_backoff_seconds=1,
            maximum_backoff_seconds=1,
            error="stale failure",
            now=200.0,
        )
        is False
    )
    with factory() as session:
        schedule = session.get(Schedule, "schedule-1")
        execution = session.get(ScheduleExecution, claim.id)
        assert schedule.active_execution_id == claim.id
        assert execution.state == "running"
        assert execution.result is None
        assert execution.error is None
        assert execution.lease_owner == (
            "replacement-worker" if lost_condition == "owner" else "original-worker"
        )


def test_completed_execution_history_is_purged_in_bounded_batches(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    with factory() as session, session.begin():
        session.add_all(
            [
                ScheduleExecution(
                    id="old-succeeded",
                    schedule_id="schedule-1",
                    task_name="test.record",
                    task_contract_version=1,
                    payload={"value": 7},
                    provider_generation=1,
                    scheduled_for=1.0,
                    state="succeeded",
                    completed_at=10.0,
                ),
                ScheduleExecution(
                    id="recent-failed",
                    schedule_id="schedule-1",
                    task_name="test.record",
                    task_contract_version=1,
                    payload={"value": 7},
                    provider_generation=1,
                    scheduled_for=2.0,
                    state="failed",
                    completed_at=190.0,
                ),
                ScheduleExecution(
                    id="old-pending",
                    schedule_id="schedule-1",
                    task_name="test.record",
                    task_contract_version=1,
                    payload={"value": 7},
                    provider_generation=1,
                    scheduled_for=3.0,
                    state="pending",
                    completed_at=None,
                ),
            ]
        )

    policy = SchedulingPolicy(history_retention_days=1, claim_batch_size=1)
    deleted = scheduling_engine.purge_execution_history(
        policy,
        now=86_400 + 100.0,
    )

    assert deleted == 1
    with factory() as session:
        assert session.get(ScheduleExecution, "old-succeeded") is None
        assert session.get(ScheduleExecution, "recent-failed") is not None
        assert session.get(ScheduleExecution, "old-pending") is not None
