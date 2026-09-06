import os
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

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
from include.scheduling.commands import delete_schedule, update_schedule


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


def _assert_concurrent_runtime_initialization(monkeypatch, database) -> None:
    factory = sessionmaker(bind=database)
    monkeypatch.setattr(scheduling_engine, "Session", factory)
    insert_barrier = Barrier(2)

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
                    100.0,
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
            )
        ]
    )

    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    assert scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0) == 1
    claim = scheduling_engine.claim_execution(generation, "worker", policy, now=100.0)
    assert claim is not None

    monkeypatch.setattr(scheduling_engine.time, "time", lambda: 100.0)
    scheduling_engine.run_claimed_execution(claim, generation, registry, policy)

    with factory() as session:
        execution = session.scalar(select(ScheduleExecution))
        schedule = session.get(Schedule, "schedule-1")
        assert execution.state == "succeeded"
        assert execution.result == {"recorded": 7}
        assert schedule.active_execution_id is None
        assert calls == [(execution.id, 7)]
        assert audits[0][0:2] == ("scheduled_task_execute", 0)
        assert audits[0][2]["data"]["execution_id"] == execution.id


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

    new_generation = scheduling_engine.ensure_runtime_state("redis", now=101.0)

    with factory() as session:
        execution = session.scalar(select(ScheduleExecution))
        assert new_generation == 2
        assert execution.provider_generation == 2
        assert execution.state == "pending"
        assert execution.dispatch_state == "pending"


def test_cluster_dispatch_claims_the_requested_execution(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy()
    generation = scheduling_engine.ensure_runtime_state("redis", now=100.0)
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    pending = scheduling_engine.pending_dispatches(generation, 10, now=100.0)

    assert len(pending) == 1
    assert scheduling_engine.mark_dispatched(pending[0], generation) is True
    claim = scheduling_engine.claim_execution_by_id(
        pending[0], generation, "cluster-worker", policy, now=100.0
    )

    assert claim is not None
    assert claim.id == pending[0]
    assert (
        scheduling_engine.execution_delivery_state(pending[0], generation, now=100.0)
        == "busy"
    )


def test_cluster_dispatch_recovers_execution_after_long_lease_expires(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy(
        poll_interval_seconds=1.0,
        execution_lease_seconds=300,
        lease_refresh_seconds=100,
    )
    generation = scheduling_engine.ensure_runtime_state("redis", now=100.0)
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    (execution_id,) = scheduling_engine.pending_dispatches(generation, 10, now=100.0)
    assert scheduling_engine.mark_dispatched(execution_id, generation) is True
    first_claim = scheduling_engine.claim_execution_by_id(
        execution_id, generation, "failed-worker", policy, now=100.0
    )
    assert first_claim is not None

    # A 100-retry delivery budget at the one-second poll interval is exhausted
    # well before this lease, so recovery must not depend on that delivery surviving.
    assert scheduling_engine.pending_dispatches(generation, 10, now=201.0) == ()
    assert scheduling_engine.pending_dispatches(generation, 10, now=401.0) == (
        execution_id,
    )

    with factory() as session:
        execution = session.get(ScheduleExecution, execution_id)
        assert execution.state == "pending"
        assert execution.dispatch_state == "pending"
        assert execution.attempt == 1
        assert execution.lease_owner is None
        assert execution.lease_expires_at is None

    assert scheduling_engine.mark_dispatched(execution_id, generation) is True
    second_claim = scheduling_engine.claim_execution_by_id(
        execution_id, generation, "replacement-worker", policy, now=401.0
    )
    assert second_claim is not None
    assert second_claim.attempt == 2


@pytest.mark.parametrize(
    ("new_state", "retry_at"),
    (("succeeded", None), ("retry_wait", 200.0)),
)
def test_local_claim_rechecks_candidate_state_at_atomic_update(
    monkeypatch,
    new_state,
    retry_at,
):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    policy = SchedulingPolicy()
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    with factory() as session:
        execution_id = session.scalar(select(ScheduleExecution.id))
    assert execution_id is not None

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


def test_completed_execution_history_is_purged_in_bounded_batches(monkeypatch):
    factory = _session_factory(monkeypatch)
    _schedule(factory)
    with factory() as session, session.begin():
        session.add_all(
            [
                ScheduleExecution(
                    id="old-succeeded",
                    schedule_id="schedule-1",
                    provider_generation=1,
                    scheduled_for=1.0,
                    state="succeeded",
                    completed_at=10.0,
                ),
                ScheduleExecution(
                    id="recent-failed",
                    schedule_id="schedule-1",
                    provider_generation=1,
                    scheduled_for=2.0,
                    state="failed",
                    completed_at=190.0,
                ),
                ScheduleExecution(
                    id="old-pending",
                    schedule_id="schedule-1",
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
