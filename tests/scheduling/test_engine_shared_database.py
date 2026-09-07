import os
import threading
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

import pytest
from sqlalchemy import Column, MetaData, Table, create_engine, delete
from sqlalchemy.orm import sessionmaker

import include.database.models  # noqa: F401
from include.config.validation import SchedulingPolicy
from include.database.models.identity import User
from include.database.models.scheduling import (
    Schedule,
    ScheduleExecution,
    SchedulingRuntimeState,
)
from include.scheduling import commands as scheduling_commands
from include.scheduling import engine as scheduling_engine
from include.scheduling.commands import delete_schedule

_DATABASE_URL_ENVIRONMENTS = (
    "CFMS_TEST_MYSQL_URL",
    "CFMS_TEST_POSTGRESQL_URL",
)


@pytest.fixture(scope="module", params=_DATABASE_URL_ENVIRONMENTS)
def shared_database(request):
    environment_name = request.param
    database_url = os.environ.get(environment_name)
    if database_url is None:
        pytest.skip(f"{environment_name} is required")

    database = create_engine(database_url, pool_pre_ping=True)
    support_metadata = MetaData()
    users = Table(
        "users",
        support_metadata,
        Column("username", User.__table__.c.username.type.copy(), primary_key=True),
    )
    tables = (
        users,
        SchedulingRuntimeState.__table__,
        Schedule.__table__,
        ScheduleExecution.__table__,
    )

    for table in reversed(tables):
        table.drop(database, checkfirst=True)
    for table in tables:
        table.create(database)
    try:
        yield database
    finally:
        for table in reversed(tables):
            table.drop(database, checkfirst=True)
        database.dispose()


@pytest.fixture
def shared_session_factory(monkeypatch, shared_database):
    factory = sessionmaker(bind=shared_database)
    monkeypatch.setattr(scheduling_engine, "Session", factory)
    try:
        yield factory
    finally:
        with shared_database.begin() as connection:
            connection.execute(delete(ScheduleExecution))
            connection.execute(delete(Schedule))
            connection.execute(delete(SchedulingRuntimeState))


def _claimed_execution(factory):
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
                created_at=100.0,
                updated_at=100.0,
            )
        )
    policy = SchedulingPolicy(
        execution_lease_seconds=60,
        lease_refresh_seconds=20,
    )
    generation = scheduling_engine.ensure_runtime_state("local", now=100.0)
    scheduling_engine.enqueue_due_schedules(generation, policy, now=100.0)
    claim = scheduling_engine.claim_execution(
        generation,
        "original-worker",
        policy,
        now=100.0,
    )
    assert claim is not None
    return generation, policy, claim


def _run_with_fixed_lock_order(
    monkeypatch,
    first: Callable[[], object],
    second: Callable[[], object],
) -> tuple[object, object]:
    original_lock_schedule = scheduling_commands.lock_schedule
    first_locked = threading.Event()
    second_entered = threading.Event()
    release_first = threading.Event()
    role = threading.local()

    def gated_lock_schedule(session, schedule_id):
        current_role = role.value
        if current_role == "second":
            second_entered.set()
        schedule = original_lock_schedule(session, schedule_id)
        if current_role == "first":
            first_locked.set()
            assert release_first.wait(10)
        return schedule

    def run_as(current_role, operation):
        role.value = current_role
        return operation()

    monkeypatch.setattr(scheduling_engine, "lock_schedule", gated_lock_schedule)
    monkeypatch.setattr(scheduling_commands, "lock_schedule", gated_lock_schedule)
    with ThreadPoolExecutor(max_workers=2) as executor:
        first_result = executor.submit(run_as, "first", first)
        assert first_locked.wait(10)
        second_result = executor.submit(run_as, "second", second)
        assert second_entered.wait(10)
        release_first.set()
        return first_result.result(timeout=15), second_result.result(timeout=15)


@pytest.mark.parametrize("first_operation", ["completion", "reclaim"])
def test_completion_and_reclaim_preserve_one_lease_owner(
    monkeypatch,
    shared_session_factory,
    first_operation,
):
    factory = shared_session_factory
    generation, policy, claim = _claimed_execution(factory)

    operations = {
        "completion": lambda: scheduling_engine.complete_execution(
            claim, generation, {"completed": True}, now=161.0
        ),
        "reclaim": lambda: scheduling_engine.claim_execution(
            generation, "replacement-worker", policy, now=161.0
        ),
    }
    second_operation = "reclaim" if first_operation == "completion" else "completion"
    results = dict(
        zip(
            (first_operation, second_operation),
            _run_with_fixed_lock_order(
                monkeypatch,
                operations[first_operation],
                operations[second_operation],
            ),
            strict=True,
        )
    )

    with factory() as session:
        schedule = session.get(Schedule, claim.schedule_id)
        execution = session.get(ScheduleExecution, claim.id)
        if first_operation == "completion":
            assert results == {"completion": True, "reclaim": None}
            assert schedule.active_execution_id is None
            assert execution.state == "succeeded"
            assert execution.lease_owner is None
        else:
            replacement = results["reclaim"]
            assert replacement is not None
            assert replacement.attempt == 2
            assert results["completion"] is False
            assert schedule.active_execution_id == claim.id
            assert execution.state == "running"
            assert execution.lease_owner == "replacement-worker"


@pytest.mark.parametrize("first_operation", ["failure", "reclaim"])
def test_failure_and_reclaim_preserve_one_lease_owner(
    monkeypatch,
    shared_session_factory,
    first_operation,
):
    factory = shared_session_factory
    generation, policy, claim = _claimed_execution(factory)

    operations = {
        "failure": lambda: scheduling_engine.fail_execution(
            claim,
            generation,
            max_attempts=1,
            initial_backoff_seconds=1,
            maximum_backoff_seconds=1,
            error="task failed",
            now=161.0,
        ),
        "reclaim": lambda: scheduling_engine.claim_execution(
            generation, "replacement-worker", policy, now=161.0
        ),
    }
    second_operation = "reclaim" if first_operation == "failure" else "failure"
    results = dict(
        zip(
            (first_operation, second_operation),
            _run_with_fixed_lock_order(
                monkeypatch,
                operations[first_operation],
                operations[second_operation],
            ),
            strict=True,
        )
    )

    with factory() as session:
        schedule = session.get(Schedule, claim.schedule_id)
        execution = session.get(ScheduleExecution, claim.id)
        if first_operation == "failure":
            assert results == {"failure": True, "reclaim": None}
            assert schedule.active_execution_id is None
            assert execution.state == "failed"
            assert execution.retry_at is None
            assert execution.lease_owner is None
        else:
            replacement = results["reclaim"]
            assert replacement is not None
            assert replacement.attempt == 2
            assert results["failure"] is False
            assert schedule.active_execution_id == claim.id
            assert execution.state == "running"
            assert execution.retry_at is None
            assert execution.lease_owner == "replacement-worker"


@pytest.mark.parametrize("first_operation", ["completion", "deletion"])
def test_completion_and_deletion_serialize_without_rollback(
    monkeypatch,
    shared_session_factory,
    first_operation,
):
    factory = shared_session_factory
    generation, _policy, claim = _claimed_execution(factory)

    def delete_claimed_schedule():
        with factory() as session, session.begin():
            return delete_schedule(
                session,
                claim.schedule_id,
                1,
                username="admin",
                now=101.0,
            )

    operations = {
        "completion": lambda: scheduling_engine.complete_execution(
            claim, generation, {"completed": True}, now=102.0
        ),
        "deletion": delete_claimed_schedule,
    }
    second_operation = "deletion" if first_operation == "completion" else "completion"
    results = dict(
        zip(
            (first_operation, second_operation),
            _run_with_fixed_lock_order(
                monkeypatch,
                operations[first_operation],
                operations[second_operation],
            ),
            strict=True,
        )
    )

    assert results == {"completion": True, "deletion": None}
    with factory() as session:
        schedule = session.get(Schedule, claim.schedule_id)
        execution = session.get(ScheduleExecution, claim.id)
        assert schedule.status == "deleted"
        assert schedule.active_execution_id is None
        assert execution.state == "succeeded"
        assert execution.result == {"completed": True}


@pytest.mark.parametrize("first_operation", ["completion", "cancellation"])
def test_completion_and_deleted_lease_cancellation_choose_one_terminal_state(
    monkeypatch,
    shared_session_factory,
    first_operation,
):
    factory = shared_session_factory
    generation, policy, claim = _claimed_execution(factory)
    with factory() as session, session.begin():
        delete_schedule(
            session,
            claim.schedule_id,
            1,
            username="admin",
            now=101.0,
        )

    operations = {
        "completion": lambda: scheduling_engine.complete_execution(
            claim, generation, {"completed": True}, now=160.0
        ),
        "cancellation": lambda: scheduling_engine.cancel_expired_deleted_executions(
            policy.claim_batch_size, now=160.0
        ),
    }
    second_operation = (
        "cancellation" if first_operation == "completion" else "completion"
    )
    results = dict(
        zip(
            (first_operation, second_operation),
            _run_with_fixed_lock_order(
                monkeypatch,
                operations[first_operation],
                operations[second_operation],
            ),
            strict=True,
        )
    )

    with factory() as session:
        schedule = session.get(Schedule, claim.schedule_id)
        execution = session.get(ScheduleExecution, claim.id)
        assert schedule.status == "deleted"
        assert schedule.active_execution_id is None
        if first_operation == "completion":
            assert results == {"completion": True, "cancellation": 0}
            assert execution.state == "succeeded"
            assert execution.result == {"completed": True}
        else:
            assert results == {"cancellation": 1, "completion": False}
            assert execution.state == "cancelled"
            assert execution.result is None
