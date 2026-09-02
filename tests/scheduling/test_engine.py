from pydantic import BaseModel
from sqlalchemy import create_engine, select
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
)
from include.scheduling import engine as scheduling_engine


class _Payload(BaseModel):
    value: int


def _session_factory(monkeypatch):
    database = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    SchedulingRuntimeState.__table__.create(database)
    Schedule.__table__.create(database)
    ScheduleExecution.__table__.create(database)
    factory = sessionmaker(bind=database, expire_on_commit=False)
    monkeypatch.setattr(scheduling_engine, "Session", factory)
    return factory


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
