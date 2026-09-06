from types import SimpleNamespace

from pydantic import BaseModel
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from include.database.models.scheduling import Schedule
from include.domains.access.permissions import Permissions
from include.extensions.scheduling import handlers
from include.providers.base import SchedulingProviderStatus
from include.scheduling import ScheduledTaskRegistration, ScheduledTaskRegistry


class _Payload(BaseModel):
    value: int


class _Connection:
    def __init__(self, data):
        self.data = data
        self.username = "admin"
        self.response = None

    def conclude_request(self, code, data, message):
        self.response = (code, data, message)


def _context(monkeypatch, permissions):
    database = create_engine("sqlite://")
    Schedule.__table__.create(database)
    factory = sessionmaker(bind=database, expire_on_commit=False)
    registry = ScheduledTaskRegistry(
        [
            ScheduledTaskRegistration(
                name="test.record",
                contract_version=1,
                payload_model=_Payload,
                execute=lambda _context, _payload: None,
                required_permission=Permissions.MANAGE_SYSTEM,
            ),
            ScheduledTaskRegistration(
                name="test.system_cleanup",
                contract_version=1,
                payload_model=_Payload,
                execute=lambda _context, _payload: None,
                required_permission=Permissions.MANAGE_SYSTEM,
                user_schedulable=False,
            ),
        ]
    )
    notifications = []
    provider = SimpleNamespace(
        status=lambda: SchedulingProviderStatus(True, "local"),
        notify_schedule_change=lambda: notifications.append(True),
    )
    monkeypatch.setattr(handlers, "Session", factory)
    monkeypatch.setattr(handlers, "collect_scheduled_tasks", lambda: registry)
    monkeypatch.setattr(handlers, "_permissions", lambda _username: permissions)
    monkeypatch.setattr(
        handlers, "ProviderManager", lambda: SimpleNamespace(scheduling=provider)
    )
    return notifications


def test_create_schedule_requires_management_and_task_permissions(monkeypatch):
    _context(monkeypatch, {Permissions.MANAGE_SCHEDULES})
    connection = _Connection(
        {
            "task_name": "test.record",
            "payload": {"value": 1},
            "trigger": {
                "type": "date",
                "data": {"run_at": "2026-01-01T00:00:00+00:00"},
                "timezone": "UTC",
            },
        }
    )

    result = handlers.RequestCreateScheduleHandler().handle(connection)

    assert result.code == 403
    assert connection.response[0] == 403


def test_create_schedule_persists_and_notifies_provider(monkeypatch):
    notifications = _context(
        monkeypatch,
        {Permissions.MANAGE_SCHEDULES, Permissions.MANAGE_SYSTEM},
    )
    connection = _Connection(
        {
            "task_name": "test.record",
            "payload": {"value": 1},
            "trigger": {
                "type": "date",
                "data": {"run_at": "2026-01-01T00:00:00+00:00"},
                "timezone": "UTC",
            },
        }
    )

    result = handlers.RequestCreateScheduleHandler().handle(connection)

    assert result.code == 0
    assert connection.response[0] == 200
    assert connection.response[1]["task_name"] == "test.record"
    assert notifications == [True]


def test_create_schedule_rejects_unrepresentable_interval(monkeypatch):
    notifications = _context(
        monkeypatch,
        {Permissions.MANAGE_SCHEDULES, Permissions.MANAGE_SYSTEM},
    )
    connection = _Connection(
        {
            "task_name": "test.record",
            "payload": {"value": 1},
            "trigger": {
                "type": "interval",
                "data": {
                    "seconds": 10**100,
                    "start_at": "2026-01-01T00:00:00+00:00",
                },
                "timezone": "UTC",
            },
        }
    )

    result = handlers.RequestCreateScheduleHandler().handle(connection)

    assert result.code == 400
    assert connection.response == (400, {}, "interval.seconds is too large")
    assert notifications == []
    with handlers.Session() as session:
        assert session.scalar(select(Schedule.id)) is None


def test_scheduling_api_returns_503_when_provider_is_degraded(monkeypatch):
    provider = SimpleNamespace(
        status=lambda: SchedulingProviderStatus(False, "redis", "unreachable")
    )
    monkeypatch.setattr(
        handlers, "ProviderManager", lambda: SimpleNamespace(scheduling=provider)
    )
    connection = _Connection({})

    result = handlers.RequestListScheduledTaskTypesHandler().handle(connection)

    assert result.code == 503
    assert connection.response[0] == 503


def test_system_tasks_and_schedules_are_hidden_from_management_api(monkeypatch):
    _context(
        monkeypatch,
        {Permissions.VIEW_SCHEDULES, Permissions.MANAGE_SYSTEM},
    )
    task_types = _Connection({})
    result = handlers.RequestListScheduledTaskTypesHandler().handle(task_types)

    assert result.code == 0
    assert [item["name"] for item in task_types.response[1]["items"]] == ["test.record"]

    with handlers.Session() as session, session.begin():
        session.add(
            Schedule(
                id="test.system_cleanup",
                task_name="test.system_cleanup",
                task_contract_version=1,
                payload={"value": 1},
                trigger_type="interval",
                trigger_data={
                    "seconds": 60,
                    "start_at": "2026-01-01T00:00:00+00:00",
                },
                timezone="UTC",
                system_managed=True,
                next_run_at=100.0,
                created_by=None,
                updated_by=None,
            )
        )

    schedules = _Connection({})
    result = handlers.RequestListSchedulesHandler().handle(schedules)

    assert result.code == 0
    assert schedules.response[1]["items"] == []
