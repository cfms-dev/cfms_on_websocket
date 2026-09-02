from types import SimpleNamespace

from pydantic import BaseModel
from sqlalchemy import create_engine
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
            )
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
