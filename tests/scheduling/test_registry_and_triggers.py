import datetime as dt
from types import SimpleNamespace
from typing import assert_type

import pytest
from pydantic import BaseModel

from include.domains.access.permissions import Permissions
from include.scheduling import (
    ScheduledTaskContext,
    ScheduledTaskRegistration,
    ScheduledTaskRegistry,
)
from include.scheduling.triggers import (
    TriggerValidationError,
    advance_trigger,
    build_trigger,
    first_run_at,
)


class _Payload(BaseModel):
    value: int


def _registration(name="test.record", version=1):
    return ScheduledTaskRegistration(
        name=name,
        contract_version=version,
        payload_model=_Payload,
        execute=lambda _context, _payload: None,
        required_permission=Permissions.MANAGE_SYSTEM,
    )


def test_registration_correlates_payload_model_and_callback():
    def execute(_context: ScheduledTaskContext, _payload: _Payload) -> None:
        pass

    registration = ScheduledTaskRegistration(
        name="test.record",
        contract_version=1,
        payload_model=_Payload,
        execute=execute,
        required_permission=Permissions.MANAGE_SYSTEM,
    )

    assert_type(registration, ScheduledTaskRegistration[_Payload])
    assert registration.payload_model is _Payload
    assert registration.execute is execute


def test_registry_validates_task_contract_and_payload():
    registry = ScheduledTaskRegistry([_registration()])

    payload = registry.validate_payload("test.record", 1, {"value": 3})

    assert payload == _Payload(value=3)
    with pytest.raises(LookupError, match="contract version"):
        registry.validate_payload("test.record", 2, {"value": 3})


def test_registry_rejects_duplicate_task_types():
    with pytest.raises(ValueError, match="Duplicate"):
        ScheduledTaskRegistry([_registration(), _registration()])


def test_system_tasks_do_not_require_user_permissions():
    registration = ScheduledTaskRegistration(
        name="core.cleanup",
        contract_version=1,
        payload_model=_Payload,
        execute=lambda _context, _payload: None,
        user_schedulable=False,
    )

    assert registration.required_permission is None


def test_user_schedulable_tasks_require_a_permission():
    with pytest.raises(ValueError, match="required permission"):
        ScheduledTaskRegistration(
            name="test.record",
            contract_version=1,
            payload_model=_Payload,
            execute=lambda _context, _payload: None,
        )


def test_collected_registry_contains_core_and_loaded_extension_tasks(monkeypatch):
    from include.extensions import manager

    monkeypatch.setattr(
        manager,
        "pm",
        SimpleNamespace(
            hook=SimpleNamespace(
                ext_register_scheduled_tasks=lambda: [
                    (_registration("extension.record"),)
                ]
            )
        ),
    )

    registry = manager.collect_scheduled_tasks()

    assert registry.get("core.schedule_history_cleanup") is not None
    assert registry.get("extension.record") is not None


def test_extension_cannot_replace_a_core_task_registration(monkeypatch):
    from include.extensions import manager

    monkeypatch.setattr(
        manager,
        "pm",
        SimpleNamespace(
            hook=SimpleNamespace(
                ext_register_scheduled_tasks=lambda: [
                    (_registration("core.schedule_history_cleanup"),)
                ]
            )
        ),
    )

    with pytest.raises(ValueError, match="Duplicate scheduled task type"):
        manager.collect_scheduled_tasks()


def test_cron_trigger_coalesces_to_latest_occurrence_in_grace_window():
    trigger = build_trigger("cron", {"expression": "* * * * *"}, "UTC")
    now = dt.datetime(2026, 1, 1, 12, 5, 30, tzinfo=dt.UTC).timestamp()
    current = dt.datetime(2026, 1, 1, 12, 0, tzinfo=dt.UTC).timestamp()

    advanced = advance_trigger(trigger, current, now, 180)

    assert (
        advanced.latest_due_at
        == dt.datetime(2026, 1, 1, 12, 5, tzinfo=dt.UTC).timestamp()
    )
    assert (
        advanced.next_run_at
        == dt.datetime(2026, 1, 1, 12, 6, tzinfo=dt.UTC).timestamp()
    )


def test_interval_trigger_preserves_its_start_anchor():
    trigger = build_trigger(
        "interval",
        {"seconds": 60, "start_at": "2026-01-01T00:00:30+00:00"},
        "UTC",
    )
    now = dt.datetime(2026, 1, 1, tzinfo=dt.UTC).timestamp()

    assert (
        first_run_at(trigger, now)
        == dt.datetime(2026, 1, 1, 0, 0, 30, tzinfo=dt.UTC).timestamp()
    )


def test_date_trigger_requires_an_absolute_time():
    with pytest.raises(TriggerValidationError, match="UTC offset"):
        build_trigger("date", {"run_at": "2026-01-01T12:00:00"}, "UTC")
