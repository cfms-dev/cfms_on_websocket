import datetime as dt

import pytest
from pydantic import BaseModel

from include.domains.access.permissions import Permissions
from include.scheduling import (
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


def test_registry_validates_task_contract_and_payload():
    registry = ScheduledTaskRegistry([_registration()])

    payload = registry.validate_payload("test.record", 1, {"value": 3})

    assert payload == _Payload(value=3)
    with pytest.raises(LookupError, match="contract version"):
        registry.validate_payload("test.record", 2, {"value": 3})


def test_registry_rejects_duplicate_task_types():
    with pytest.raises(ValueError, match="Duplicate"):
        ScheduledTaskRegistry([_registration(), _registration()])


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
