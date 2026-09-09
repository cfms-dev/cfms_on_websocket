from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from include.domains.access.permissions import Permissions
from include.extensions.scheduled_lockdown import _extension as extension
from include.scheduling import ScheduledTaskContext


def _context(execution_id: str, scheduled_for: float = 100.0):
    return ScheduledTaskContext(
        schedule_id="schedule-1",
        execution_id=execution_id,
        scheduled_for=scheduled_for,
        attempt=1,
    )


def test_extension_registers_user_schedulable_lockdown_window():
    (registration,) = extension.ext_register_scheduled_tasks()

    assert registration.name == "scheduled_lockdown.window"
    assert registration.contract_version == 1
    assert registration.required_permission is Permissions.APPLY_LOCKDOWN
    assert registration.user_schedulable is True
    assert registration.system_schedule is None


@pytest.mark.parametrize(
    "payload",
    [
        {"duration_seconds": 0},
        {"duration_seconds": -1},
        {"duration_seconds": True},
        {"duration_seconds": 60, "reason": ""},
        {"duration_seconds": 60, "unknown": True},
    ],
)
def test_window_payload_rejects_invalid_values(payload):
    with pytest.raises(ValidationError):
        extension.ScheduledLockdownWindowPayload.model_validate(payload)


def test_window_uses_execution_id_as_unique_activation(monkeypatch):
    calls = []

    def apply(activation_id, expires_at, reason):
        calls.append((activation_id, expires_at, reason))
        return SimpleNamespace(
            outcome="applied",
            cancelled_file_tasks=2,
        )

    monkeypatch.setattr(extension, "apply_scheduled_lockdown", apply)
    payload = extension.ScheduledLockdownWindowPayload(
        duration_seconds=60,
        reason="Maintenance",
    )

    first = extension.run_scheduled_lockdown_window(_context("execution-1"), payload)
    second = extension.run_scheduled_lockdown_window(
        _context("execution-2", 200.0), payload
    )

    assert calls == [
        ("execution-1", 160.0, "Maintenance"),
        ("execution-2", 260.0, "Maintenance"),
    ]
    assert first.data == {
        "activation_id": "execution-1",
        "expires_at": 160.0,
        "outcome": "applied",
        "cancelled_file_tasks": 2,
    }
    assert second.data["activation_id"] == "execution-2"
