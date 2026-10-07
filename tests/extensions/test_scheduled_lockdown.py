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


def test_extension_registers_user_schedulable_lockdown_tasks():
    registrations = {
        registration.name: registration
        for registration in extension.ext_register_scheduled_tasks()
    }

    assert set(registrations) == {
        "scheduled_lockdown.window",
        "scheduled_lockdown.enable",
        "scheduled_lockdown.disable",
    }
    for registration in registrations.values():
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


@pytest.mark.parametrize(
    ("model", "payload"),
    [
        (extension.ScheduledLockdownEnablePayload, {"reason": ""}),
        (extension.ScheduledLockdownEnablePayload, {"reason": True}),
        (extension.ScheduledLockdownEnablePayload, {"unknown": True}),
        (extension.ScheduledLockdownDisablePayload, {"reason": None}),
        (extension.ScheduledLockdownDisablePayload, {"unknown": True}),
    ],
)
def test_transition_payloads_reject_invalid_values(model, payload):
    with pytest.raises(ValidationError):
        model.model_validate(payload)


@pytest.mark.parametrize(
    ("execution_id", "scheduled_for", "expires_at"),
    [
        pytest.param("execution-1", 100.0, 160.0, id="first-occurrence"),
        pytest.param("execution-2", 200.0, 260.0, id="later-occurrence"),
    ],
)
def test_window_uses_execution_id_as_unique_activation(
    monkeypatch, execution_id, scheduled_for, expires_at
):
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

    result = extension.run_scheduled_lockdown_window(
        _context(execution_id, scheduled_for), payload
    )

    assert calls == [(execution_id, expires_at, "Maintenance")]
    assert result.data == {
        "activation_id": execution_id,
        "expires_at": expires_at,
        "outcome": "applied",
        "cancelled_file_tasks": 2,
    }


def test_enable_uses_execution_id_without_an_expiry(monkeypatch):
    calls = []

    def apply(activation_id, expires_at, reason):
        calls.append((activation_id, expires_at, reason))
        return SimpleNamespace(outcome="applied", cancelled_file_tasks=3)

    monkeypatch.setattr(extension, "apply_scheduled_lockdown", apply)

    result = extension.run_scheduled_lockdown_enable(
        _context("execution-1"),
        extension.ScheduledLockdownEnablePayload(reason="Maintenance"),
    )

    assert calls == [("execution-1", None, "Maintenance")]
    assert result.data == {
        "activation_id": "execution-1",
        "outcome": "applied",
        "cancelled_file_tasks": 3,
    }


def test_disable_runs_the_guarded_domain_transition(monkeypatch):
    monkeypatch.setattr(
        extension,
        "disable_scheduled_lockdown",
        lambda: SimpleNamespace(outcome="condition_not_met"),
    )

    result = extension.run_scheduled_lockdown_disable(
        _context("execution-1"),
        extension.ScheduledLockdownDisablePayload(),
    )

    assert result.data == {"outcome": "condition_not_met"}
