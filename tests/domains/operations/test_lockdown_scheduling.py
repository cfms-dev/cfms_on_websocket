from types import SimpleNamespace

from include.domains.operations.lockdown import scheduling


def test_expiry_schedule_tracks_active_activation(monkeypatch):
    registration = scheduling.lockdown_expiry_task
    monkeypatch.setattr(
        scheduling.lockdown_state_manager,
        "get_scheduled_activation",
        lambda: None,
    )
    assert registration.system_schedule() is None

    monkeypatch.setattr(
        scheduling.lockdown_state_manager,
        "get_scheduled_activation",
        lambda: SimpleNamespace(
            activation_id="execution-1",
            expires_at=200.0,
            observed_at=100.0,
        ),
    )
    definition = registration.system_schedule()

    assert definition.id == "core.lockdown_expiry"
    assert definition.trigger_type == "date"
    assert definition.trigger_data == {"run_at": "1970-01-01T00:03:20+00:00"}
    assert definition.payload == {"activation_id": "execution-1"}
    assert definition.run_immediately is False

    monkeypatch.setattr(
        scheduling.lockdown_state_manager,
        "get_scheduled_activation",
        lambda: SimpleNamespace(
            activation_id="execution-2",
            expires_at=None,
            observed_at=100.0,
        ),
    )
    assert registration.system_schedule() is None


def test_expiry_runs_immediately_when_overdue(monkeypatch):
    registration = scheduling.lockdown_expiry_task
    monkeypatch.setattr(
        scheduling.lockdown_state_manager,
        "get_scheduled_activation",
        lambda: SimpleNamespace(
            activation_id="execution-1",
            expires_at=200.0,
            observed_at=201.0,
        ),
    )
    monkeypatch.setattr(
        scheduling,
        "expire_scheduled_lockdown",
        lambda activation_id: (
            SimpleNamespace(outcome="applied")
            if activation_id == "execution-1"
            else None
        ),
    )

    definition = registration.system_schedule()
    result = registration.execute(
        object(),
        registration.payload_model(activation_id="execution-1"),
    )

    assert definition.run_immediately is True
    assert result.data == {
        "activation_id": "execution-1",
        "outcome": "applied",
    }
