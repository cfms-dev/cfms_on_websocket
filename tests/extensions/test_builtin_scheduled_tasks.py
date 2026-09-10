from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from include.domains.identity.commands.permission_cleanup import PermissionEntryCounts


def test_permission_cleanup_is_registered_as_a_system_interval_task(monkeypatch):
    from include.extensions.builtin import permission_cleanup

    policy = SimpleNamespace(cleanup_interval_seconds=180)
    monkeypatch.setattr(
        permission_cleanup,
        "IdentityPermissionRetentionPolicy",
        SimpleNamespace(from_config=lambda: policy),
    )
    monkeypatch.setattr(
        permission_cleanup,
        "cleanup_expired_permission_entries",
        lambda received_policy: (
            PermissionEntryCounts(user_entries=2, group_entries=3)
            if received_policy is policy
            else None
        ),
    )

    registration = permission_cleanup.permission_cleanup_task
    definition = registration.system_schedule()
    result = registration.execute(object(), registration.payload_model())

    assert registration.required_permission is None
    assert registration.user_schedulable is False
    assert registration.max_attempts == 1
    assert definition.id == "builtin.permission_cleanup"
    assert definition.trigger_type == "interval"
    assert definition.trigger_data == {"seconds": 180}
    assert result.data == {"user_entries": 2, "group_entries": 3}
    assert result.audit_success is True

    monkeypatch.setattr(
        permission_cleanup,
        "cleanup_expired_permission_entries",
        lambda _policy: PermissionEntryCounts(),
    )
    assert (
        registration.execute(object(), registration.payload_model()).audit_success
        is False
    )


def test_builtin_system_task_intervals_follow_their_policies(monkeypatch):
    from include.extensions.builtin import scheduled_tasks

    monkeypatch.setattr(
        scheduled_tasks.DocumentUploadPolicy,
        "from_config",
        classmethod(lambda _cls: SimpleNamespace(cleanup_interval_seconds=180)),
    )

    definitions = {
        registration.name: registration.system_schedule()
        for registration in scheduled_tasks.BUILTIN_SCHEDULED_TASKS
    }

    assert {
        name: definition.trigger_data for name, definition in definitions.items()
    } == {
        "builtin.upload_cleanup": {"seconds": 180},
        "builtin.auth_throttle_cleanup": {"seconds": 3600},
        "builtin.creation_risk_cleanup": {"seconds": 180},
        "builtin.download_risk_cleanup": {"seconds": 60},
    }
    assert all(definition.run_immediately for definition in definitions.values())
    for registration in scheduled_tasks.BUILTIN_SCHEDULED_TASKS:
        assert registration.required_permission is None
        assert registration.user_schedulable is False
        assert registration.max_attempts == 1
        with pytest.raises(ValidationError):
            registration.payload_model.model_validate({"unexpected": True})


def test_builtin_system_tasks_return_cleanup_counts(monkeypatch):
    from include.extensions.builtin import scheduled_tasks

    session = object()

    class SessionFactory:
        def __call__(self):
            return nullcontext(session)

        def begin(self):
            return nullcontext(session)

    monkeypatch.setattr(
        scheduled_tasks,
        "Session",
        SessionFactory(),
    )
    monkeypatch.setattr(
        scheduled_tasks,
        "database_now",
        lambda received_session: 123.0 if received_session is session else None,
    )
    monkeypatch.setattr(
        scheduled_tasks,
        "reclaim_abandoned_uploads",
        lambda now, *, limit: (
            SimpleNamespace(
                matched_tasks=limit,
                expired_tasks=2,
                removed_revisions=3,
                removed_documents=4,
                storage_cleanup_failures=5,
            )
            if now == 123.0
            else None
        ),
    )
    policy = object()
    monkeypatch.setattr(
        scheduled_tasks.AuthThrottlePolicy,
        "from_config",
        classmethod(lambda _cls: policy),
    )
    monkeypatch.setattr(
        scheduled_tasks,
        "purge_expired_auth_throttle_records",
        lambda received_policy, *, now: (
            SimpleNamespace(account_records=6, login_records=7, traffic_records=8)
            if received_policy is policy and now == 123.0
            else None
        ),
    )
    monkeypatch.setattr(
        scheduled_tasks,
        "cleanup_document_creation_risk_state",
        lambda received_session, *, now: (
            SimpleNamespace(ip_accounts=9, buckets=10)
            if received_session is session and now == 123.0
            else None
        ),
    )
    monkeypatch.setattr(
        scheduled_tasks,
        "cleanup_document_download_risk_state",
        lambda received_session, *, now: (
            SimpleNamespace(ip_accounts=11, buckets=12)
            if received_session is session and now == 123.0
            else None
        ),
    )
    registrations = {
        registration.name: registration
        for registration in scheduled_tasks.BUILTIN_SCHEDULED_TASKS
    }

    results = {
        name: registration.execute(object(), registration.payload_model())
        for name, registration in registrations.items()
    }

    assert {name: result.data for name, result in results.items()} == {
        "builtin.upload_cleanup": {
            "matched_tasks": 256,
            "expired_tasks": 2,
            "removed_revisions": 3,
            "removed_documents": 4,
            "storage_cleanup_failures": 5,
        },
        "builtin.auth_throttle_cleanup": {
            "account_records": 6,
            "login_records": 7,
            "traffic_records": 8,
        },
        "builtin.creation_risk_cleanup": {"ip_accounts": 9, "buckets": 10},
        "builtin.download_risk_cleanup": {"ip_accounts": 11, "buckets": 12},
    }
    assert all(result.audit_success for result in results.values())


def test_builtin_system_tasks_suppress_empty_cleanup_audits(monkeypatch):
    from include.extensions.builtin import scheduled_tasks

    session = object()

    class SessionFactory:
        def __call__(self):
            return nullcontext(session)

        def begin(self):
            return nullcontext(session)

    monkeypatch.setattr(scheduled_tasks, "Session", SessionFactory())
    monkeypatch.setattr(scheduled_tasks, "database_now", lambda _session: 123.0)
    monkeypatch.setattr(
        scheduled_tasks,
        "reclaim_abandoned_uploads",
        lambda *_args, **_kwargs: SimpleNamespace(
            matched_tasks=0,
            expired_tasks=0,
            removed_revisions=0,
            removed_documents=0,
            storage_cleanup_failures=0,
        ),
    )
    monkeypatch.setattr(
        scheduled_tasks.AuthThrottlePolicy,
        "from_config",
        classmethod(lambda _cls: object()),
    )
    monkeypatch.setattr(
        scheduled_tasks,
        "purge_expired_auth_throttle_records",
        lambda *_args, **_kwargs: SimpleNamespace(
            account_records=0,
            login_records=0,
            traffic_records=0,
        ),
    )
    monkeypatch.setattr(
        scheduled_tasks,
        "cleanup_document_creation_risk_state",
        lambda *_args, **_kwargs: SimpleNamespace(ip_accounts=0, buckets=0),
    )
    monkeypatch.setattr(
        scheduled_tasks,
        "cleanup_document_download_risk_state",
        lambda *_args, **_kwargs: SimpleNamespace(ip_accounts=0, buckets=0),
    )

    results = [
        registration.execute(object(), registration.payload_model())
        for registration in scheduled_tasks.BUILTIN_SCHEDULED_TASKS
    ]

    assert all(result.audit_success is False for result in results)


def test_permission_cleanup_uses_database_clock(monkeypatch):
    from include.extensions.builtin import permission_cleanup

    session = object()
    policy = SimpleNamespace(retention_days=2, batch_size=10)
    monkeypatch.setattr(
        permission_cleanup,
        "Session",
        SimpleNamespace(begin=lambda: nullcontext(session)),
    )
    monkeypatch.setattr(
        permission_cleanup,
        "database_now",
        lambda received_session: 200_000.0 if received_session is session else None,
    )
    calls = []

    def purge(received_session, cutoff, batch_size):
        calls.append((received_session, cutoff, batch_size))
        return PermissionEntryCounts(user_entries=0, group_entries=0)

    monkeypatch.setattr(permission_cleanup, "purge_expired_permission_entries", purge)

    result = permission_cleanup.cleanup_expired_permission_entries(policy)

    assert result.total == 0
    assert calls == [(session, 27_200.0, 10)]


def test_core_schedule_history_cleanup_is_always_registered(monkeypatch):
    from include.scheduling import tasks

    policy = object()
    monkeypatch.setattr(
        tasks.SchedulingPolicy,
        "from_config",
        classmethod(lambda _cls: policy),
    )
    monkeypatch.setattr(
        tasks,
        "purge_execution_history",
        lambda received_policy: 13 if received_policy is policy else None,
    )

    registration = tasks.CORE_SCHEDULED_TASKS[0]
    definition = registration.system_schedule()
    result = registration.execute(object(), registration.payload_model())

    assert registration.name == "core.schedule_history_cleanup"
    assert registration.required_permission is None
    assert registration.user_schedulable is False
    assert registration.max_attempts == 1
    assert definition.id == registration.name
    assert definition.trigger_data == {"seconds": 3600}
    assert result.data == {"deleted_executions": 13}
    assert result.audit_success is True

    monkeypatch.setattr(tasks, "purge_execution_history", lambda _policy: 0)
    assert (
        registration.execute(object(), registration.payload_model()).audit_success
        is False
    )


def test_core_lockdown_expiry_schedule_tracks_active_activation(monkeypatch):
    from include.scheduling import tasks

    registration = next(
        item
        for item in tasks.CORE_SCHEDULED_TASKS
        if item.name == "core.lockdown_expiry"
    )
    monkeypatch.setattr(
        tasks.lockdown_state_manager,
        "get_scheduled_activation",
        lambda: None,
    )
    assert registration.system_schedule() is None

    monkeypatch.setattr(
        tasks.lockdown_state_manager,
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


def test_core_lockdown_expiry_runs_immediately_when_overdue(monkeypatch):
    from include.scheduling import tasks

    registration = next(
        item
        for item in tasks.CORE_SCHEDULED_TASKS
        if item.name == "core.lockdown_expiry"
    )
    monkeypatch.setattr(
        tasks.lockdown_state_manager,
        "get_scheduled_activation",
        lambda: SimpleNamespace(
            activation_id="execution-1",
            expires_at=200.0,
            observed_at=201.0,
        ),
    )
    monkeypatch.setattr(
        tasks,
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
