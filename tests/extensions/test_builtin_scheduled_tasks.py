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
    monkeypatch.setattr(
        scheduled_tasks,
        "Session",
        SimpleNamespace(begin=lambda: nullcontext(session)),
    )
    monkeypatch.setattr(
        scheduled_tasks,
        "reclaim_abandoned_uploads",
        lambda *, limit: SimpleNamespace(
            matched_tasks=limit,
            expired_tasks=2,
            removed_revisions=3,
            removed_documents=4,
            storage_cleanup_failures=5,
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
        lambda received_policy: (
            SimpleNamespace(account_records=6, login_records=7, traffic_records=8)
            if received_policy is policy
            else None
        ),
    )
    monkeypatch.setattr(
        scheduled_tasks,
        "cleanup_document_creation_risk_state",
        lambda received_session: (
            SimpleNamespace(ip_accounts=9, buckets=10)
            if received_session is session
            else None
        ),
    )
    monkeypatch.setattr(
        scheduled_tasks,
        "cleanup_document_download_risk_state",
        lambda received_session: (
            SimpleNamespace(ip_accounts=11, buckets=12)
            if received_session is session
            else None
        ),
    )
    registrations = {
        registration.name: registration
        for registration in scheduled_tasks.BUILTIN_SCHEDULED_TASKS
    }

    results = {
        name: registration.execute(object(), registration.payload_model()).data
        for name, registration in registrations.items()
    }

    assert results == {
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
