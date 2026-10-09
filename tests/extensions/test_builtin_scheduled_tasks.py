from contextlib import nullcontext
from types import SimpleNamespace

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import sessionmaker

from include.domains.identity.commands.permission_cleanup import PermissionEntryCounts
from include.extensions.builtin import permission_cleanup, scheduled_tasks
from include.scheduling import tasks


@pytest.mark.unit
def test_permission_cleanup_is_registered_as_a_system_interval_task(monkeypatch):
    monkeypatch.setattr(
        permission_cleanup.IdentityPermissionRetentionPolicy,
        "from_config",
        classmethod(lambda _cls: SimpleNamespace(cleanup_interval_seconds=180)),
    )
    registration = permission_cleanup.permission_cleanup_task

    definition = registration.system_schedule()

    assert registration.required_permission is None
    assert registration.user_schedulable is False
    assert registration.max_attempts == 1
    assert definition.id == "builtin.permission_cleanup"
    assert definition.trigger_type == "interval"
    assert definition.trigger_data == {"seconds": 180}


@pytest.mark.unit
@pytest.mark.parametrize(
    ("counts", "expected_data", "audit_success"),
    [
        pytest.param(
            PermissionEntryCounts(user_entries=2, group_entries=3),
            {"user_entries": 2, "group_entries": 3},
            True,
            id="nonempty",
        ),
        pytest.param(
            PermissionEntryCounts(),
            {"user_entries": 0, "group_entries": 0},
            False,
            id="empty",
        ),
    ],
)
def test_permission_cleanup_task_reports_counts_and_audit_policy(
    monkeypatch, counts, expected_data, audit_success
):
    policy = object()
    monkeypatch.setattr(
        permission_cleanup.IdentityPermissionRetentionPolicy,
        "from_config",
        classmethod(lambda _cls: policy),
    )

    def cleanup(received_policy):
        assert received_policy is policy
        return counts

    monkeypatch.setattr(
        permission_cleanup, "cleanup_expired_permission_entries", cleanup
    )
    registration = permission_cleanup.permission_cleanup_task

    result = registration.execute(object(), registration.payload_model())

    assert result.data == expected_data
    assert result.audit_success is audit_success


@pytest.mark.unit
@pytest.mark.parametrize(
    ("task_name", "seconds"),
    [
        pytest.param("builtin.upload_cleanup", 180, id="upload"),
        pytest.param("builtin.auth_throttle_cleanup", 3600, id="authentication"),
        pytest.param("builtin.creation_risk_cleanup", 180, id="creation-risk"),
        pytest.param("builtin.download_risk_cleanup", 60, id="download-risk"),
    ],
)
def test_builtin_system_task_interval_follows_policy(monkeypatch, task_name, seconds):
    monkeypatch.setattr(
        scheduled_tasks.DocumentUploadPolicy,
        "from_config",
        classmethod(lambda _cls: SimpleNamespace(cleanup_interval_seconds=180)),
    )
    registration = next(
        item
        for item in scheduled_tasks.BUILTIN_SCHEDULED_TASKS
        if item.name == task_name
    )

    definition = registration.system_schedule()

    assert definition.id == task_name
    assert definition.trigger_data == {"seconds": seconds}
    assert definition.run_immediately is True
    assert registration.required_permission is None
    assert registration.user_schedulable is False
    assert registration.max_attempts == 1


@pytest.mark.unit
@pytest.mark.parametrize(
    "registration", scheduled_tasks.BUILTIN_SCHEDULED_TASKS, ids=lambda item: item.name
)
def test_builtin_system_task_rejects_payload_fields(registration):
    with pytest.raises(ValidationError, match="unexpected"):
        registration.payload_model.model_validate({"unexpected": True})


@pytest.fixture
def _task_sessions(monkeypatch, sqlite_engine_factory):
    database = sqlite_engine_factory()
    monkeypatch.setattr(scheduled_tasks, "Session", sessionmaker(bind=database))
    monkeypatch.setattr(scheduled_tasks, "database_now", lambda _session: 123.0)


@pytest.mark.component
@pytest.mark.usefixtures("_task_sessions")
@pytest.mark.parametrize(
    ("task_name", "cleanup_name", "counts"),
    [
        pytest.param(
            "builtin.upload_cleanup",
            "reclaim_abandoned_uploads",
            {
                "matched_tasks": 256,
                "expired_tasks": 2,
                "removed_revisions": 3,
                "removed_documents": 4,
                "storage_cleanup_failures": 5,
            },
            id="upload",
        ),
        pytest.param(
            "builtin.auth_throttle_cleanup",
            "purge_expired_auth_throttle_records",
            {"account_records": 6, "login_records": 7, "traffic_records": 8},
            id="authentication",
        ),
        pytest.param(
            "builtin.creation_risk_cleanup",
            "cleanup_document_creation_risk_state",
            {"ip_accounts": 9, "buckets": 10},
            id="creation-risk",
        ),
        pytest.param(
            "builtin.download_risk_cleanup",
            "cleanup_document_download_risk_state",
            {"ip_accounts": 11, "buckets": 12},
            id="download-risk",
        ),
    ],
)
@pytest.mark.parametrize("empty", [False, True], ids=["nonempty", "empty"])
def test_builtin_cleanup_task_reports_its_counts_and_audit_policy(
    monkeypatch, task_name, cleanup_name, counts, empty
):
    expected_data = {key: 0 for key in counts} if empty else counts
    policy = object()
    if task_name == "builtin.auth_throttle_cleanup":
        monkeypatch.setattr(
            scheduled_tasks.AuthThrottlePolicy,
            "from_config",
            classmethod(lambda _cls: policy),
        )

    def cleanup(*args, **kwargs):
        assert kwargs["now"] == 123.0
        if task_name == "builtin.upload_cleanup":
            assert kwargs["limit"] == 256
        elif task_name == "builtin.auth_throttle_cleanup":
            assert args == (policy,)
        else:
            assert args[0].in_transaction() is True
        return SimpleNamespace(**expected_data)

    monkeypatch.setattr(scheduled_tasks, cleanup_name, cleanup)
    registration = next(
        item
        for item in scheduled_tasks.BUILTIN_SCHEDULED_TASKS
        if item.name == task_name
    )

    result = registration.execute(object(), registration.payload_model())

    assert result.data == expected_data
    assert result.audit_success is (not empty)


@pytest.mark.unit
def test_permission_cleanup_uses_database_clock(monkeypatch):
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


@pytest.mark.unit
def test_core_schedule_history_cleanup_is_always_registered():
    registration = next(
        item
        for item in tasks.CORE_SCHEDULED_TASKS
        if item.name == "core.schedule_history_cleanup"
    )

    definition = registration.system_schedule()

    assert registration.required_permission is None
    assert registration.user_schedulable is False
    assert registration.max_attempts == 1
    assert definition.id == registration.name
    assert definition.trigger_data == {"seconds": 3600}


@pytest.mark.unit
@pytest.mark.parametrize("deleted", [13, 0], ids=["nonempty", "empty"])
def test_schedule_history_cleanup_reports_count_and_audit_policy(monkeypatch, deleted):
    policy = object()
    monkeypatch.setattr(
        tasks.SchedulingPolicy,
        "from_config",
        classmethod(lambda _cls: policy),
    )

    def purge(received_policy):
        assert received_policy is policy
        return deleted

    monkeypatch.setattr(tasks, "purge_execution_history", purge)
    registration = next(
        item
        for item in tasks.CORE_SCHEDULED_TASKS
        if item.name == "core.schedule_history_cleanup"
    )

    result = registration.execute(object(), registration.payload_model())

    assert result.data == {"deleted_executions": deleted}
    assert result.audit_success is (deleted > 0)
