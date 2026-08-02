from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from include.config.validation import ConfigValidationError
from include.database.models.identity import User
from include.database.models.operations import AuditEntry
from include.database.session import Base
from include.extensions.brute_force_lockdown import _extension as extension
from include.transport.request_handler import Result


def _config(**overrides):
    settings = {
        "window_seconds": 600,
        "failure_threshold": 50,
        "distinct_account_threshold": 10,
        "distinct_ip_threshold": 10,
        "reason": extension.DEFAULT_REASON,
    }
    settings.update(overrides)
    return {
        "extensions": {
            "enabled": ["brute_force_lockdown"],
            "brute_force_lockdown": settings,
        }
    }


def test_policy_uses_defaults_when_extension_table_is_missing():
    policy = extension.BruteForceLockdownPolicy.from_config(
        {"extensions": {"enabled": ["brute_force_lockdown"]}}
    )

    assert policy == extension.BruteForceLockdownPolicy()


def test_extension_advertises_capability_flag():
    assert extension.ext_register_extension_flags() == {"brute_force_lockdown"}


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"unknown": 1}, "unknown fields"),
        ({"window_seconds": True}, "positive integer"),
        ({"failure_threshold": 0}, "positive integer"),
        ({"distinct_account_threshold": 51}, "must not exceed"),
        ({"distinct_ip_threshold": 51}, "must not exceed"),
        ({"reason": "   "}, "non-empty string"),
        ({"reason": "x" * 1025}, "must not exceed 1024"),
    ],
)
def test_policy_rejects_invalid_values(overrides, message):
    with pytest.raises(ConfigValidationError, match=message):
        extension.BruteForceLockdownPolicy.from_config(_config(**overrides))


@pytest.fixture
def detector_database(monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(
        engine,
        tables=[User.__table__, AuditEntry.__table__],
    )
    testing_session = sessionmaker(bind=engine)
    monkeypatch.setattr(extension, "Session", testing_session)
    monkeypatch.setattr(extension, "_STARTED_AT", 0.0)
    monkeypatch.setattr(
        extension.lockdown_state_manager,
        "get_last_disabled_at",
        lambda: 0.0,
    )

    with testing_session.begin() as session:
        for username in ("alice", "bob"):
            session.add(
                User(
                    username=username,
                    pass_hash="unused",
                    passwd_last_modified=0,
                    created_time=0,
                )
            )

    return testing_session


def _audit_failure(session, username, ip_address, logged_time):
    session.add(
        AuditEntry(
            action="login",
            result=401,
            target=username,
            remote_address=ip_address,
            logged_time=logged_time,
        )
    )


def test_window_stats_include_current_audited_failure_once(detector_database):
    with detector_database.begin() as session:
        _audit_failure(session, "alice", "192.0.2.1", 950)
        _audit_failure(session, "bob", "192.0.2.2", 960)
        _audit_failure(session, "alice", "192.0.2.3", 1000)

    policy = extension.BruteForceLockdownPolicy(
        window_seconds=100,
        failure_threshold=3,
        distinct_account_threshold=2,
        distinct_ip_threshold=3,
    )

    stats = extension._collect_window_stats("alice", policy, now=1000)

    assert stats == extension.FailureWindowStats(
        failure_count=3,
        distinct_accounts=2,
        distinct_ip_addresses=3,
        window_started_at=900,
        observed_at=1000,
    )
    assert stats.reaches(policy) is True


def test_window_stats_exclude_expired_and_unknown_accounts(detector_database):
    with detector_database.begin() as session:
        _audit_failure(session, "alice", "192.0.2.1", 899)
        _audit_failure(session, "unknown", "192.0.2.2", 950)
        _audit_failure(session, "alice", "192.0.2.3", 1000)

    policy = extension.BruteForceLockdownPolicy(window_seconds=100)

    stats = extension._collect_window_stats("alice", policy, now=1000)

    assert stats.failure_count == 1
    assert stats.distinct_accounts == 1
    assert stats.distinct_ip_addresses == 1
    assert extension._collect_window_stats("unknown", policy, now=1000) is None


@pytest.mark.parametrize(
    ("action", "callback"),
    [
        ("login", None),
        ("login", Result(code=200, target="alice")),
        ("login", Result(code=202, target="alice")),
        ("login", Result(code=429, target="alice")),
        ("sso_oidc_callback", Result(code=401, target="alice")),
    ],
)
def test_detector_ignores_non_credential_failures(monkeypatch, action, callback):
    monkeypatch.setattr(
        extension,
        "_collect_window_stats",
        lambda *_args, **_kwargs: pytest.fail("unexpected detector query"),
    )

    extension.ext_post_request(
        action,
        SimpleNamespace(data={}, remote_address="192.0.2.1"),
        callback,
        0.1,
    )


def test_detector_triggers_once_at_threshold(monkeypatch):
    policy = extension.BruteForceLockdownPolicy(
        failure_threshold=3,
        distinct_account_threshold=2,
        distinct_ip_threshold=3,
    )
    stats = extension.FailureWindowStats(3, 2, 1, 900, 1000)
    transitions = []
    audits = []

    monkeypatch.setattr(
        extension.lockdown_state_manager,
        "get_state",
        lambda: SimpleNamespace(enabled=False),
    )
    monkeypatch.setattr(
        extension.BruteForceLockdownPolicy,
        "from_config",
        lambda _config: policy,
    )
    monkeypatch.setattr(
        extension,
        "_collect_window_stats",
        lambda *_args, **_kwargs: stats,
    )

    def fake_apply(*args, **kwargs):
        transitions.append((args, kwargs))
        return SimpleNamespace(applied=True, cancelled_file_tasks=4)

    monkeypatch.setattr(extension, "apply_lockdown", fake_apply)
    monkeypatch.setattr(
        extension,
        "_audit_automatic_lockdown",
        lambda *args: audits.append(args),
    )

    extension.ext_post_request(
        "login",
        SimpleNamespace(data={}, remote_address="192.0.2.1"),
        Result(code=401, target="alice"),
        0.1,
    )

    assert transitions == [
        (
            (True, extension.DEFAULT_REASON),
            {"only_if_inactive": True},
        )
    ]
    assert audits == [(policy, stats, 4)]


def test_window_stats_exclude_failures_before_last_unlock(
    detector_database, monkeypatch
):
    with detector_database.begin() as session:
        _audit_failure(session, "alice", "192.0.2.1", 949)
        _audit_failure(session, "alice", "192.0.2.2", 950)

    monkeypatch.setattr(
        extension.lockdown_state_manager,
        "get_last_disabled_at",
        lambda: 950.0,
    )

    stats = extension._collect_window_stats(
        "alice",
        extension.BruteForceLockdownPolicy(window_seconds=100),
        now=1000,
    )

    assert stats.failure_count == 1
    assert stats.window_started_at == 950.0


def test_automatic_audit_contains_only_aggregate_details(monkeypatch):
    calls = []
    policy = extension.BruteForceLockdownPolicy()
    stats = extension.FailureWindowStats(50, 10, 4, 900, 1000)
    monkeypatch.setattr(
        extension,
        "log_audit",
        lambda *args, **kwargs: calls.append((args, kwargs)),
    )

    extension._audit_automatic_lockdown(policy, stats, 2)

    args, kwargs = calls[0]
    assert args == ("automatic_lockdown", 0)
    assert kwargs["data"]["failure_count"] == 50
    assert kwargs["data"]["distinct_accounts"] == 10
    assert "username" not in kwargs["data"]
    assert "ip_address" not in kwargs["data"]
