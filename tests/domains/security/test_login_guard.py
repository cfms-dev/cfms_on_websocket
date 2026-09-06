from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from shutil import copyfile
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def guard_context(monkeypatch, tmp_path):
    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)

    from include.database.models.comments import Comment
    from include.database.models.security import (
        AccountThrottle,
        BannedSubnet,
        LoginThrottle,
        TrafficThrottle,
    )
    from include.database.session import Base
    from include.domains.security.guards import login
    from include.providers.caching.memory import MemoryCachingProvider
    from include.providers.manager import ProviderManager

    test_engine = create_engine(f"sqlite:///{tmp_path / 'guard.db'}")
    Base.metadata.create_all(
        test_engine,
        tables=[
            Comment.__table__,
            AccountThrottle.__table__,
            BannedSubnet.__table__,
            LoginThrottle.__table__,
            TrafficThrottle.__table__,
        ],
    )
    test_session = sessionmaker(bind=test_engine)
    policy = login.AuthThrottlePolicy(
        account_failure_threshold=3,
        account_base_delay_seconds=30,
        account_max_delay_seconds=120,
        account_reset_seconds=3600,
        account_ip_failure_threshold=100,
        account_ip_window_seconds=900,
        account_ip_block_seconds=900,
        ip_failure_threshold=100,
        ip_window_seconds=600,
        ip_block_seconds=900,
        record_retention_days=1,
    )

    monkeypatch.setattr(login, "Session", test_session)
    monkeypatch.setattr(login, "engine", test_engine)
    monkeypatch.setattr(login, "log_audit", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        login.AuthThrottlePolicy,
        "from_config",
        classmethod(lambda _cls: policy),
    )
    ProviderManager().register(MemoryCachingProvider())
    monkeypatch.setattr(login.LoginGuard, "_banned_rules", [])
    monkeypatch.setattr(login.LoginGuard, "_networks_loaded", True)

    yield SimpleNamespace(
        login=login,
        policy=policy,
        Session=test_session,
        BannedSubnet=BannedSubnet,
        AccountThrottle=AccountThrottle,
        LoginThrottle=LoginThrottle,
        TrafficThrottle=TrafficThrottle,
    )
    test_engine.dispose()


def test_distributed_failures_trigger_account_throttle(guard_context):
    guard = guard_context.login.LoginGuard
    factor = guard_context.login.AuthFactor.PASSWORD

    guard.report_failure("203.0.113.1", "alice", factor)
    guard.report_failure("203.0.113.2", "alice", factor)
    decision = guard.report_failure("203.0.113.3", "alice", factor)

    assert decision.allowed is False
    assert decision.scope == guard_context.login.ThrottleScope.ACCOUNT
    assert guard.evaluate("203.0.113.4", "alice", factor).allowed is False


def test_factor_success_resets_account_but_not_ip_history(guard_context):
    guard = guard_context.login.LoginGuard
    password = guard_context.login.AuthFactor.PASSWORD
    totp = guard_context.login.AuthFactor.TOTP
    ip = "203.0.113.10"

    guard.report_failure(ip, "alice", password)
    guard.report_failure(ip, "alice", password)
    guard.report_success(ip, "alice", password)

    assert guard.evaluate(ip, "alice", password).allowed is True
    assert guard.evaluate(ip, "alice", totp).allowed is True
    with guard_context.Session() as session:
        assert session.get(guard_context.AccountThrottle, ("alice", "password")) is None
        ip_record = session.get(guard_context.TrafficThrottle, ip)
        assert ip_record is not None
        assert ip_record.failed_attempts == 2


def test_password_and_totp_account_counters_are_independent(guard_context):
    guard = guard_context.login.LoginGuard
    password = guard_context.login.AuthFactor.PASSWORD
    totp = guard_context.login.AuthFactor.TOTP

    for index in range(3):
        guard.report_failure(f"198.51.100.{index + 1}", "alice", password)

    assert guard.evaluate("198.51.100.20", "alice", password).allowed is False
    assert guard.evaluate("198.51.100.20", "alice", totp).allowed is True


def test_account_delay_doubles_and_is_capped(guard_context):
    update = guard_context.login.LoginGuard._update_account
    policy = guard_context.policy
    now = 1_700_000_000.0
    record = guard_context.AccountThrottle(
        username="alice",
        factor="password",
        failed_attempts=2,
        last_attempt=now,
    )

    first_lock = update(record, now, policy)
    second_time = now + 31
    second_lock = update(record, second_time, policy)
    third_time = second_time + 61
    third_lock = update(record, third_time, policy)
    capped_time = third_time + 121
    capped_lock = update(record, capped_time, policy)

    assert first_lock == now + 30
    assert second_lock == second_time + 60
    assert third_lock == third_time + 120
    assert capped_lock == capped_time + 120


def test_concurrent_failures_do_not_lose_increments(guard_context):
    guard = guard_context.login.LoginGuard
    factor = guard_context.login.AuthFactor.PASSWORD
    attempt_count = 24

    with ThreadPoolExecutor(max_workers=8) as executor:
        list(
            executor.map(
                lambda _index: guard.report_failure(
                    "192.0.2.50", "parallel-user", factor
                ),
                range(attempt_count),
            )
        )

    with guard_context.Session() as session:
        account = session.get(
            guard_context.AccountThrottle, ("parallel-user", "password")
        )
        pair = session.get(guard_context.LoginThrottle, ("parallel-user", "192.0.2.50"))
        ip_record = session.get(guard_context.TrafficThrottle, "192.0.2.50")
        assert account.failed_attempts == attempt_count
        assert pair.failed_attempts == attempt_count
        assert ip_record.failed_attempts == attempt_count


def test_cleanup_removes_only_stale_unlocked_records(guard_context):
    old = guard_context.login.time.time() - 2 * 86400
    with guard_context.Session.begin() as session:
        session.add(
            guard_context.AccountThrottle(
                username="stale",
                factor="password",
                failed_attempts=1,
                last_attempt=old,
            )
        )

    result = guard_context.login.purge_expired_auth_throttle_records(
        guard_context.policy
    )

    with guard_context.Session() as session:
        assert session.get(guard_context.AccountThrottle, ("stale", "password")) is None
    assert result.account_records == 1
    assert result.login_records == 0
    assert result.traffic_records == 0


def test_scheduled_and_expired_subnet_rules(guard_context, monkeypatch):
    guard = guard_context.login.LoginGuard
    now = 1_700_000_000.0
    with guard_context.Session.begin() as session:
        session.add_all(
            [
                guard_context.BannedSubnet(
                    subnet="192.0.2.0/24",
                    created_at=now,
                    starts_at=now + 10,
                ),
                guard_context.BannedSubnet(
                    subnet="2001:db8::/32",
                    created_at=now,
                    starts_at=now - 20,
                    expires_at=now + 10,
                ),
            ]
        )
    guard.reload_networks()
    monkeypatch.setattr(guard_context.login.time, "time", lambda: now)

    assert guard.evaluate_subnet_access("192.0.2.10").allowed is True
    assert guard.evaluate_subnet_access("2001:db8::10").allowed is False

    monkeypatch.setattr(guard_context.login.time, "time", lambda: now + 10)
    assert guard.evaluate_subnet_access("192.0.2.10").allowed is False
    assert guard.evaluate_subnet_access("2001:db8::10").allowed is True


@pytest.mark.parametrize("address", ["", "not-an-ip"])
def test_invalid_address_is_not_blocked_by_subnet_rules(guard_context, address):
    decision = guard_context.login.LoginGuard.evaluate_subnet_access(address)

    assert decision.allowed is True


def test_permanent_access_compatibility_method_was_removed(guard_context):
    assert not hasattr(guard_context.login.LoginGuard, "evaluate_permanent_access")


def test_lockout_invalidation_event_clears_local_cache(guard_context):
    guard = guard_context.login.LoginGuard
    key = guard_context.TrafficThrottle.make_cache_key("192.0.2.25")
    cache = guard_context.login.ProviderManager().caching
    cache.set(guard._cache_key(key), 1_800_000_000.0, ttl=600)

    guard.handle_event('{"type":"invalidate_lockouts","keys":[["ip","192.0.2.25"]]}')

    assert cache.get(guard._cache_key(key)) is None
