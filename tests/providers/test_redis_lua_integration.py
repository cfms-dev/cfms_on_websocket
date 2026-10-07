import os
import threading
import time
import uuid
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from contextlib import ExitStack
from functools import partial
from urllib.parse import unquote, urlsplit

import pytest
lazy import redis
lazy from redis.backoff import NoBackoff
lazy from redis.retry import Retry

from include.providers.base import RateLimitCharge, RateLimitDecision
lazy from include.providers.rate_limits.redis import RedisRateLimitProvider
lazy from include.providers.scheduling.redis import _RELEASE_LEASE, _RENEW_LEASE


@pytest.fixture
def redis_integration(monkeypatch):
    url = os.environ.get("CFMS_TEST_REDIS_URL")
    if url is None:
        pytest.skip("set CFMS_TEST_REDIS_URL to enable real Redis behavior tests")

    address = urlsplit(url)
    if (
        address.scheme != "redis"
        or not address.hostname
        or address.username
        or address.query
        or address.fragment
    ):
        pytest.fail("CFMS_TEST_REDIS_URL must use redis://[:password]@host:port/db")
    connection = {
        "host": address.hostname,
        "port": address.port or 6379,
        "password": unquote(address.password or ""),
        "db": int(address.path.removeprefix("/") or "0"),
    }
    monkeypatch.setattr(
        redis,
        "Redis",
        partial(
            redis.Redis,
            socket_connect_timeout=2,
            socket_timeout=2,
            retry=Retry(NoBackoff(), 0),
        ),
    )
    client = redis.Redis(
        **connection,
        decode_responses=True,
    )
    prefix = f"cfms:test-{uuid.uuid4().hex}"
    connected = False
    try:
        client.ping()
        connected = True
        yield connection, client, prefix
    finally:
        try:
            if connected:
                for key in client.scan_iter(match=f"{prefix}:*"):
                    client.delete(key)
        finally:
            client.close()


@pytest.fixture
def redis_rate_limit(redis_integration):
    connection, client, prefix = redis_integration
    provider = RedisRateLimitProvider(**connection)
    try:
        yield provider, client, prefix
    finally:
        provider._client.close()


def _wait_for(predicate: Callable[[], bool], *, timeout_seconds: float = 3) -> None:
    deadline = time.monotonic() + timeout_seconds
    while not predicate():
        assert time.monotonic() < deadline, (
            "Redis state did not reach the expected state"
        )
        time.sleep(0.01)


def test_redis_rate_limit_refill_fractional_retry_and_clock_regression(
    redis_rate_limit,
):
    provider, _client, prefix = redis_rate_limit
    charge = RateLimitCharge(f"{prefix}:account", "account", 2, 2, 10, 1)

    assert provider.consume((charge,), retention_seconds=60, now=100).allowed
    assert provider.consume((charge,), retention_seconds=60, now=100).allowed
    assert provider.consume((charge,), retention_seconds=60, now=100) == (
        RateLimitDecision(False, "account", 2, 5)
    )
    assert provider.consume((charge,), retention_seconds=60, now=102.5) == (
        RateLimitDecision(False, "account", 2, 3)
    )
    assert provider.consume((charge,), retention_seconds=60, now=105).allowed
    assert provider.consume((charge,), retention_seconds=60, now=104) == (
        RateLimitDecision(False, "account", 2, 5)
    )


def test_redis_rate_limit_caps_refilled_and_reconfigured_buckets(redis_rate_limit):
    provider, _client, prefix = redis_rate_limit
    charge = RateLimitCharge(f"{prefix}:account", "account", 2, 2, 10, 1)
    assert provider.consume((charge,), retention_seconds=60, now=100).allowed

    assert provider.consume((charge,), retention_seconds=60, now=1000).allowed
    assert provider.consume((charge,), retention_seconds=60, now=1000).allowed
    assert not provider.consume((charge,), retention_seconds=60, now=1000).allowed

    generous = RateLimitCharge(f"{prefix}:changed", "account", 10, 1, 10, 1)
    assert provider.consume((generous,), retention_seconds=60, now=100).allowed
    restricted = RateLimitCharge(generous.key, "account", 1, 1, 10, 1)
    assert provider.consume((restricted,), retention_seconds=60, now=100).allowed
    assert provider.consume((restricted,), retention_seconds=60, now=100) == (
        RateLimitDecision(False, "account", 1, 10)
    )


@pytest.mark.parametrize(
    ("ip_period", "limiting_scope", "retry_after"),
    [(30, "ip", 30), (10, "account", 10)],
)
def test_redis_rate_limit_selects_the_slowest_scope_and_first_tie(
    redis_rate_limit, ip_period, limiting_scope, retry_after
):
    provider, _client, prefix = redis_rate_limit
    charges = (
        RateLimitCharge(f"{prefix}:account", "account", 1, 1, 10, 1),
        RateLimitCharge(f"{prefix}:ip", "ip", 1, 1, ip_period, 1),
    )

    assert provider.consume(charges, retention_seconds=60, now=100).allowed
    assert provider.consume(charges, retention_seconds=60, now=100) == (
        RateLimitDecision(False, limiting_scope, 1, retry_after)
    )


def test_redis_rate_limit_charges_available_buckets_when_another_scope_denies(
    redis_rate_limit,
):
    provider, _client, prefix = redis_rate_limit
    account = RateLimitCharge(f"{prefix}:account", "account", 1, 1, 10, 1)
    ip = RateLimitCharge(f"{prefix}:ip", "ip", 2, 1, 10, 1)

    assert provider.consume((account, ip), retention_seconds=60, now=100).allowed
    assert provider.consume((account, ip), retention_seconds=60, now=100) == (
        RateLimitDecision(False, "account", 1, 10)
    )
    assert provider.consume((ip,), retention_seconds=60, now=100) == (
        RateLimitDecision(False, "ip", 1, 10)
    )


def test_redis_rate_limit_uses_server_time_when_no_clock_is_supplied(redis_rate_limit):
    provider, client, prefix = redis_rate_limit
    charge = RateLimitCharge(f"{prefix}:account", "account", 1, 1, 10, 1)
    before_seconds, before_microseconds = client.time()

    assert provider.consume((charge,), retention_seconds=60).allowed

    after_seconds, after_microseconds = client.time()
    last_refill = float(client.hget(charge.key, "last_refill_at"))
    assert (
        before_seconds + before_microseconds / 1_000_000
        <= last_refill
        <= after_seconds + after_microseconds / 1_000_000
    )


def test_redis_rate_limit_expires_inactive_state(redis_rate_limit):
    provider, client, prefix = redis_rate_limit
    charge = RateLimitCharge(f"{prefix}:account", "account", 1, 1, 100, 1)

    assert provider.consume((charge,), retention_seconds=1, now=100).allowed
    assert 0 < client.pttl(charge.key) <= 1000
    _wait_for(lambda: client.pttl(charge.key) == -2)

    assert provider.consume((charge,), retention_seconds=1, now=100).allowed


def test_redis_rate_limit_refreshes_retention_after_a_denied_charge(redis_rate_limit):
    provider, client, prefix = redis_rate_limit
    charge = RateLimitCharge(f"{prefix}:account", "account", 1, 1, 100, 1)
    assert provider.consume((charge,), retention_seconds=5, now=100).allowed
    assert client.pexpire(charge.key, 1000)

    assert not provider.consume((charge,), retention_seconds=5, now=100).allowed

    assert 1000 < client.pttl(charge.key) <= 5000


def test_redis_rate_limit_capacity_is_atomic_across_provider_instances(
    redis_integration,
):
    connection, _client, prefix = redis_integration
    charge = RateLimitCharge(f"{prefix}:account", "account", 5, 5, 60, 1)
    barrier = threading.Barrier(20, timeout=5)

    def consume(provider):
        barrier.wait()
        return provider.consume((charge,), retention_seconds=60, now=100)

    with ExitStack() as resources:
        providers = []
        for _ in range(20):
            provider = RedisRateLimitProvider(**connection)
            resources.callback(provider._client.close)
            providers.append(provider)
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = [executor.submit(consume, provider) for provider in providers]
            decisions = [future.result(timeout=5) for future in futures]

    assert sum(decision.allowed for decision in decisions) == 5
    assert [decision for decision in decisions if not decision.allowed] == [
        RateLimitDecision(False, "account", 5, 12)
    ] * 15


def test_redis_rate_limit_propagates_real_script_errors(redis_rate_limit):
    provider, client, prefix = redis_rate_limit
    charge = RateLimitCharge(f"{prefix}:account", "account", 1, 1, 10, 1)
    client.set(charge.key, "wrong-type")

    with pytest.raises(redis.ResponseError, match="WRONGTYPE"):
        provider.consume((charge,), retention_seconds=60, now=100)

    assert client.get(charge.key) == "wrong-type"


def test_redis_scheduler_renews_and_releases_only_the_current_owner(redis_integration):
    _connection, client, prefix = redis_integration
    key = f"{prefix}:scheduling:leader"
    assert client.set(key, "owner-a", nx=True, px=1000)
    previous_ttl = client.pttl(key)

    assert client.eval(_RENEW_LEASE, 1, key, "owner-a", 10_000) == 1

    assert client.get(key) == "owner-a"
    assert previous_ttl < client.pttl(key) <= 10_000
    renewed_ttl = client.pttl(key)

    assert client.eval(_RENEW_LEASE, 1, key, "owner-b", 20_000) == 0
    assert client.eval(_RELEASE_LEASE, 1, key, "owner-b") == 0
    assert client.get(key) == "owner-a"
    assert 0 < client.pttl(key) <= renewed_ttl

    assert client.eval(_RELEASE_LEASE, 1, key, "owner-a") == 1
    assert client.get(key) is None
    assert client.eval(_RENEW_LEASE, 1, key, "owner-a", 10_000) == 0
    assert client.eval(_RELEASE_LEASE, 1, key, "owner-a") == 0


def test_redis_scheduler_expired_owner_cannot_modify_its_successor(redis_integration):
    _connection, client, prefix = redis_integration
    key = f"{prefix}:scheduling:leader"
    assert client.set(key, "owner-a", nx=True, px=150)
    _wait_for(lambda: client.pttl(key) == -2)
    assert client.set(key, "owner-b", nx=True, px=10_000)
    successor_ttl = client.pttl(key)

    assert client.eval(_RENEW_LEASE, 1, key, "owner-a", 20_000) == 0
    assert client.eval(_RELEASE_LEASE, 1, key, "owner-a") == 0

    assert client.get(key) == "owner-b"
    assert 0 < client.pttl(key) <= successor_ttl
    assert client.eval(_RELEASE_LEASE, 1, key, "owner-b") == 1


def test_redis_scheduler_candidates_elect_one_owner_and_protect_its_lease(
    redis_integration,
):
    connection, client, prefix = redis_integration
    key = f"{prefix}:scheduling:leader"
    barrier = threading.Barrier(2, timeout=5)

    def acquire(candidate, owner):
        barrier.wait()
        return owner, candidate.set(key, owner, nx=True, px=10_000)

    with ExitStack() as resources:
        candidates = []
        for _ in range(2):
            candidate = redis.Redis(
                **connection,
                decode_responses=True,
            )
            resources.callback(candidate.close)
            candidates.append(candidate)
        with ThreadPoolExecutor(max_workers=2) as executor:
            futures = [
                executor.submit(acquire, candidate, owner)
                for candidate, owner in zip(
                    candidates, ("owner-a", "owner-b"), strict=True
                )
            ]
            outcomes = [future.result(timeout=5) for future in futures]

    assert sum(bool(acquired) for _owner, acquired in outcomes) == 1
    winner = next(owner for owner, acquired in outcomes if acquired)
    loser = next(owner for owner, acquired in outcomes if not acquired)
    winner_ttl = client.pttl(key)
    assert client.eval(_RENEW_LEASE, 1, key, loser, 20_000) == 0
    assert client.eval(_RELEASE_LEASE, 1, key, loser) == 0
    assert client.get(key) == winner
    assert 0 < client.pttl(key) <= winner_ttl
    assert client.eval(_RELEASE_LEASE, 1, key, winner) == 1
