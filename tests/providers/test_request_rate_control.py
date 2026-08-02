import queue
import threading

from include.providers.base import RateLimitCharge
from include.providers.rate_limits.memory import MemoryRateLimitProvider


def _charge(
    key: str = "account:alice",
    scope: str = "account",
    *,
    capacity: int = 2,
    refill_tokens: int = 2,
    refill_period_seconds: int = 10,
    cost: int = 1,
) -> RateLimitCharge:
    return RateLimitCharge(
        key=key,
        scope=scope,
        capacity=capacity,
        refill_tokens=refill_tokens,
        refill_period_seconds=refill_period_seconds,
        cost=cost,
    )


def test_memory_rate_limit_provider_refills_and_reports_retry_after():
    provider = MemoryRateLimitProvider()
    charge = _charge()

    assert provider.consume((charge,), retention_seconds=60, now=100.0).allowed
    assert provider.consume((charge,), retention_seconds=60, now=100.0).allowed

    denied = provider.consume((charge,), retention_seconds=60, now=100.0)
    assert not denied.allowed
    assert denied.scope == "account"
    assert denied.effective_limit == 2
    assert denied.retry_after_seconds == 5

    assert provider.consume((charge,), retention_seconds=60, now=105.0).allowed


def test_memory_rate_limit_provider_returns_slowest_limiting_scope():
    provider = MemoryRateLimitProvider()
    account = _charge(capacity=1, refill_tokens=1, refill_period_seconds=10)
    ip = _charge(
        "ip:203.0.113.1",
        "ip",
        capacity=1,
        refill_tokens=1,
        refill_period_seconds=30,
    )

    assert provider.consume((account, ip), retention_seconds=60, now=100.0).allowed
    denied = provider.consume((account, ip), retention_seconds=60, now=100.0)

    assert not denied.allowed
    assert denied.scope == "ip"
    assert denied.retry_after_seconds == 30


def test_memory_rate_limit_provider_enforces_capacity_concurrently():
    provider = MemoryRateLimitProvider()
    charge = _charge(capacity=5, refill_tokens=5)
    barrier = threading.Barrier(20)
    outcomes: queue.SimpleQueue[bool] = queue.SimpleQueue()

    def consume() -> None:
        barrier.wait()
        decision = provider.consume((charge,), retention_seconds=60, now=100.0)
        outcomes.put(decision.allowed)

    threads = [threading.Thread(target=consume) for _ in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=2)
        assert not thread.is_alive()

    assert sum(outcomes.get() for _ in threads) == 5


def test_memory_rate_limit_provider_expires_stale_state():
    provider = MemoryRateLimitProvider(max_entries=1)
    charge = _charge(capacity=1, refill_tokens=1, refill_period_seconds=100)
    assert provider.consume((charge,), retention_seconds=10, now=100.0).allowed
    assert not provider.consume((charge,), retention_seconds=10, now=100.0).allowed

    assert provider.consume((charge,), retention_seconds=10, now=111.0).allowed
