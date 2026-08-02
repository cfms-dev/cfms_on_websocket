import pytest

pytest.importorskip("redis")

from include.providers.base import RateLimitCharge
from include.providers.rate_limits.redis import (
    _CONSUME_SCRIPT,
    RedisRateLimitProvider,
)


def test_redis_rate_limit_provider_uses_one_atomic_multi_bucket_script():
    calls = []

    class FakeRedis:
        def eval(self, *args):
            calls.append(args)
            return [2, 7]

    provider = RedisRateLimitProvider.__new__(RedisRateLimitProvider)
    provider._client = FakeRedis()
    charges = (
        RateLimitCharge("account-key", "account", 20, 10, 60, 2),
        RateLimitCharge("ip-key", "ip", 100, 50, 60, 5),
    )

    decision = provider.consume(charges, retention_seconds=600)

    assert calls == [
        (
            _CONSUME_SCRIPT,
            2,
            "account-key",
            "ip-key",
            "",
            20,
            10,
            60,
            2,
            600,
            100,
            50,
            60,
            5,
            600,
        )
    ]
    assert not decision.allowed
    assert decision.scope == "ip"
    assert decision.effective_limit == 10
    assert decision.retry_after_seconds == 7
    assert "redis.call('TIME')" in _CONSUME_SCRIPT
    assert "redis.call('HMGET'" in _CONSUME_SCRIPT
    assert "redis.call('HSET'" in _CONSUME_SCRIPT
    assert "redis.call('EXPIRE'" in _CONSUME_SCRIPT
