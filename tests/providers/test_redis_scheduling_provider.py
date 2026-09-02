import threading

import pytest
import redis
from dramatiq.errors import Retry

from include.config.validation import SchedulingPolicy
from include.providers.scheduling import redis as scheduling_redis
from include.providers.scheduling.redis import RedisSchedulingProvider
from include.scheduling.registry import ScheduledTaskRegistry


class _FakeRedis:
    def __init__(self):
        self.error = None
        self.messages = []

    def ping(self):
        if self.error is not None:
            raise self.error
        return True

    def publish(self, channel, message):
        if self.error is not None:
            raise self.error
        self.messages.append((channel, message))

    def close(self):
        pass


def _provider(client=None):
    provider = RedisSchedulingProvider.__new__(RedisSchedulingProvider)
    provider._policy = SchedulingPolicy()
    provider._redis_config = {}
    provider._client = client or _FakeRedis()
    provider._broker = None
    provider._actor = None
    provider._registry = ScheduledTaskRegistry()
    provider._generation = 1
    provider._last_error = None
    provider._state_lock = threading.Lock()
    return provider


def test_redis_provider_reports_degraded_without_stopping_server(monkeypatch):
    client = _FakeRedis()
    client.error = redis.ConnectionError("unavailable")
    provider = _provider(client)
    monkeypatch.setattr(scheduling_redis, "ensure_runtime_state", lambda _mode: 1)

    provider.start(ScheduledTaskRegistry())

    status = provider.status()
    assert status.available is False
    assert status.detail == "ConnectionError"


def test_redis_notification_failure_is_recorded_but_not_raised():
    client = _FakeRedis()
    provider = _provider(client)
    provider.notify_schedule_change()
    assert client.messages == [(scheduling_redis._NOTIFY_CHANNEL, "1")]

    client.error = redis.ConnectionError("unavailable")
    provider.notify_schedule_change()
    assert provider._last_error == "ConnectionError"


def test_busy_execution_requests_delayed_redelivery(monkeypatch):
    provider = _provider()
    monkeypatch.setattr(scheduling_redis, "claim_execution_by_id", lambda *_args: None)
    monkeypatch.setattr(
        scheduling_redis, "execution_delivery_state", lambda *_args: "busy"
    )

    with pytest.raises(Retry) as error:
        provider._consume_execution("execution", 1)

    assert error.value.delay == 1000


def test_stale_duplicate_message_is_acknowledged(monkeypatch):
    provider = _provider()
    monkeypatch.setattr(scheduling_redis, "claim_execution_by_id", lambda *_args: None)
    monkeypatch.setattr(
        scheduling_redis, "execution_delivery_state", lambda *_args: "stale"
    )

    assert provider._consume_execution("execution", 1) is None


def test_leader_scripts_compare_the_unique_owner_token():
    assert "get', KEYS[1]" in scheduling_redis._RENEW_LEASE
    assert "ARGV[1]" in scheduling_redis._RENEW_LEASE
    assert "pexpire" in scheduling_redis._RENEW_LEASE
    assert "del" in scheduling_redis._RELEASE_LEASE
