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
        self.closed = 0

    def ping(self):
        if self.error is not None:
            raise self.error
        return True

    def publish(self, channel, message):
        if self.error is not None:
            raise self.error
        self.messages.append((channel, message))

    def close(self):
        self.closed += 1


class _FakeBroker:
    def __init__(self):
        self.closed = 0

    def close(self):
        self.closed += 1


class _FakeWorker:
    instances = []

    def __init__(self, broker, *, queues, worker_threads):
        self.broker = broker
        self.queues = queues
        self.worker_threads = worker_threads
        self.workers = []
        self.consumers = {}
        self.started = 0
        self.stop_timeouts = []
        self.instances.append(self)

    def start(self):
        self.started += 1

    def stop(self, timeout):
        self.stop_timeouts.append(timeout)


class _FakePubSub:
    def __init__(self, *, subscribe_error=None, on_message=None):
        self.subscribe_error = subscribe_error
        self.on_message = on_message
        self.closed = 0

    def subscribe(self, _channel):
        if self.subscribe_error is not None:
            raise self.subscribe_error

    def get_message(self, *, timeout):
        assert timeout > 0
        if self.on_message is not None:
            self.on_message()
        return None

    def close(self):
        self.closed += 1


class _CoordinatorRedis(_FakeRedis):
    def __init__(self, pubsubs):
        super().__init__()
        self.pubsubs = list(pubsubs)
        self.set_calls = []
        self.eval_calls = []

    def pubsub(self, *, ignore_subscribe_messages):
        assert ignore_subscribe_messages is True
        return self.pubsubs.pop(0)

    def set(self, key, token, *, nx, px):
        self.set_calls.append((key, token, nx, px))
        return True

    def eval(self, script, key_count, key, token, *args):
        self.eval_calls.append((script, key_count, key, token, *args))
        return 1


def _provider(client=None):
    provider = RedisSchedulingProvider.__new__(RedisSchedulingProvider)
    provider._policy = SchedulingPolicy()
    provider._redis_config = {}
    provider._client = client or _FakeRedis()
    provider._broker = None
    provider._actor = None
    provider._worker = None
    provider._scheduler_thread = None
    provider._stop = threading.Event()
    provider._registry = ScheduledTaskRegistry()
    provider._generation = 1
    provider._redis_error = None
    provider._runtime_error = None
    provider._started = False
    provider._closed = False
    provider._state_lock = threading.Lock()
    return provider


def _prepare_embedded_runtime(monkeypatch, provider):
    broker = _FakeBroker()
    coordinator_started = threading.Event()

    def ensure_actor(registry):
        provider._registry = registry
        provider._broker = broker
        provider._actor = object()
        return provider._actor

    def coordinator(_registry, _generation):
        coordinator_started.set()
        provider._stop.wait()

    _FakeWorker.instances.clear()
    monkeypatch.setattr(scheduling_redis, "Worker", _FakeWorker)
    monkeypatch.setattr(scheduling_redis, "ensure_runtime_state", lambda _mode: 7)
    monkeypatch.setattr(provider, "_ensure_actor", ensure_actor)
    monkeypatch.setattr(provider, "_scheduler_loop", coordinator)
    return broker, coordinator_started


def test_redis_provider_embeds_coordinator_and_worker_pool(monkeypatch):
    provider = _provider()
    broker, coordinator_started = _prepare_embedded_runtime(monkeypatch, provider)
    registry = ScheduledTaskRegistry()

    provider.start(registry)
    assert coordinator_started.wait(1)
    provider.start(registry)

    assert provider._generation == 7
    assert len(_FakeWorker.instances) == 1
    worker = _FakeWorker.instances[0]
    assert worker.started == 1
    assert worker.queues == {"cfms-scheduled-tasks"}
    assert worker.worker_threads == provider._policy.worker_threads
    assert provider.status().available is True

    provider.shutdown()
    provider.shutdown()

    assert len(worker.stop_timeouts) == 1
    assert broker.closed == 1
    assert provider._client.closed == 1
    assert provider.status().detail == "not_running"


def test_redis_provider_reports_degraded_without_stopping_server(monkeypatch):
    client = _FakeRedis()
    client.error = redis.ConnectionError("unavailable")
    provider = _provider(client)
    _, coordinator_started = _prepare_embedded_runtime(monkeypatch, provider)

    provider.start(ScheduledTaskRegistry())
    assert coordinator_started.wait(1)

    status = provider.status()
    assert status.available is False
    assert status.detail == "ConnectionError"

    client.error = None
    assert provider.status().available is True
    provider.shutdown()


def test_redis_provider_propagates_database_runtime_initialization_failure(
    monkeypatch,
):
    provider = _provider()
    monkeypatch.setattr(
        scheduling_redis,
        "ensure_runtime_state",
        lambda _mode: (_ for _ in ()).throw(RuntimeError("database unavailable")),
    )

    with pytest.raises(RuntimeError, match="database unavailable"):
        provider.start(ScheduledTaskRegistry())

    assert provider._started is False
    assert provider._worker is None
    assert provider._scheduler_thread is None
    provider.shutdown()


def test_redis_notification_failure_is_recorded_but_not_raised():
    client = _FakeRedis()
    provider = _provider(client)
    provider.notify_schedule_change()
    assert client.messages == [(scheduling_redis._NOTIFY_CHANNEL, "1")]

    client.error = redis.ConnectionError("unavailable")
    provider.notify_schedule_change()
    assert provider._redis_error == "ConnectionError"


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


def test_coordinator_renews_and_releases_leadership_with_one_owner_token(
    monkeypatch,
):
    provider = _provider()
    iteration_count = 0

    def after_iteration():
        nonlocal iteration_count
        iteration_count += 1
        if iteration_count == 2:
            provider._stop.set()

    pubsub = _FakePubSub(on_message=after_iteration)
    client = _CoordinatorRedis([pubsub])
    provider._client = client
    synchronized = []
    enqueued = []
    dispatched = []
    monkeypatch.setattr(
        scheduling_redis,
        "synchronize_system_schedules",
        lambda registry: synchronized.append(registry),
    )
    monkeypatch.setattr(
        scheduling_redis,
        "enqueue_due_schedules",
        lambda generation, policy: enqueued.append((generation, policy)),
    )
    monkeypatch.setattr(
        provider,
        "_dispatch_pending",
        lambda generation: dispatched.append(generation),
    )
    registry = ScheduledTaskRegistry()

    provider._scheduler_loop(registry, 11)

    assert len(synchronized) == 2
    assert [generation for generation, _policy in enqueued] == [11, 11]
    assert dispatched == [11, 11]
    owner_token = client.set_calls[0][1]
    assert client.eval_calls[0][0] == scheduling_redis._RENEW_LEASE
    assert client.eval_calls[0][3] == owner_token
    assert client.eval_calls[-1][0] == scheduling_redis._RELEASE_LEASE
    assert client.eval_calls[-1][3] == owner_token
    assert pubsub.closed == 1


def test_coordinator_retries_after_redis_recovers(monkeypatch):
    provider = _provider()
    provider._policy = SchedulingPolicy(poll_interval_seconds=0.01)
    failed_pubsub = _FakePubSub(subscribe_error=redis.ConnectionError("unavailable"))
    recovered_pubsub = _FakePubSub(on_message=provider._stop.set)
    client = _CoordinatorRedis([failed_pubsub, recovered_pubsub])
    provider._client = client
    monkeypatch.setattr(
        scheduling_redis, "synchronize_system_schedules", lambda _registry: None
    )
    monkeypatch.setattr(
        scheduling_redis,
        "enqueue_due_schedules",
        lambda _generation, _policy: None,
    )
    monkeypatch.setattr(provider, "_dispatch_pending", lambda _generation: None)

    provider._scheduler_loop(ScheduledTaskRegistry(), 1)

    assert failed_pubsub.closed == 1
    assert recovered_pubsub.closed == 1
    assert provider._redis_error is None


def test_leader_scripts_compare_the_unique_owner_token():
    assert "get', KEYS[1]" in scheduling_redis._RENEW_LEASE
    assert "ARGV[1]" in scheduling_redis._RENEW_LEASE
    assert "pexpire" in scheduling_redis._RENEW_LEASE
    assert "del" in scheduling_redis._RELEASE_LEASE
