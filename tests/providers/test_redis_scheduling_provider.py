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


class _FakeThread:
    def __init__(self, alive=True):
        self.alive = alive

    def is_alive(self):
        return self.alive

    def join(self, timeout=None):
        pass


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
        self.workers = [_FakeThread() for _ in range(self.worker_threads)]
        self.consumers = {next(iter(self.queues)): _FakeThread()}

    def stop(self, timeout):
        self.stop_timeouts.append(timeout)
        for thread in (*self.workers, *self.consumers.values()):
            if isinstance(thread, _FakeThread):
                thread.alive = False


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
    provider._policy = SchedulingPolicy(redis_namespace="test-cluster")
    provider._redis_config = {}
    provider._notify_channel = "cfms:test-cluster:scheduling:changed"
    provider._leader_key = "cfms:test-cluster:scheduling:leader"
    provider._broker_namespace = "cfms:test-cluster:scheduling:dramatiq"
    provider._queue_name = "cfms-test-cluster-scheduled-tasks"
    provider._client = client or _FakeRedis()
    provider._broker = None
    provider._actor = None
    provider._worker = None
    provider._scheduler_thread = None
    provider._stop = threading.Event()
    provider._registry = ScheduledTaskRegistry()
    provider._generation = 1
    provider._redis_error = None
    provider._reconciliation_error = None
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

    def coordinator(_registry, _generation, stop):
        coordinator_started.set()
        stop.wait()

    _FakeWorker.instances.clear()
    monkeypatch.setattr(scheduling_redis, "Worker", _FakeWorker)
    monkeypatch.setattr(
        scheduling_redis,
        "ensure_runtime_state",
        lambda _mode, _namespace: 7,
    )
    monkeypatch.setattr(
        scheduling_redis, "synchronize_system_schedules", lambda _registry: None
    )
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
    assert worker.queues == {"cfms-test-cluster-scheduled-tasks"}
    assert worker.worker_threads == provider._policy.worker_threads
    assert provider.status().available is True

    provider.shutdown()
    provider.shutdown()

    assert len(worker.stop_timeouts) == 1
    assert broker.closed == 1
    assert provider._client.closed == 1
    assert provider.status().detail == "not_running"


@pytest.mark.parametrize(
    "failure",
    ("coordinator", "consumer", "worker_pool", "partial_worker", "worker_count"),
)
def test_redis_provider_requires_complete_runtime_for_health(failure):
    provider = _provider()
    provider._started = True
    provider._scheduler_thread = _FakeThread()
    worker = _FakeWorker(
        _FakeBroker(),
        queues={provider._queue_name},
        worker_threads=provider._policy.worker_threads,
    )
    worker.start()
    provider._worker = worker

    if failure == "coordinator":
        provider._scheduler_thread.alive = False
    elif failure == "consumer":
        next(iter(worker.consumers.values())).alive = False
    elif failure == "worker_pool":
        for thread in worker.workers:
            thread.alive = False
    elif failure == "partial_worker":
        worker.workers[0].alive = False
    else:
        worker.workers.pop()

    status = provider.status()

    assert status.available is False
    assert status.detail == "not_running"


def test_redis_provider_rejects_restart_until_previous_run_exits(monkeypatch):
    release_run = threading.Event()
    first_coordinator_started = threading.Event()
    second_coordinator_started = threading.Event()
    coordinator_stops = []
    coordinator_lock = threading.Lock()
    brokers = []

    class BlockingWorker(_FakeWorker):
        def start(self):
            self.started += 1
            thread = threading.Thread(target=lambda: release_run.wait(5), daemon=True)
            self.workers = [thread]
            self.consumers = {next(iter(self.queues)): _FakeThread()}
            thread.start()

        def stop(self, timeout):
            self.stop_timeouts.append(timeout)
            for thread in self.workers:
                thread.join(timeout=timeout / 1000)
            for consumer in self.consumers.values():
                consumer.alive = False

    provider = _provider()
    provider._policy = SchedulingPolicy(
        redis_namespace="test-cluster",
        shutdown_grace_seconds=1,
    )

    def ensure_actor(registry):
        broker = _FakeBroker()
        brokers.append(broker)
        provider._registry = registry
        provider._broker = broker
        provider._actor = object()
        return provider._actor

    def coordinator(_registry, _generation, stop):
        with coordinator_lock:
            coordinator_stops.append(stop)
            run_number = len(coordinator_stops)
        if run_number == 1:
            first_coordinator_started.set()
            stop.wait()
            assert release_run.wait(5)
        else:
            second_coordinator_started.set()
            stop.wait()

    monkeypatch.setattr(scheduling_redis, "Worker", BlockingWorker)
    monkeypatch.setattr(
        scheduling_redis,
        "ensure_runtime_state",
        lambda _mode, _namespace: 7,
    )
    monkeypatch.setattr(provider, "_ensure_actor", ensure_actor)
    monkeypatch.setattr(provider, "_scheduler_loop", coordinator)
    monkeypatch.setattr(provider, "_create_client", lambda: _FakeRedis())
    registry = ScheduledTaskRegistry()

    provider.start(registry)
    assert first_coordinator_started.wait(1)

    provider.shutdown()

    status = provider.status()
    assert status.available is False
    assert status.detail == "stopping"
    with pytest.raises(
        RuntimeError,
        match="previous run is still stopping",
    ):
        provider.start(registry)
    assert coordinator_stops[0].is_set()

    release_run.set()
    provider.shutdown()
    provider.start(registry)
    assert second_coordinator_started.wait(1)
    assert coordinator_stops[0] is not coordinator_stops[1]
    assert coordinator_stops[0].is_set()
    assert not coordinator_stops[1].is_set()

    provider.shutdown()
    assert all(broker.closed == 1 for broker in brokers)


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
        lambda _mode, _namespace: (_ for _ in ()).throw(
            RuntimeError("database unavailable")
        ),
    )

    with pytest.raises(RuntimeError, match="database unavailable"):
        provider.start(ScheduledTaskRegistry())

    assert provider._started is False
    assert provider._worker is None
    assert provider._scheduler_thread is None
    provider.shutdown()


def test_redis_provider_fails_startup_before_runtime_for_invalid_definition(
    monkeypatch,
):
    provider = _provider()
    monkeypatch.setattr(
        scheduling_redis,
        "ensure_runtime_state",
        lambda _mode, _namespace: 7,
    )
    monkeypatch.setattr(
        scheduling_redis,
        "synchronize_system_schedules",
        lambda _registry: (_ for _ in ()).throw(ValueError("invalid definition")),
    )

    with pytest.raises(ValueError, match="invalid definition"):
        provider.start(ScheduledTaskRegistry())

    assert provider._started is False
    assert provider._worker is None
    assert provider._scheduler_thread is None


def test_redis_notification_failure_is_recorded_but_not_raised():
    client = _FakeRedis()
    provider = _provider(client)
    provider.notify_schedule_change()
    assert client.messages == [(provider._notify_channel, "1")]

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

    provider._scheduler_loop(registry, 11, provider._stop)

    assert len(synchronized) == 2
    assert [generation for generation, _policy in enqueued] == [11, 11]
    assert dispatched == [11, 11]
    owner_token = client.set_calls[0][1]
    assert client.eval_calls[0][0] == scheduling_redis._RENEW_LEASE
    assert client.eval_calls[0][3] == owner_token
    assert client.eval_calls[-1][0] == scheduling_redis._RELEASE_LEASE
    assert client.eval_calls[-1][3] == owner_token
    assert {call[2] for call in client.eval_calls} == {provider._leader_key}
    assert client.set_calls[0][0] == provider._leader_key
    assert pubsub.closed == 1


def test_reconciliation_failure_does_not_block_redis_dispatch(monkeypatch):
    provider = _provider()
    pubsub = _FakePubSub(on_message=provider._stop.set)
    provider._client = _CoordinatorRedis([pubsub])
    enqueued = []
    dispatched = []
    monkeypatch.setattr(
        scheduling_redis,
        "synchronize_system_schedules",
        lambda _registry: (_ for _ in ()).throw(ValueError("invalid definition")),
    )
    monkeypatch.setattr(
        scheduling_redis,
        "enqueue_due_schedules",
        lambda generation, policy: enqueued.append((generation, policy)),
    )
    monkeypatch.setattr(
        provider, "_dispatch_pending", lambda generation: dispatched.append(generation)
    )

    provider._scheduler_loop(ScheduledTaskRegistry(), 11, provider._stop)

    assert enqueued == [(11, provider._policy)]
    assert dispatched == [11]
    assert provider._reconciliation_error == "ValueError"


def test_redis_resources_are_scoped_to_the_deployment_namespace(monkeypatch):
    monkeypatch.setattr(
        RedisSchedulingProvider,
        "_create_client",
        lambda _provider: _FakeRedis(),
    )

    first = RedisSchedulingProvider(
        {"host": "localhost"},
        SchedulingPolicy(redis_namespace="first"),
    )
    second = RedisSchedulingProvider(
        {"host": "localhost"},
        SchedulingPolicy(redis_namespace="second"),
    )

    assert first._notify_channel == "cfms:first:scheduling:changed"
    assert first._leader_key == "cfms:first:scheduling:leader"
    assert first._broker_namespace == "cfms:first:scheduling:dramatiq"
    assert first._queue_name == "cfms-first-scheduled-tasks"
    assert second._notify_channel != first._notify_channel
    assert second._leader_key != first._leader_key
    assert second._broker_namespace != first._broker_namespace
    assert second._queue_name != first._queue_name


def test_dramatiq_broker_and_actor_use_namespaced_resources(monkeypatch):
    provider = _provider()
    captured = {}
    broker = _FakeBroker()

    def create_broker(**kwargs):
        captured["broker"] = kwargs
        return broker

    def create_actor(**kwargs):
        captured["actor"] = kwargs
        return lambda function: function

    monkeypatch.setattr(scheduling_redis, "RedisBroker", create_broker)
    monkeypatch.setattr(scheduling_redis.dramatiq, "actor", create_actor)

    provider._ensure_actor(ScheduledTaskRegistry())

    assert captured["broker"]["namespace"] == provider._broker_namespace
    assert captured["actor"]["queue_name"] == provider._queue_name


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

    provider._scheduler_loop(ScheduledTaskRegistry(), 1, provider._stop)

    assert failed_pubsub.closed == 1
    assert recovered_pubsub.closed == 1
    assert provider._redis_error is None


def test_leader_scripts_compare_the_unique_owner_token():
    assert "get', KEYS[1]" in scheduling_redis._RENEW_LEASE
    assert "ARGV[1]" in scheduling_redis._RENEW_LEASE
    assert "pexpire" in scheduling_redis._RENEW_LEASE
    assert "del" in scheduling_redis._RELEASE_LEASE
