import secrets
import threading
import time
from collections.abc import Mapping
from typing import Any

import dramatiq
import redis
from dramatiq.brokers.redis import RedisBroker
from dramatiq.errors import Retry
from dramatiq.worker import Worker
from loguru import logger

from include.config.validation import SchedulingPolicy
from include.providers.base import SchedulingProvider, SchedulingProviderStatus
from include.scheduling.engine import (
    claim_execution_by_id,
    enqueue_due_schedules,
    ensure_runtime_state,
    execution_delivery_state,
    mark_dispatched,
    pending_dispatches,
    run_claimed_execution,
    synchronize_system_schedules,
)
from include.scheduling.registry import ScheduledTaskRegistry

_NOTIFY_CHANNEL = "cfms:scheduling:changed"
_LEADER_KEY = "cfms:scheduling:leader"
_RENEW_LEASE = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('pexpire', KEYS[1], ARGV[2])
end
return 0
"""
_RELEASE_LEASE = """
if redis.call('get', KEYS[1]) == ARGV[1] then
    return redis.call('del', KEYS[1])
end
return 0
"""


class RedisSchedulingProvider(SchedulingProvider):
    _broker: RedisBroker | None
    _registry: ScheduledTaskRegistry
    _generation: int

    def __init__(self, redis_config: Mapping[str, Any], policy: SchedulingPolicy):
        self._policy = policy
        self._redis_config = {
            "host": redis_config["host"],
            "port": redis_config.get("port", 6379),
            "password": redis_config.get("password", "") or None,
            "db": redis_config.get("db", 0),
        }
        self._client = self._create_client()
        self._broker = None
        self._actor = None
        self._worker: Worker | None = None
        self._scheduler_thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._redis_error: str | None = None
        self._runtime_error: str | None = None
        self._started = False
        self._closed = False
        self._state_lock = threading.Lock()

    @classmethod
    def from_config(cls, config: Mapping[str, Any]):
        return cls(config["redis"], SchedulingPolicy.from_config(config))

    def start(self, registry: ScheduledTaskRegistry) -> None:
        with self._state_lock:
            if self._started:
                return
            if self._closed:
                self._client = self._create_client()
                self._closed = False

            self._registry = registry
            self._generation = ensure_runtime_state("redis")
            self._stop.clear()
            self._ensure_actor(registry)
            assert self._broker is not None
            worker = Worker(
                self._broker,
                queues={"cfms-scheduled-tasks"},
                worker_threads=self._policy.worker_threads,
            )
            scheduler_thread = threading.Thread(
                target=self._scheduler_loop,
                args=(registry, self._generation),
                name="schedule-redis-coordinator",
                daemon=True,
            )
            self._worker = worker
            self._scheduler_thread = scheduler_thread
            try:
                worker.start()
                scheduler_thread.start()
            except Exception:
                self._stop.set()
                self._worker = None
                self._scheduler_thread = None
                self._actor = None
                broker = self._broker
                self._broker = None
                if worker.workers or worker.consumers:
                    worker.stop(timeout=self._policy.shutdown_grace_seconds * 1000)
                broker.close()
                raise
            self._started = True

        try:
            self._ping()
        except redis.RedisError:
            logger.warning("Starting with the Redis scheduling provider degraded")

    def shutdown(self) -> None:
        with self._state_lock:
            if self._closed:
                return
            self._closed = True
            self._started = False
            self._stop.set()
            scheduler_thread = self._scheduler_thread
            worker = self._worker
            broker = self._broker
            self._scheduler_thread = None
            self._worker = None
            self._broker = None
            self._actor = None

        deadline = time.monotonic() + self._policy.shutdown_grace_seconds
        try:
            if scheduler_thread is not None:
                scheduler_thread.join(timeout=max(0.0, deadline - time.monotonic()))
            if worker is not None:
                worker.stop(timeout=max(0, int((deadline - time.monotonic()) * 1000)))
        finally:
            try:
                if broker is not None:
                    broker.close()
            finally:
                self._client.close()

    def notify_schedule_change(self) -> None:
        try:
            self._client.publish(_NOTIFY_CHANNEL, "1")
            with self._state_lock:
                self._redis_error = None
        except redis.RedisError as exc:
            with self._state_lock:
                self._redis_error = type(exc).__name__
            logger.warning("Failed to notify Redis scheduler of a schedule change")

    def status(self) -> SchedulingProviderStatus:
        with self._state_lock:
            started = self._started
            scheduler_thread = self._scheduler_thread
        if not started or scheduler_thread is None or not scheduler_thread.is_alive():
            return SchedulingProviderStatus(
                available=False,
                mode="redis",
                detail="not_running",
            )
        try:
            self._ping()
        except redis.RedisError:
            pass
        with self._state_lock:
            detail = self._runtime_error or self._redis_error
        return SchedulingProviderStatus(
            available=detail is None,
            mode="redis",
            detail=detail,
        )

    def _create_client(self):
        return redis.Redis(
            **self._redis_config,
            decode_responses=True,
            socket_connect_timeout=2,
            socket_timeout=2,
            health_check_interval=30,
        )

    def _ping(self) -> None:
        try:
            self._client.ping()
        except redis.RedisError as exc:
            with self._state_lock:
                self._redis_error = type(exc).__name__
            raise
        with self._state_lock:
            self._redis_error = None

    def _ensure_actor(self, registry: ScheduledTaskRegistry):
        if self._actor is not None:
            return self._actor
        self._registry = registry
        self._broker = RedisBroker(
            **self._redis_config,
            namespace="cfms-scheduling",
        )
        self._actor = dramatiq.actor(
            actor_name="cfms_scheduled_task",
            queue_name="cfms-scheduled-tasks",
            broker=self._broker,
            max_retries=100,
            min_backoff=1000,
            max_backoff=30000,
        )(self._consume_execution)
        return self._actor

    def _consume_execution(self, execution_id: str, generation: int) -> None:
        """Consume one delivery, retrying only work that may become claimable."""
        owner = secrets.token_hex(32)
        claim = claim_execution_by_id(
            execution_id,
            generation,
            owner,
            self._policy,
        )
        if claim is None:
            state = execution_delivery_state(execution_id, generation)
            if state in {"busy", "ready"}:
                raise Retry(
                    "Execution is not claimable yet",
                    delay=max(1000, int(self._policy.poll_interval_seconds * 1000)),
                )
            return
        run_claimed_execution(
            claim,
            generation,
            self._registry,
            self._policy,
        )

    def _dispatch_pending(self, generation: int) -> None:
        assert self._actor is not None
        for execution_id in pending_dispatches(
            generation, self._policy.claim_batch_size
        ):
            # Send before marking so a broker failure leaves the execution visible.
            # A crash between these calls can duplicate delivery, which the database
            # lease and deterministic execution ID are designed to tolerate.
            self._actor.send(execution_id, generation)
            mark_dispatched(execution_id, generation)

    def _scheduler_loop(self, registry: ScheduledTaskRegistry, generation: int) -> None:
        """Run this Provider's Redis-elected scheduler candidate.

        Redis coordinates leadership and wake-ups, while the application database
        remains authoritative for schedules, executions, and dispatch state.
        """
        token = secrets.token_hex(32)
        lease_ttl_ms = max(10_000, int(self._policy.poll_interval_seconds * 5_000))
        leader = False
        pubsub = None
        try:
            while not self._stop.is_set():
                try:
                    if pubsub is None:
                        pubsub = self._client.pubsub(ignore_subscribe_messages=True)
                        pubsub.subscribe(_NOTIFY_CHANNEL)
                    # The random token makes renewal conditional: a candidate whose
                    # lease expired cannot renew or release its successor's lease.
                    if leader:
                        leader = bool(
                            self._client.eval(
                                _RENEW_LEASE,
                                1,
                                _LEADER_KEY,
                                token,
                                lease_ttl_ms,
                            )
                        )
                    else:
                        leader = bool(
                            self._client.set(
                                _LEADER_KEY,
                                token,
                                nx=True,
                                px=lease_ttl_ms,
                            )
                        )
                    if leader:
                        synchronize_system_schedules(registry)
                        enqueue_due_schedules(generation, self._policy)
                        self._dispatch_pending(generation)
                    with self._state_lock:
                        self._redis_error = None
                        self._runtime_error = None
                    pubsub.get_message(
                        timeout=min(self._policy.poll_interval_seconds, 1.0)
                    )
                except Exception as exc:  # noqa: BLE001 - provider degrades and retries.
                    leader = False
                    with self._state_lock:
                        if isinstance(exc, redis.RedisError):
                            self._redis_error = type(exc).__name__
                        else:
                            self._runtime_error = type(exc).__name__
                    logger.exception("Redis scheduling coordinator iteration failed")
                    if pubsub is not None:
                        pubsub.close()
                        pubsub = None
                    self._stop.wait(self._policy.poll_interval_seconds)
        finally:
            if leader:
                try:
                    self._client.eval(_RELEASE_LEASE, 1, _LEADER_KEY, token)
                except redis.RedisError:
                    logger.exception("Failed to release Redis scheduler leadership")
            if pubsub is not None:
                pubsub.close()
