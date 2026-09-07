import secrets
import threading
import time

from loguru import logger

from include.config.validation import SchedulingPolicy
from include.providers.base import SchedulingProvider, SchedulingProviderStatus
from include.scheduling.engine import (
    cancel_expired_deleted_executions,
    claim_execution,
    enqueue_due_schedules,
    ensure_runtime_state,
    run_claimed_execution,
    synchronize_system_schedules,
)
from include.scheduling.registry import ScheduledTaskRegistry


class LocalSchedulingProvider(SchedulingProvider):
    _registry: ScheduledTaskRegistry
    _generation: int

    def __init__(self, policy: SchedulingPolicy):
        self._policy = policy
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._threads: list[threading.Thread] = []
        self._state_lock = threading.Lock()
        self._scheduler_error: str | None = None
        self._worker_errors: dict[str, str] = {}

    def start(self, registry: ScheduledTaskRegistry) -> None:
        with self._state_lock:
            if self._threads:
                if any(thread.is_alive() for thread in self._threads):
                    if self._stop.is_set():
                        raise RuntimeError(
                            "Cannot restart scheduling provider while the previous "
                            "run is still stopping"
                        )
                    return
                self._threads = []
            generation = ensure_runtime_state("local")
            stop = threading.Event()
            wake = threading.Event()
            scheduler = threading.Thread(
                target=self._scheduler_loop,
                args=(registry, generation, stop, wake),
                name="schedule-local-scheduler",
                daemon=True,
            )
            workers = [
                threading.Thread(
                    target=self._worker_loop,
                    args=(registry, generation, stop, wake),
                    name=f"schedule-local-worker-{index + 1}",
                    daemon=True,
                )
                for index in range(self._policy.worker_threads)
            ]
            self._registry = registry
            self._generation = generation
            self._stop = stop
            self._wake = wake
            self._threads = [scheduler, *workers]
            self._scheduler_error = None
            self._worker_errors.clear()
            for thread in self._threads:
                thread.start()

    def shutdown(self) -> None:
        with self._state_lock:
            threads = tuple(self._threads)
            if not threads:
                return
            stop = self._stop
            wake = self._wake
            stop.set()
            wake.set()
        deadline = time.monotonic() + self._policy.shutdown_grace_seconds
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))
        alive = tuple(thread for thread in threads if thread.is_alive())
        with self._state_lock:
            if tuple(self._threads) == threads and not alive:
                self._threads = []
        if alive:
            logger.warning(
                "Local scheduling shutdown timed out with threads still running: {}",
                ", ".join(thread.name for thread in alive),
            )

    def notify_schedule_change(self) -> None:
        with self._state_lock:
            wake = self._wake
        wake.set()

    def status(self) -> SchedulingProviderStatus:
        with self._state_lock:
            alive = tuple(thread for thread in self._threads if thread.is_alive())
            stopping = bool(alive) and self._stop.is_set()
            running = bool(self._threads) and len(alive) == len(self._threads)
            if stopping:
                detail = "stopping"
            elif not running:
                detail = "not_running"
            else:
                detail = self._scheduler_error or next(
                    iter(self._worker_errors.values()), None
                )
        return SchedulingProviderStatus(
            available=running and not stopping and detail is None,
            mode="local",
            detail=detail,
        )

    def _scheduler_loop(
        self,
        registry: ScheduledTaskRegistry,
        generation: int,
        stop: threading.Event,
        wake: threading.Event,
    ) -> None:
        while not stop.is_set():
            try:
                synchronize_system_schedules(registry)
                cancel_expired_deleted_executions(self._policy.claim_batch_size)
                enqueue_due_schedules(generation, self._policy)
                with self._state_lock:
                    self._scheduler_error = None
            except Exception as exc:  # noqa: BLE001 - provider remains degraded and retries.
                with self._state_lock:
                    self._scheduler_error = type(exc).__name__
                logger.exception("Local scheduling loop failed")
            wake.wait(self._policy.poll_interval_seconds)
            wake.clear()

    def _worker_loop(
        self,
        registry: ScheduledTaskRegistry,
        generation: int,
        stop: threading.Event,
        wake: threading.Event,
    ) -> None:
        lease_owner = secrets.token_hex(32)
        while not stop.is_set():
            try:
                claim = claim_execution(generation, lease_owner, self._policy)
                if claim is not None:
                    run_claimed_execution(claim, generation, registry, self._policy)
                with self._state_lock:
                    self._worker_errors.pop(lease_owner, None)
                if claim is not None:
                    continue
            except Exception as exc:  # noqa: BLE001 - provider remains degraded and retries.
                with self._state_lock:
                    self._worker_errors[lease_owner] = type(exc).__name__
                logger.exception("Local scheduling worker failed")
            wake.wait(self._policy.poll_interval_seconds)
            wake.clear()
