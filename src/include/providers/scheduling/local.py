import secrets
import threading
import time

from loguru import logger

from include.config.validation import SchedulingPolicy
from include.providers.base import SchedulingProvider, SchedulingProviderStatus
from include.scheduling.engine import (
    claim_execution,
    enqueue_due_schedules,
    ensure_runtime_state,
    purge_execution_history,
    run_claimed_execution,
)
from include.scheduling.registry import ScheduledTaskRegistry


class LocalSchedulingProvider(SchedulingProvider):
    def __init__(self, policy: SchedulingPolicy):
        self._policy = policy
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._threads: list[threading.Thread] = []
        self._registry: ScheduledTaskRegistry | None = None
        self._generation: int | None = None
        self._state_lock = threading.Lock()
        self._last_error: str | None = None

    def start(self, registry: ScheduledTaskRegistry) -> None:
        with self._state_lock:
            if self._threads:
                return
            self._registry = registry
            self._generation = ensure_runtime_state("local")
            self._stop.clear()
            scheduler = threading.Thread(
                target=self._scheduler_loop,
                name="schedule-local-scheduler",
                daemon=True,
            )
            workers = [
                threading.Thread(
                    target=self._worker_loop,
                    name=f"schedule-local-worker-{index + 1}",
                    daemon=True,
                )
                for index in range(self._policy.worker_threads)
            ]
            self._threads = [scheduler, *workers]
            for thread in self._threads:
                thread.start()

    def shutdown(self) -> None:
        with self._state_lock:
            threads = self._threads
            if not threads:
                return
            self._threads = []
        self._stop.set()
        self._wake.set()
        deadline = time.monotonic() + self._policy.shutdown_grace_seconds
        for thread in threads:
            thread.join(timeout=max(0.0, deadline - time.monotonic()))

    def notify_schedule_change(self) -> None:
        self._wake.set()

    def status(self) -> SchedulingProviderStatus:
        with self._state_lock:
            running = bool(self._threads) and all(
                thread.is_alive() for thread in self._threads
            )
            detail = self._last_error
        return SchedulingProviderStatus(
            available=running and detail is None,
            mode="local",
            detail=detail,
        )

    def _record_error(self, error: Exception) -> None:
        with self._state_lock:
            self._last_error = type(error).__name__

    def _scheduler_loop(self) -> None:
        next_cleanup_at = 0.0
        while not self._stop.is_set():
            try:
                enqueue_due_schedules(self._generation, self._policy)
                if time.monotonic() >= next_cleanup_at:
                    purge_execution_history(self._policy)
                    next_cleanup_at = time.monotonic() + 3_600
                with self._state_lock:
                    self._last_error = None
            except Exception as exc:  # noqa: BLE001 - provider remains degraded and retries.
                self._record_error(exc)
                logger.exception("Local scheduling loop failed")
            self._wake.wait(self._policy.poll_interval_seconds)
            self._wake.clear()

    def _worker_loop(self) -> None:
        lease_owner = secrets.token_hex(32)
        while not self._stop.is_set():
            try:
                claim = claim_execution(self._generation, lease_owner, self._policy)
                if claim is not None:
                    run_claimed_execution(
                        claim, self._generation, self._registry, self._policy
                    )
                    continue
            except Exception as exc:  # noqa: BLE001 - provider remains degraded and retries.
                self._record_error(exc)
                logger.exception("Local scheduling worker failed")
            self._wake.wait(self._policy.poll_interval_seconds)
            self._wake.clear()
