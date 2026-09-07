import threading
from types import SimpleNamespace

import pytest

from include.config.validation import SchedulingPolicy
from include.providers.scheduling import local
from include.providers.scheduling.local import LocalSchedulingProvider
from include.scheduling.registry import ScheduledTaskRegistry


def test_local_provider_starts_scheduler_and_workers_and_stops(monkeypatch):
    scheduler_ran = threading.Event()
    worker_ran = threading.Event()
    synchronized = threading.Event()
    expired_deleted_cancelled = threading.Event()

    monkeypatch.setattr(local, "ensure_runtime_state", lambda _mode: 1)

    def enqueue(_generation, _policy):
        scheduler_ran.set()
        return 0

    def claim(_generation, _owner, _policy):
        worker_ran.set()
        return None

    monkeypatch.setattr(local, "enqueue_due_schedules", enqueue)
    monkeypatch.setattr(local, "claim_execution", claim)
    monkeypatch.setattr(
        local,
        "cancel_expired_deleted_executions",
        lambda _batch_size: expired_deleted_cancelled.set(),
    )
    monkeypatch.setattr(
        local,
        "synchronize_system_schedules",
        lambda _registry: synchronized.set(),
    )
    provider = LocalSchedulingProvider(
        SchedulingPolicy(
            worker_threads=1,
            poll_interval_seconds=0.01,
            shutdown_grace_seconds=1,
        )
    )

    provider.start(ScheduledTaskRegistry())

    assert scheduler_ran.wait(1)
    assert synchronized.wait(1)
    assert expired_deleted_cancelled.wait(1)
    assert worker_ran.wait(1)
    assert provider.status().available is True

    provider.shutdown()

    assert provider.status().available is False
    provider.shutdown()


def test_local_provider_cleans_up_after_partial_thread_start(monkeypatch):
    original_start = threading.Thread.start

    def start_or_fail(thread):
        if thread.name == "schedule-local-worker-1":
            raise RuntimeError("worker thread failed to start")
        original_start(thread)

    monkeypatch.setattr(local, "ensure_runtime_state", lambda _mode: 1)
    monkeypatch.setattr(local, "synchronize_system_schedules", lambda _registry: None)
    monkeypatch.setattr(
        local, "cancel_expired_deleted_executions", lambda _batch_size: 0
    )
    monkeypatch.setattr(local, "enqueue_due_schedules", lambda _generation, _policy: 0)
    monkeypatch.setattr(threading.Thread, "start", start_or_fail)
    provider = LocalSchedulingProvider(
        SchedulingPolicy(
            worker_threads=1,
            poll_interval_seconds=0.01,
            shutdown_grace_seconds=1,
        )
    )

    with pytest.raises(RuntimeError, match="worker thread failed to start"):
        provider.start(ScheduledTaskRegistry())

    provider.shutdown()
    assert provider.status().available is False
    assert provider._threads == []


def test_scheduler_success_does_not_hide_worker_failure(monkeypatch):
    provider = LocalSchedulingProvider(SchedulingPolicy())
    registry = ScheduledTaskRegistry()
    stop = threading.Event()
    wake = SimpleNamespace(wait=lambda _timeout: None, clear=lambda: None)

    def fail_claim(_generation, _owner, _policy):
        stop.set()
        raise RuntimeError("worker failed")

    monkeypatch.setattr(local, "claim_execution", fail_claim)
    provider._worker_loop(registry, 1, stop, wake)

    stop.clear()

    def finish_scheduler_iteration(_registry):
        stop.set()

    monkeypatch.setattr(
        local, "synchronize_system_schedules", finish_scheduler_iteration
    )
    monkeypatch.setattr(
        local, "cancel_expired_deleted_executions", lambda _batch_size: 0
    )
    monkeypatch.setattr(local, "enqueue_due_schedules", lambda _generation, _policy: 0)
    provider._scheduler_loop(registry, 1, stop, wake)

    provider._threads = [threading.current_thread()]
    provider._stop = threading.Event()
    status = provider.status()

    assert status.available is False
    assert status.detail == "RuntimeError"


def test_provider_bootstrap_registers_scheduling_when_api_extension_is_disabled(
    monkeypatch,
):
    from include.providers import bootstrap

    registered = []
    monkeypatch.setattr(
        bootstrap,
        "ProviderManager",
        lambda: SimpleNamespace(register=registered.append),
    )

    bootstrap.initialize_providers(
        {
            "extensions": {"enabled": []},
            "provider": {
                "storage": "local",
                "caching": "memory",
                "rate_limit": "memory",
                "event_bus": "local",
                "scheduling": "local",
            },
        }
    )

    assert any(isinstance(item, LocalSchedulingProvider) for item in registered)


def test_local_provider_rejects_restart_until_long_running_worker_exits(monkeypatch):
    task_started = threading.Event()
    release_task = threading.Event()
    restarted_worker = threading.Event()
    claim_lock = threading.Lock()
    claim_count = 0
    generations = iter((1, 2))

    monkeypatch.setattr(local, "ensure_runtime_state", lambda _mode: next(generations))
    monkeypatch.setattr(local, "synchronize_system_schedules", lambda _registry: None)
    monkeypatch.setattr(
        local, "cancel_expired_deleted_executions", lambda _batch_size: 0
    )
    monkeypatch.setattr(local, "enqueue_due_schedules", lambda _generation, _policy: 0)

    def claim(_generation, _owner, _policy):
        nonlocal claim_count
        with claim_lock:
            claim_count += 1
            current_claim = claim_count
        if current_claim == 1:
            return object()
        restarted_worker.set()
        return None

    def run(_claim, _generation, _registry, _policy):
        task_started.set()
        assert release_task.wait(5)

    monkeypatch.setattr(local, "claim_execution", claim)
    monkeypatch.setattr(local, "run_claimed_execution", run)
    provider = LocalSchedulingProvider(
        SchedulingPolicy(
            worker_threads=1,
            poll_interval_seconds=0.01,
            shutdown_grace_seconds=1,
        )
    )
    registry = ScheduledTaskRegistry()

    provider.start(registry)
    provider.start(registry)
    assert task_started.wait(1)

    provider.shutdown()

    status = provider.status()
    assert status.available is False
    assert status.detail == "stopping"
    with pytest.raises(
        RuntimeError,
        match="previous run is still stopping",
    ):
        provider.start(registry)

    release_task.set()
    provider.shutdown()
    with claim_lock:
        assert claim_count == 1

    provider.start(registry)
    assert restarted_worker.wait(1)
    provider.shutdown()
