import threading

from include.config.validation import SchedulingPolicy
from include.providers.scheduling import local
from include.providers.scheduling.local import LocalSchedulingProvider
from include.scheduling.registry import ScheduledTaskRegistry


def test_local_provider_starts_scheduler_and_workers_and_stops(monkeypatch):
    scheduler_ran = threading.Event()
    worker_ran = threading.Event()

    monkeypatch.setattr(local, "ensure_runtime_state", lambda _mode: 1)

    def enqueue(_generation, _policy):
        scheduler_ran.set()
        return 0

    def claim(_generation, _owner, _policy):
        worker_ran.set()
        return None

    monkeypatch.setattr(local, "enqueue_due_schedules", enqueue)
    monkeypatch.setattr(local, "claim_execution", claim)
    provider = LocalSchedulingProvider(
        SchedulingPolicy(
            worker_threads=1,
            poll_interval_seconds=0.01,
            shutdown_grace_seconds=1,
        )
    )

    provider.start(ScheduledTaskRegistry())

    assert scheduler_ran.wait(1)
    assert worker_ran.wait(1)
    assert provider.status().available is True

    provider.shutdown()

    assert provider.status().available is False
    provider.shutdown()
