import threading
from types import SimpleNamespace


def test_permission_cleanup_worker_runs_immediately_and_restarts(monkeypatch):
    from include.extensions.builtin import _permission_cleanup

    policy = SimpleNamespace(cleanup_interval_seconds=60)
    monkeypatch.setattr(
        _permission_cleanup,
        "IdentityPermissionRetentionPolicy",
        SimpleNamespace(from_config=lambda: policy),
    )
    called = threading.Event()
    calls = []

    def cleanup(received_policy):
        calls.append(received_policy)
        called.set()

    monkeypatch.setattr(
        _permission_cleanup,
        "cleanup_expired_permission_entries",
        cleanup,
    )
    worker = _permission_cleanup.PermissionCleanupWorker()

    worker.start()
    assert called.wait(1.0)
    worker.stop(timeout=1.0)
    worker.stop(timeout=1.0)

    called.clear()
    worker.start()
    assert called.wait(1.0)
    worker.stop(timeout=1.0)

    assert calls == [policy, policy]


def test_permission_cleanup_worker_retries_after_failure(monkeypatch):
    from include.extensions.builtin import _permission_cleanup

    policy = SimpleNamespace(cleanup_interval_seconds=1)
    monkeypatch.setattr(
        _permission_cleanup,
        "IdentityPermissionRetentionPolicy",
        SimpleNamespace(from_config=lambda: policy),
    )
    recovered = threading.Event()
    attempts = 0

    def cleanup(_policy):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("database unavailable")
        recovered.set()

    monkeypatch.setattr(
        _permission_cleanup,
        "cleanup_expired_permission_entries",
        cleanup,
    )
    worker = _permission_cleanup.PermissionCleanupWorker()

    worker.start()
    try:
        assert recovered.wait(3.0)
    finally:
        worker.stop(timeout=1.0)

    assert attempts >= 2
