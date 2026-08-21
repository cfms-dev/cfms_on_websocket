import threading
import time

from loguru import logger as log

from include.config.validation import IdentityPermissionRetentionPolicy
from include.database.session import Session
from include.domains.identity.commands.permission_cleanup import (
    PermissionEntryCounts,
    purge_expired_permission_entries,
)

logger = log.bind(name="permission_cleanup")
_SECONDS_PER_DAY = 24 * 60 * 60
_CONFIG_RETRY_INTERVAL_SECONDS = 60
_SHUTDOWN_TIMEOUT_SECONDS = 5.0


def cleanup_expired_permission_entries(
    policy: IdentityPermissionRetentionPolicy,
    now: float | None = None,
) -> PermissionEntryCounts:
    if now is None:
        now = time.time()
    cutoff = now - policy.retention_days * _SECONDS_PER_DAY

    with Session.begin() as session:
        result = purge_expired_permission_entries(
            session,
            cutoff,
            policy.batch_size,
        )

    if result.total:
        logger.bind(
            cutoff=cutoff,
            user_entries=result.user_entries,
            group_entries=result.group_entries,
        ).info("Expired permission entries were purged")
    return result


class PermissionCleanupWorker:
    def __init__(self) -> None:
        self._lifecycle_lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        with self._lifecycle_lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._run,
                name="permission-cleanup-worker",
                daemon=True,
            )
            self._thread.start()

    def stop(self, timeout: float = _SHUTDOWN_TIMEOUT_SECONDS) -> None:
        with self._lifecycle_lock:
            thread = self._thread
            if thread is None:
                return
            self._stop.set()
        thread.join(timeout)
        with self._lifecycle_lock:
            if self._thread is thread and not thread.is_alive():
                self._thread = None

    def _run(self) -> None:
        while not self._stop.is_set():
            interval = _CONFIG_RETRY_INTERVAL_SECONDS
            try:
                policy = IdentityPermissionRetentionPolicy.from_config()
                interval = policy.cleanup_interval_seconds
                cleanup_expired_permission_entries(policy)
            except Exception:
                logger.exception("Expired permission cleanup failed")

            self._stop.wait(interval)


permission_cleanup_worker = PermissionCleanupWorker()
