import threading
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from itertools import batched

import orjson
from loguru import logger as log

from include.config.constants import FILE_TASK_EVENT_CHANNEL
from include.providers.manager import ProviderManager

logger = log.bind(name="file_tasks")
_active_tasks: dict[str, set[threading.Event]] = {}
_active_tasks_lock = threading.Lock()


@contextmanager
def watch_file_task(task_id: str) -> Iterator[threading.Event]:
    cancelled = threading.Event()
    with _active_tasks_lock:
        _active_tasks.setdefault(task_id, set()).add(cancelled)
    try:
        yield cancelled
    finally:
        with _active_tasks_lock:
            watchers = _active_tasks.get(task_id)
            if watchers is not None:
                watchers.discard(cancelled)
                if not watchers:
                    _active_tasks.pop(task_id, None)


def cancel_local_file_tasks(task_ids: Sequence[str]) -> None:
    with _active_tasks_lock:
        watchers = [
            watcher
            for task_id in task_ids
            for watcher in _active_tasks.get(task_id, ())
        ]
    for watcher in watchers:
        watcher.set()


def publish_cancelled_file_tasks(task_ids: Sequence[str]) -> None:
    if not task_ids:
        return
    cancel_local_file_tasks(task_ids)
    for chunk in batched(task_ids, 256):
        try:
            ProviderManager().event_bus.publish(
                FILE_TASK_EVENT_CHANNEL,
                orjson.dumps({"cancelled": chunk}).decode(),
            )
        except Exception:
            logger.exception("Failed to publish file-task cancellation")


def on_file_task_event(message: str) -> None:
    try:
        payload = orjson.loads(message)
        task_ids = payload["cancelled"]
        if not isinstance(task_ids, list) or not all(
            isinstance(task_id, str) for task_id in task_ids
        ):
            raise ValueError("Invalid file-task event")
    except orjson.JSONDecodeError, KeyError, TypeError, ValueError:
        logger.warning("Ignoring invalid file-task event")
        return
    cancel_local_file_tasks(task_ids)
