__all__ = ["LocalEventBusProvider"]

import threading
from collections.abc import Callable

from loguru import logger

from include.providers.base import EventBusProvider


class LocalEventBusProvider(EventBusProvider):
    def __init__(self):
        self._subscribers: dict[str, list[Callable[[str], None]]] = {}
        self._lock = threading.Lock()

    def subscribe(self, channel: str, callback: Callable[[str], None]) -> None:
        with self._lock:
            if channel not in self._subscribers:
                self._subscribers[channel] = []
            self._subscribers[channel].append(callback)

    def publish(self, channel: str, message: str) -> None:
        with self._lock:
            subs = self._subscribers.get(channel, []).copy()

        for callback in subs:
            try:
                callback(message)
            except Exception as e:
                logger.error(f"Error in pubsub callback: {e}")
