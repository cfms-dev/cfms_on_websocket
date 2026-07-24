__all__ = ["RedisEventBusProvider"]

import threading
from collections.abc import Callable

import redis
from loguru import logger

from include.providers.base import EventBusProvider


class RedisEventBusProvider(EventBusProvider):
    def __init__(self, host: str, port: int, password: str = "", db: int = 0):
        self._client = redis.Redis(
            host=host, port=port, password=password, db=db, decode_responses=True
        )
        self._pubsub = self._client.pubsub()
        self._callbacks: dict[str, list[Callable[[str], None]]] = {}
        self._lock = threading.Lock()

        self._thread = threading.Thread(target=self._listen_loop, daemon=True)
        self._started = False

    def subscribe(self, channel: str, callback: Callable[[str], None]) -> None:
        with self._lock:
            if channel not in self._callbacks:
                self._callbacks[channel] = []
                self._pubsub.subscribe(channel)
            self._callbacks[channel].append(callback)

            if not self._started:
                self._thread.start()
                self._started = True

    def publish(self, channel: str, message: str) -> None:
        self._client.publish(channel, message)

    def _listen_loop(self):
        try:
            for message in self._pubsub.listen():
                if message["type"] == "message":
                    channel = message["channel"]
                    data = message["data"]
                    with self._lock:
                        subs = self._callbacks.get(channel, []).copy()

                    for callback in subs:
                        try:
                            callback(data)
                        except Exception as e:  # noqa: BLE001 - callbacks are third-party code.
                            logger.error(f"Error in Redis pubsub callback: {e}")
        except Exception as e:  # noqa: BLE001 - keep the listener alive after broker errors.
            logger.error(f"Redis pubsub listener error: {e}")
