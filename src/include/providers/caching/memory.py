__all__ = ["MemoryCachingProvider"]

import collections
import threading
import time
from typing import Any

from include.providers.base import CachingProvider


class MemoryCachingProvider(CachingProvider):
    def __init__(self, max_size: int = 10000):
        self._max_size = max_size
        self._cache: collections.OrderedDict[
            str, tuple[bytes | bytearray | memoryview | str | int | float, float]
        ] = collections.OrderedDict()
        self._lock = threading.RLock()

    def _prune(self):
        while len(self._cache) > self._max_size:
            self._cache.popitem(last=False)

    def get(self, key: str) -> Any:
        with self._lock:
            val = self._cache.get(key)
            if val is None:
                return None
            if val[1] > 0 and val[1] < time.time():
                self._cache.pop(key, None)
                return None
            # LRU behavior
            self._cache.move_to_end(key)
            return val[0]

    def set(
        self,
        key: str,
        value: bytes | bytearray | memoryview | str | float,
        ttl: float | None = None,
        nx: bool = False,
    ) -> bool:
        with self._lock:
            if nx and self.exists(key):
                return False
            expire_at = time.time() + ttl if ttl else 0.0
            self._cache[key] = (value, expire_at)
            self._cache.move_to_end(key)
            self._prune()
            return True

    def delete(self, key: str) -> None:
        with self._lock:
            self._cache.pop(key, None)

    def exists(self, key: str) -> bool:
        with self._lock:
            val = self._cache.get(key)
            if val is None:
                return False
            if val[1] > 0 and val[1] < time.time():
                self._cache.pop(key, None)
                return False
            return True
