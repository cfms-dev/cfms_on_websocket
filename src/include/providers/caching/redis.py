__all__ = ["RedisCachingProvider"]

from typing import Any

import redis

from include.providers.base import CachingProvider


class RedisCachingProvider(CachingProvider):
    def __init__(self, host: str, port: int, password: str = "", db: int = 0):
        self._client = redis.Redis(
            host=host, port=port, password=password, db=db, decode_responses=True
        )

    def get(self, key: str) -> Any:
        """Get a value by key.

        Returns None if the key does not exist or has expired.
        Note that this method only returns string data (if the data exists).
        """
        return self._client.get(key)

    def set(
        self,
        key: str,
        value: bytes | bytearray | memoryview | str | int | float,
        ttl: float | None = None,
        nx: bool = False,
    ) -> bool:
        # Use millisecond precision when possible to avoid losing fractional seconds
        px = int(ttl * 1000) if ttl is not None else None
        res = self._client.set(key, value, px=px, nx=nx)
        return bool(res)

    def delete(self, key: str) -> None:
        self._client.delete(key)

    def exists(self, key: str) -> bool:
        return bool(self._client.exists(key))
