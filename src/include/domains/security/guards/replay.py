"""
Nonce store for replay attack protection.

Tracks used nonces with automatic expiration to prevent replay attacks.
"""

__all__ = ["NonceStore", "nonce_store"]

import math
import time

from include.config.constants import REPLAY_PROTECTION_TIME_WINDOW_SECONDS
from include.providers.manager import ProviderManager


class NonceStore:
    """
    Thread-safe & Cluster-ready store for tracking used nonces to prevent replay attacks.
    """

    def __init__(self, time_window: float = REPLAY_PROTECTION_TIME_WINDOW_SECONDS):
        self._time_window = time_window

    def validate_and_store(self, nonce: str, timestamp: float) -> str | None:
        if not math.isfinite(timestamp):
            return "Request timestamp is not a finite number"

        now = time.time()
        if abs(now - timestamp) > self._time_window:
            return "Request timestamp is outside the acceptable time window"

        cache = ProviderManager().caching
        ttl = self._time_window * 2

        key = f"nonce:{nonce}"
        success = cache.set(key, str(now), ttl=ttl, nx=True)
        if not success:
            return "Duplicate nonce detected: possible replay attack"

        return None


# Global singleton instance
nonce_store = NonceStore()
