from dataclasses import dataclass
from typing import Any

import orjson

from include.providers.base import CachingProvider
from include.providers.manager import ProviderManager


@dataclass(frozen=True, slots=True)
class LockdownState:
    enabled: bool = False
    reason: str | None = None

    def __post_init__(self) -> None:
        if not self.enabled and self.reason is not None:
            raise ValueError("A lockdown reason requires lockdown to be enabled")

    def as_response_data(self) -> dict[str, bool | str | None]:
        return {"status": self.enabled, "reason": self.reason}


class LockdownStateManager:
    _CACHE_KEY = "system:lockdown"

    def __init__(self, cache: CachingProvider | None = None) -> None:
        self._cache = cache

    @property
    def cache(self) -> CachingProvider:
        if self._cache is not None:
            return self._cache
        return ProviderManager().caching

    def get_state(self) -> LockdownState:
        cached_state = self.cache.get(self._CACHE_KEY)
        if cached_state is None:
            return LockdownState()

        if cached_state in ("1", b"1"):
            return LockdownState(enabled=True)

        try:
            data: dict[str, Any] = orjson.loads(cached_state)
            enabled = data["status"]
            reason = data.get("reason")
            if not isinstance(enabled, bool) or not (
                reason is None or isinstance(reason, str)
            ):
                raise ValueError("Invalid cached lockdown state")
            return LockdownState(
                enabled=enabled,
                reason=reason,
            )
        except (orjson.JSONDecodeError, KeyError, TypeError, ValueError):
            return LockdownState()

    def set_state(self, state: LockdownState) -> LockdownState:
        if state.enabled:
            self.cache.set(self._CACHE_KEY, orjson.dumps(state.as_response_data()))
        else:
            self.cache.delete(self._CACHE_KEY)
        return state

    def enable(self, reason: str | None = None) -> LockdownState:
        return self.set_state(LockdownState(enabled=True, reason=reason))

    def disable(self) -> LockdownState:
        return self.set_state(LockdownState())


lockdown_state_manager = LockdownStateManager()
