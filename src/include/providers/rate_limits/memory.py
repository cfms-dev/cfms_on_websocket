__all__ = ["MemoryRateLimitProvider"]

import math
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass

from include.providers.base import (
    RateLimitCharge,
    RateLimitDecision,
    RateLimitProvider,
)


@dataclass(slots=True)
class _BucketState:
    tokens: float
    last_refill_at: float
    last_seen_at: float


class MemoryRateLimitProvider(RateLimitProvider):
    def __init__(self, max_entries: int = 10_000) -> None:
        self._max_entries = max_entries
        self._buckets: OrderedDict[str, _BucketState] = OrderedDict()
        self._lock = threading.Lock()

    def consume(
        self,
        charges: tuple[RateLimitCharge, ...],
        *,
        retention_seconds: int,
        now: float | None = None,
    ) -> RateLimitDecision:
        if not charges:
            return RateLimitDecision(True)
        if now is None:
            now = time.monotonic()

        with self._lock:
            stale_before = now - retention_seconds
            while self._buckets:
                _oldest_key, oldest_state = next(iter(self._buckets.items()))
                if oldest_state.last_seen_at >= stale_before:
                    break
                self._buckets.popitem(last=False)

            denied: list[tuple[RateLimitCharge, int]] = []
            for charge in charges:
                state = self._buckets.get(charge.key)
                if state is None:
                    state = _BucketState(
                        tokens=float(charge.capacity),
                        last_refill_at=now,
                        last_seen_at=now,
                    )
                    self._buckets[charge.key] = state
                elif now > state.last_refill_at:
                    refill_rate = charge.refill_tokens / charge.refill_period_seconds
                    state.tokens = min(
                        float(charge.capacity),
                        state.tokens + (now - state.last_refill_at) * refill_rate,
                    )
                    state.last_refill_at = now

                state.tokens = min(state.tokens, float(charge.capacity))
                state.last_seen_at = now
                self._buckets.move_to_end(charge.key)
                if state.tokens >= charge.cost:
                    state.tokens -= charge.cost
                    continue

                retry_after = max(
                    1,
                    math.ceil(
                        (charge.cost - state.tokens)
                        / (charge.refill_tokens / charge.refill_period_seconds)
                    ),
                )
                denied.append((charge, retry_after))

            while len(self._buckets) > self._max_entries:
                self._buckets.popitem(last=False)

        if not denied:
            return RateLimitDecision(True)
        limiting, retry_after = max(denied, key=lambda item: item[1])
        return RateLimitDecision(
            False,
            scope=limiting.scope,
            effective_limit=max(1, limiting.refill_tokens // limiting.cost),
            retry_after_seconds=retry_after,
        )
