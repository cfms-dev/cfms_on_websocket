__all__ = ["RedisRateLimitProvider"]

import redis

from include.providers.base import (
    RateLimitCharge,
    RateLimitDecision,
    RateLimitProvider,
)

_CONSUME_SCRIPT = """
local current_time
if ARGV[1] == '' then
    local redis_time = redis.call('TIME')
    current_time = tonumber(redis_time[1]) + tonumber(redis_time[2]) / 1000000
else
    current_time = tonumber(ARGV[1])
end

local limiting_index = 0
local longest_retry = 0
for index = 1, #KEYS do
    local offset = 2 + (index - 1) * 5
    local capacity = tonumber(ARGV[offset])
    local refill_tokens = tonumber(ARGV[offset + 1])
    local refill_period = tonumber(ARGV[offset + 2])
    local cost = tonumber(ARGV[offset + 3])
    local retention = tonumber(ARGV[offset + 4])
    local values = redis.call('HMGET', KEYS[index], 'tokens', 'last_refill_at')
    local tokens = tonumber(values[1]) or capacity
    local last_refill_at = tonumber(values[2]) or current_time
    if current_time > last_refill_at then
        local refill_rate = refill_tokens / refill_period
        tokens = math.min(capacity, tokens + (current_time - last_refill_at) * refill_rate)
        last_refill_at = current_time
    end
    tokens = math.min(tokens, capacity)
    if tokens >= cost then
        tokens = tokens - cost
    else
        local retry = math.ceil((cost - tokens) / (refill_tokens / refill_period))
        if retry < 1 then retry = 1 end
        if retry > longest_retry then
            longest_retry = retry
            limiting_index = index
        end
    end
    redis.call('HSET', KEYS[index], 'tokens', tokens, 'last_refill_at', last_refill_at)
    redis.call('EXPIRE', KEYS[index], retention)
end
return {limiting_index, longest_retry}
"""


class RedisRateLimitProvider(RateLimitProvider):
    def __init__(self, host: str, port: int, password: str = "", db: int = 0) -> None:
        self._client = redis.Redis(
            host=host, port=port, password=password, db=db, decode_responses=True
        )

    def consume(
        self,
        charges: tuple[RateLimitCharge, ...],
        *,
        retention_seconds: int,
        now: float | None = None,
    ) -> RateLimitDecision:
        if not charges:
            return RateLimitDecision(True)
        arguments: list[str | int | float] = ["" if now is None else now]
        for charge in charges:
            arguments.extend(
                (
                    charge.capacity,
                    charge.refill_tokens,
                    charge.refill_period_seconds,
                    charge.cost,
                    retention_seconds,
                )
            )
        limiting_index, retry_after = self._client.eval(
            _CONSUME_SCRIPT,
            len(charges),
            *(charge.key for charge in charges),
            *arguments,
        )
        limiting_index = int(limiting_index)
        retry_after = int(retry_after)
        if limiting_index == 0:
            return RateLimitDecision(True)
        limiting = charges[limiting_index - 1]
        return RateLimitDecision(
            False,
            scope=limiting.scope,
            effective_limit=max(1, limiting.refill_tokens // limiting.cost),
            retry_after_seconds=max(1, retry_after),
        )
