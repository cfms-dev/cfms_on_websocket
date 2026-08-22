__all__ = [
    "RequestRateControlDecision",
    "check_connection_attempt",
    "check_request_rate",
    "validate_handler_rate_limit_costs",
]

import hashlib
import hmac
import threading
import time
from dataclasses import dataclass

from loguru import logger as log

from include.config.settings import global_config
from include.config.validation import RequestRateControlPolicy
from include.providers.base import RateLimitCharge
from include.providers.manager import ProviderManager

logger = log.bind(name="request_rate_control")
_log_lock = threading.Lock()
_last_log_times: dict[tuple[str, ...], float] = {}


def _should_log(key: tuple[str, ...], interval_seconds: float) -> bool:
    now = time.monotonic()
    with _log_lock:
        last_log_time = _last_log_times.get(key, float("-inf"))
        if now - last_log_time < interval_seconds:
            return False
        _last_log_times[key] = now
        return True


@dataclass(frozen=True, slots=True)
class RequestRateControlDecision:
    allowed: bool
    would_block: bool = False
    scope: str | None = None
    limit: int | None = None
    retry_after_seconds: int = 0


def _bucket_key(namespace: str, scope: str, identity: str) -> str:
    secret = global_config["server"]["secret_key"].encode()
    digest = hmac.new(secret, identity.encode(), hashlib.sha256).hexdigest()
    return f"cfms:rate-limit:v1:{namespace}:{scope}:{digest}"


def _evaluate(
    charges: tuple[RateLimitCharge, ...],
    policy: RequestRateControlPolicy,
    *,
    action: str | None,
    username: str | None,
    ip_address: str,
) -> RequestRateControlDecision:
    if policy.mode == "disabled":
        return RequestRateControlDecision(True)
    try:
        decision = ProviderManager().rate_limit.consume(
            charges, retention_seconds=policy.state_retention_seconds
        )
    except Exception:  # noqa: BLE001 - shared rate state fails open behind local caps.
        if _should_log(("provider_error",), 60):
            logger.bind(
                action=action,
                username=username,
                remote_address=ip_address,
            ).exception("Request rate-limit provider failed; allowing request")
        return RequestRateControlDecision(True)

    would_block = not decision.allowed
    if would_block and _should_log(
        ("limit", policy.mode, decision.scope or "unknown", action or "connection"),
        10,
    ):
        logger.bind(
            action=action,
            username=username,
            remote_address=ip_address,
            scope=decision.scope,
            limit=decision.effective_limit,
            retry_after_seconds=decision.retry_after_seconds,
            mode=policy.mode,
            would_block=True,
        ).warning("Request rate limit evaluated")
    return RequestRateControlDecision(
        allowed=decision.allowed or policy.mode == "observe",
        would_block=would_block,
        scope=decision.scope,
        limit=decision.effective_limit,
        retry_after_seconds=decision.retry_after_seconds,
    )


def check_connection_attempt(ip_address: str) -> RequestRateControlDecision:
    policy = RequestRateControlPolicy.from_config()
    return _evaluate(
        (
            RateLimitCharge(
                key=_bucket_key("connection", "ip", ip_address),
                scope="ip",
                capacity=policy.connection_capacity,
                refill_tokens=policy.connection_refill_tokens,
                refill_period_seconds=policy.connection_refill_period_seconds,
                cost=1,
            ),
        ),
        policy,
        action=None,
        username=None,
        ip_address=ip_address,
    )


def check_request_rate(
    action: str,
    handler_cost: int,
    ip_address: str,
    *,
    username: str | None,
    bypass: bool,
) -> RequestRateControlDecision:
    if bypass:
        return RequestRateControlDecision(True)
    policy = RequestRateControlPolicy.from_config()
    cost = policy.cost_for(action, handler_cost)
    charges = [
        RateLimitCharge(
            key=_bucket_key("request", "ip", ip_address),
            scope="ip",
            capacity=policy.ip_capacity,
            refill_tokens=policy.ip_refill_tokens,
            refill_period_seconds=policy.request_refill_period_seconds,
            cost=cost,
        )
    ]
    if username is not None:
        charges.append(
            RateLimitCharge(
                key=_bucket_key("request", "account", username),
                scope="account",
                capacity=policy.account_capacity,
                refill_tokens=policy.account_refill_tokens,
                refill_period_seconds=policy.request_refill_period_seconds,
                cost=cost,
            )
        )
    return _evaluate(
        tuple(charges),
        policy,
        action=action,
        username=username,
        ip_address=ip_address,
    )


def validate_handler_rate_limit_costs(
    handlers: dict[str, type],
) -> tuple[str, ...]:
    policy = RequestRateControlPolicy.from_config()
    maximum_cost = min(policy.account_capacity, policy.ip_capacity)
    for action, handler in handlers.items():
        cost = handler.rate_limit_cost
        if (
            isinstance(cost, bool)
            or not isinstance(cost, int)
            or cost <= 0
            or cost > maximum_cost
        ):
            raise ValueError(
                f"Request handler for action {action!r} must declare a positive "
                f"integer rate_limit_cost not exceeding {maximum_cost}"
            )
    configured_actions = {action for action, _cost in policy.action_costs}
    return tuple(sorted(configured_actions - handlers.keys()))
