from __future__ import annotations

import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, fields
from typing import TYPE_CHECKING, Any

from loguru import logger as log
from sqlalchemy import distinct, func

from include.config.validation import ConfigValidationError
from include.database.models.identity import User
from include.database.models.operations import AuditEntry
from include.database.session import Session
from include.domains.operations.commands.audit import log_audit
from include.domains.operations.lockdown import (
    apply_lockdown,
    lockdown_state_manager,
)
from include.extensions.manager import hookimpl
from include.providers.manager import ProviderManager

if TYPE_CHECKING:
    from include.transport.connection import ConnectionHandler
    from include.transport.request_handler import Result

logger = log.bind(name="brute_force_lockdown")

DEFAULT_REASON = (
    "Automatic security lockdown: suspected credential-guessing attack detected."
)
RESET_CACHE_KEY = "extension:brute_force_lockdown:last_manual_unlock"
_STARTED_AT = time.time()
_detection_lock = threading.Lock()


@dataclass(frozen=True, slots=True)
class BruteForceLockdownPolicy:
    window_seconds: int = 600
    failure_threshold: int = 50
    distinct_account_threshold: int = 10
    distinct_ip_threshold: int = 10
    reason: str = DEFAULT_REASON

    @classmethod
    def from_config(cls, config: Any) -> BruteForceLockdownPolicy:
        try:
            extensions = config["extensions"]
        except KeyError as exc:
            raise ConfigValidationError(
                "Missing configuration section 'extensions'"
            ) from exc
        if not isinstance(extensions, Mapping):
            raise ConfigValidationError(
                "Configuration section 'extensions' must be a table"
            )

        section = extensions.get("brute_force_lockdown", {})
        if not isinstance(section, Mapping):
            raise ConfigValidationError(
                "extensions.brute_force_lockdown must be a table"
            )

        allowed_fields = {field.name for field in fields(cls)}
        unknown_fields = sorted(set(section) - allowed_fields)
        if unknown_fields:
            raise ConfigValidationError(
                "extensions.brute_force_lockdown contains unknown fields: "
                + ", ".join(unknown_fields)
            )

        values = {
            field.name: section.get(field.name, field.default) for field in fields(cls)
        }
        policy = cls(**values)
        for field_name in (
            "window_seconds",
            "failure_threshold",
            "distinct_account_threshold",
            "distinct_ip_threshold",
        ):
            value = getattr(policy, field_name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ConfigValidationError(
                    f"extensions.brute_force_lockdown.{field_name} must be a "
                    "positive integer"
                )

        if policy.distinct_account_threshold > policy.failure_threshold:
            raise ConfigValidationError(
                "extensions.brute_force_lockdown.distinct_account_threshold must "
                "not exceed failure_threshold"
            )
        if policy.distinct_ip_threshold > policy.failure_threshold:
            raise ConfigValidationError(
                "extensions.brute_force_lockdown.distinct_ip_threshold must not "
                "exceed failure_threshold"
            )
        if not isinstance(policy.reason, str) or not policy.reason.strip():
            raise ConfigValidationError(
                "extensions.brute_force_lockdown.reason must be a non-empty string"
            )
        if len(policy.reason) > 1024:
            raise ConfigValidationError(
                "extensions.brute_force_lockdown.reason must not exceed 1024 characters"
            )

        return cls(
            window_seconds=policy.window_seconds,
            failure_threshold=policy.failure_threshold,
            distinct_account_threshold=policy.distinct_account_threshold,
            distinct_ip_threshold=policy.distinct_ip_threshold,
            reason=policy.reason.strip(),
        )


@dataclass(frozen=True, slots=True)
class FailureWindowStats:
    failure_count: int
    distinct_accounts: int
    distinct_ip_addresses: int
    window_started_at: float
    observed_at: float

    def reaches(self, policy: BruteForceLockdownPolicy) -> bool:
        return self.failure_count >= policy.failure_threshold and (
            self.distinct_accounts >= policy.distinct_account_threshold
            or self.distinct_ip_addresses >= policy.distinct_ip_threshold
        )


def _last_manual_unlock() -> float:
    value = ProviderManager().caching.get(RESET_CACHE_KEY)
    if value is None:
        return 0.0
    try:
        return float(value)
    except TypeError, ValueError:
        logger.warning("Ignoring invalid brute-force lockdown reset marker")
        return 0.0


def _record_manual_unlock() -> None:
    ProviderManager().caching.set(RESET_CACHE_KEY, time.time())


def _collect_window_stats(
    username: str,
    policy: BruteForceLockdownPolicy,
    now: float,
) -> FailureWindowStats | None:
    window_started_at = max(
        now - policy.window_seconds,
        _STARTED_AT,
        _last_manual_unlock(),
    )
    with Session() as session:
        if (
            session.query(User.username).filter(User.username == username).first()
            is None
        ):
            return None

        row = (
            session.query(
                func.count(AuditEntry.id),
                func.count(distinct(AuditEntry.target)),
                func.count(distinct(AuditEntry.remote_address)),
            )
            .select_from(AuditEntry)
            .join(User, User.username == AuditEntry.target)
            .filter(
                AuditEntry.action == "login",
                AuditEntry.result == 401,
                AuditEntry.logged_time >= window_started_at,
            )
            .one()
        )

    return FailureWindowStats(
        failure_count=int(row[0] or 0),
        distinct_accounts=int(row[1] or 0),
        distinct_ip_addresses=int(row[2] or 0),
        window_started_at=window_started_at,
        observed_at=now,
    )


def _audit_automatic_lockdown(
    policy: BruteForceLockdownPolicy,
    stats: FailureWindowStats,
    cancelled_file_tasks: int,
) -> None:
    log_audit(
        "automatic_lockdown",
        0,
        data={
            "source_extension": "brute_force_lockdown",
            "window_seconds": policy.window_seconds,
            "window_started_at": stats.window_started_at,
            "observed_at": stats.observed_at,
            "failure_count": stats.failure_count,
            "distinct_accounts": stats.distinct_accounts,
            "distinct_ip_addresses": stats.distinct_ip_addresses,
            "failure_threshold": policy.failure_threshold,
            "distinct_account_threshold": policy.distinct_account_threshold,
            "distinct_ip_threshold": policy.distinct_ip_threshold,
            "cancelled_file_tasks": cancelled_file_tasks,
        },
    )


@hookimpl
def ext_validate_config(config: Mapping[str, Any]) -> None:
    BruteForceLockdownPolicy.from_config(config)


@hookimpl
def ext_register_extension_flags() -> set[str]:
    return {"brute_force_lockdown"}


@hookimpl
def ext_post_request(
    action: str,
    handler: ConnectionHandler,
    callback: Result | None,
    time_cost: float,
) -> None:
    del time_cost
    try:
        if (
            action == "lockdown"
            and callback is not None
            and callback.code == 0
            and handler.data.get("status") is False
        ):
            _record_manual_unlock()
            return

        if action != "login" or callback is None or callback.code != 401:
            return
        if not isinstance(callback.target, str) or not callback.target:
            return

        with _detection_lock:
            if lockdown_state_manager.get_state().enabled:
                return

            from include.config.settings import global_config

            policy = BruteForceLockdownPolicy.from_config(global_config)
            now = time.time()
            stats = _collect_window_stats(
                callback.target,
                policy,
                now,
            )
            if stats is None or not stats.reaches(policy):
                return

            transition = apply_lockdown(
                True,
                policy.reason,
                only_if_inactive=True,
            )
            if not transition.applied:
                return

            _audit_automatic_lockdown(
                policy,
                stats,
                transition.cancelled_file_tasks,
            )
            logger.warning(
                "Automatic lockdown activated after suspected credential-guessing "
                "activity"
            )
    except Exception:  # noqa: BLE001 - detector failures must not break authentication.
        logger.exception("Failed to evaluate automatic brute-force lockdown")
