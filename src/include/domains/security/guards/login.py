"""Authentication throttling and scheduled subnet blocking."""

from __future__ import annotations

import ipaddress
import json
import math
import threading
import time
from dataclasses import dataclass
from enum import StrEnum
from typing import ClassVar
from warnings import deprecated

from loguru import logger as log
from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError

from include.config.validation import AuthThrottlePolicy
from include.database.models.security import (
    AccountThrottle,
    BannedSubnet,
    LoginThrottle,
    TrafficThrottle,
)
from include.database.session import Session, engine
from include.domains.operations.commands.audit import log_audit
from include.providers.manager import ProviderManager

logger = log.bind(name="login_guard")


class AuthFactor(StrEnum):
    PASSWORD = "password"
    TOTP = "totp"


class ThrottleScope(StrEnum):
    BANNED_SUBNET = "banned_subnet"
    IP = "ip"
    ACCOUNT = "account"
    ACCOUNT_IP = "account_ip"


@dataclass(frozen=True)
class ThrottleDecision:
    allowed: bool
    scope: ThrottleScope | None = None
    retry_after_seconds: int | None = None


@dataclass(frozen=True, slots=True)
class BannedSubnetRule:
    network: ipaddress.IPv4Network | ipaddress.IPv6Network
    starts_at: float
    expires_at: float | None

    def is_active(self, now: float) -> bool:
        return self.starts_at <= now and (
            self.expires_at is None or now < self.expires_at
        )


class LoginGuard:
    _banned_rules: ClassVar[list[BannedSubnetRule]] = []
    _networks_loaded = False
    _network_lock = threading.Lock()
    _write_lock = threading.RLock()
    _cleanup_lock = threading.Lock()
    _last_cleanup_monotonic = 0.0

    @classmethod
    def reload_networks(cls) -> None:
        rules: list[BannedSubnetRule] = []
        with Session() as session:
            rows = session.query(BannedSubnet).all()
            for row in rows:
                try:
                    rules.append(
                        BannedSubnetRule(
                            network=ipaddress.ip_network(row.subnet, strict=True),
                            starts_at=row.starts_at,
                            expires_at=row.expires_at,
                        )
                    )
                except ValueError:
                    logger.warning(
                        f"Ignoring invalid subnet in database: {row.subnet!r}"
                    )
        with cls._network_lock:
            cls._banned_rules = rules
            cls._networks_loaded = True
        logger.info(f"Loaded {len(rules)} banned subnet rule(s) from database.")

    @classmethod
    def evaluate_subnet_access(cls, ip_address: str) -> ThrottleDecision:
        if not cls._networks_loaded:
            cls.reload_networks()
        if not ip_address:
            return ThrottleDecision(True)
        try:
            address = ipaddress.ip_address(ip_address)
        except ValueError:
            return ThrottleDecision(True)
        now = time.time()
        with cls._network_lock:
            rules = tuple(cls._banned_rules)
        if any(rule.is_active(now) and address in rule.network for rule in rules):
            return ThrottleDecision(False, ThrottleScope.BANNED_SUBNET)
        return ThrottleDecision(True)

    @staticmethod
    def _cache_key(key: tuple[str, ...]) -> str:
        encoded = json.dumps(key, ensure_ascii=False, separators=(",", ":"))
        return f"guard:v2:{encoded}"

    @classmethod
    def invalidate_cache_keys(cls, keys: list[tuple[str, ...]]) -> None:
        cache = ProviderManager().caching
        for key in keys:
            cache.delete(cls._cache_key(key))

    @classmethod
    def handle_event(cls, message: str) -> None:
        try:
            payload = json.loads(message)
            event_type = payload["type"]
            if event_type == "reload_subnets":
                cls.reload_networks()
                return
            if event_type == "invalidate_lockouts":
                keys = payload["keys"]
                if not isinstance(keys, list) or not all(
                    isinstance(key, list) and all(isinstance(part, str) for part in key)
                    for key in keys
                ):
                    raise ValueError("Invalid lockout cache keys")
                cls.invalidate_cache_keys([tuple(key) for key in keys])
                return
            raise ValueError(f"Unknown event type: {event_type!r}")
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            logger.warning("Ignoring invalid login guard event")

    @classmethod
    def _cache_decision(
        cls,
        scope: ThrottleScope,
        key: tuple[str, ...],
        locked_until: float,
        now: float,
    ) -> ThrottleDecision:
        retry_after = max(1, math.ceil(locked_until - now))
        ProviderManager().caching.set(
            cls._cache_key(key), locked_until, ttl=retry_after
        )
        return ThrottleDecision(False, scope, retry_after)

    @classmethod
    def evaluate(
        cls,
        ip_address: str,
        username: str | None = None,
        factor: AuthFactor | None = None,
    ) -> ThrottleDecision:
        subnet = cls.evaluate_subnet_access(ip_address)
        if not subnet.allowed:
            return subnet

        policy = AuthThrottlePolicy.from_config()
        if not policy.enabled:
            return ThrottleDecision(True)

        checks: list[tuple[ThrottleScope, tuple[str, ...], type, object]] = []
        if ip_address:
            checks.append(
                (
                    ThrottleScope.IP,
                    TrafficThrottle.make_cache_key(ip_address),
                    TrafficThrottle,
                    ip_address,
                )
            )
        if username and factor:
            checks.append(
                (
                    ThrottleScope.ACCOUNT,
                    AccountThrottle.make_cache_key(username, factor.value),
                    AccountThrottle,
                    (username, factor.value),
                )
            )
        if username and ip_address:
            checks.append(
                (
                    ThrottleScope.ACCOUNT_IP,
                    LoginThrottle.make_cache_key(username, ip_address),
                    LoginThrottle,
                    (username, ip_address),
                )
            )

        now = time.time()
        cache = ProviderManager().caching
        for scope, key, _model, _identity in checks:
            cache_key = cls._cache_key(key)
            expiry = cache.get(cache_key)
            if expiry is None:
                continue
            retry_after = math.ceil(float(expiry) - now)
            if retry_after > 0:
                return ThrottleDecision(False, scope, retry_after)
            cache.delete(cache_key)

        with Session() as session:
            for scope, key, model, identity in checks:
                record = session.get(model, identity)
                if (
                    record is not None
                    and record.locked_until is not None
                    and record.locked_until > now
                ):
                    return cls._cache_decision(scope, key, record.locked_until, now)
        return ThrottleDecision(True)

    @classmethod
    @deprecated("Use evaluate() instead, which returns a ThrottleDecision object.")
    def check_access(cls, ip_address: str, username: str | None = None) -> bool:
        """Compatibility wrapper for extensions using the legacy boolean API."""
        return cls.evaluate(ip_address, username).allowed

    @staticmethod
    def _query_record(session, model, conditions):
        statement = select(model).where(*conditions)
        if engine.dialect.name != "sqlite":
            statement = statement.with_for_update()
        return session.execute(statement).scalar_one_or_none()

    @classmethod
    def _get_or_create(cls, session, model, conditions, create_values: dict):
        record = cls._query_record(session, model, conditions)
        if record is not None:
            return record
        try:
            with session.begin_nested():
                record = model(**create_values)
                session.add(record)
                session.flush()
            return record
        except IntegrityError:
            record = cls._query_record(session, model, conditions)
            if record is None:
                raise
            return record

    @staticmethod
    def _update_fixed_window(
        record,
        now: float,
        threshold: int,
        window_seconds: int,
        block_seconds: int,
    ) -> float | None:
        if now >= record.window_started_at + window_seconds:
            record.window_started_at = now
            record.failed_attempts = 1
        else:
            record.failed_attempts += 1
        record.last_attempt = now
        if record.failed_attempts >= threshold:
            record.locked_until = now + block_seconds
            return record.locked_until
        record.locked_until = None
        return None

    @staticmethod
    def _update_account(
        record: AccountThrottle, now: float, policy: AuthThrottlePolicy
    ) -> float | None:
        if now >= record.last_attempt + policy.account_reset_seconds:
            record.failed_attempts = 1
        else:
            record.failed_attempts += 1
        record.last_attempt = now
        if record.failed_attempts >= policy.account_failure_threshold:
            exponent = record.failed_attempts - policy.account_failure_threshold
            delay = min(
                policy.account_base_delay_seconds * (2**exponent),
                policy.account_max_delay_seconds,
            )
            record.locked_until = now + delay
            return record.locked_until
        record.locked_until = None
        return None

    @classmethod
    def report_failure(
        cls,
        ip_address: str,
        username: str,
        factor: AuthFactor = AuthFactor.PASSWORD,
    ) -> ThrottleDecision:
        policy = AuthThrottlePolicy.from_config()
        if not policy.enabled:
            return ThrottleDecision(True)

        now = time.time()
        locked: list[tuple[ThrottleScope, tuple[str, ...], float]] = []
        with cls._write_lock, Session.begin() as session:
            ip_record = cls._get_or_create(
                session,
                TrafficThrottle,
                (TrafficThrottle.ip_address == ip_address,),
                {
                    "ip_address": ip_address,
                    "failed_attempts": 0,
                    "window_started_at": now,
                    "last_attempt": now,
                },
            )
            ip_lock = cls._update_fixed_window(
                ip_record,
                now,
                policy.ip_failure_threshold,
                policy.ip_window_seconds,
                policy.ip_block_seconds,
            )
            if ip_lock:
                locked.append(
                    (
                        ThrottleScope.IP,
                        TrafficThrottle.make_cache_key(ip_address),
                        ip_lock,
                    )
                )

            account_record = cls._get_or_create(
                session,
                AccountThrottle,
                (
                    AccountThrottle.username == username,
                    AccountThrottle.factor == factor.value,
                ),
                {
                    "username": username,
                    "factor": factor.value,
                    "failed_attempts": 0,
                    "last_attempt": now,
                },
            )
            account_lock = cls._update_account(account_record, now, policy)
            if account_lock:
                locked.append(
                    (
                        ThrottleScope.ACCOUNT,
                        AccountThrottle.make_cache_key(username, factor.value),
                        account_lock,
                    )
                )

            pair_record = cls._get_or_create(
                session,
                LoginThrottle,
                (
                    LoginThrottle.username == username,
                    LoginThrottle.ip_address == ip_address,
                ),
                {
                    "username": username,
                    "ip_address": ip_address,
                    "failed_attempts": 0,
                    "window_started_at": now,
                    "last_attempt": now,
                },
            )
            pair_lock = cls._update_fixed_window(
                pair_record,
                now,
                policy.account_ip_failure_threshold,
                policy.account_ip_window_seconds,
                policy.account_ip_block_seconds,
            )
            if pair_lock:
                locked.append(
                    (
                        ThrottleScope.ACCOUNT_IP,
                        LoginThrottle.make_cache_key(username, ip_address),
                        pair_lock,
                    )
                )
            session.flush()

        cls._maybe_cleanup(policy)
        if not locked:
            return ThrottleDecision(True)

        scope, key, locked_until = max(locked, key=lambda item: item[2])
        logger.bind(
            scope=scope.value,
            factor=factor.value,
            username=username,
            ip_address=ip_address,
            locked_until=locked_until,
        ).warning("Authentication throttle activated")
        decision = cls._cache_decision(scope, key, locked_until, now)
        log_audit(
            "auth_throttle",
            429,
            target=username,
            data={
                "scope": scope.value,
                "factor": factor.value,
                "retry_after_seconds": decision.retry_after_seconds,
            },
            remote_address=ip_address,
        )
        return decision

    @classmethod
    def report_success(
        cls,
        ip_address: str,
        username: str,
        factor: AuthFactor = AuthFactor.PASSWORD,
        *,
        completed_authentication: bool = False,
    ) -> None:
        cache_keys = [AccountThrottle.make_cache_key(username, factor.value)]
        with cls._write_lock, Session.begin() as session:
            account_record = AccountThrottle.get_record(session, username, factor.value)
            if account_record:
                session.delete(account_record)
            if completed_authentication:
                pair_record = LoginThrottle.get_record(session, username, ip_address)
                if pair_record:
                    session.delete(pair_record)
                cache_keys.append(LoginThrottle.make_cache_key(username, ip_address))
        cls.invalidate_cache_keys(cache_keys)

    @classmethod
    def _maybe_cleanup(cls, policy: AuthThrottlePolicy) -> None:
        if time.monotonic() - cls._last_cleanup_monotonic < 3600:
            return
        if not cls._cleanup_lock.acquire(blocking=False):
            return
        try:
            if time.monotonic() - cls._last_cleanup_monotonic < 3600:
                return
            now = time.time()
            cutoff = now - policy.record_retention_days * 86400
            with Session.begin() as session:
                for model in (AccountThrottle, LoginThrottle, TrafficThrottle):
                    session.query(model).filter(
                        model.last_attempt < cutoff,
                        or_(model.locked_until.is_(None), model.locked_until <= now),
                    ).delete(synchronize_session=False)
            cls._last_cleanup_monotonic = time.monotonic()
        finally:
            cls._cleanup_lock.release()
