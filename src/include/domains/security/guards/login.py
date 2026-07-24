"""Authentication throttling and permanent subnet blocking."""

from __future__ import annotations

import ipaddress
import json
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum
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


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


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


class LoginGuard:
    _banned_networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    _networks_loaded = False
    _network_lock = threading.Lock()
    _write_lock = threading.RLock()
    _cleanup_lock = threading.Lock()
    _last_cleanup_monotonic = 0.0

    @classmethod
    def reload_networks(cls) -> None:
        networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        with Session() as session:
            rows = session.query(BannedSubnet).all()
            for row in rows:
                try:
                    networks.append(ipaddress.ip_network(row.subnet, strict=True))
                except ValueError:
                    logger.warning(
                        f"Ignoring invalid subnet in database: {row.subnet!r}"
                    )
        with cls._network_lock:
            cls._banned_networks = networks
            cls._networks_loaded = True
        logger.info(f"Loaded {len(networks)} banned subnet(s) from database.")

    @classmethod
    def _is_ip_banned_by_subnet(cls, ip_str: str) -> bool:
        try:
            address = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        with cls._network_lock:
            networks = tuple(cls._banned_networks)
        return any(address in network for network in networks)

    @classmethod
    def evaluate_permanent_access(cls, ip_address: str) -> ThrottleDecision:
        if not cls._networks_loaded:
            cls.reload_networks()
        if ip_address and cls._is_ip_banned_by_subnet(ip_address):
            return ThrottleDecision(False, ThrottleScope.BANNED_SUBNET)
        return ThrottleDecision(True)

    @staticmethod
    def _cache_key(key: tuple[str, ...]) -> str:
        encoded = json.dumps(key, ensure_ascii=False, separators=(",", ":"))
        return f"guard:v2:{encoded}"

    @classmethod
    def _cache_decision(
        cls,
        scope: ThrottleScope,
        key: tuple[str, ...],
        locked_until: datetime,
        now: datetime,
    ) -> ThrottleDecision:
        retry_after = max(1, int((locked_until - now).total_seconds() + 0.999))
        ProviderManager().caching.set(
            cls._cache_key(key), locked_until.timestamp(), ttl=retry_after
        )
        return ThrottleDecision(False, scope, retry_after)

    @classmethod
    def evaluate(
        cls,
        ip_address: str,
        username: str | None = None,
        factor: AuthFactor | None = None,
    ) -> ThrottleDecision:
        permanent = cls.evaluate_permanent_access(ip_address)
        if not permanent.allowed:
            return permanent

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

        now = _utc_now()
        cache = ProviderManager().caching
        for scope, key, _model, _identity in checks:
            cache_key = cls._cache_key(key)
            expiry = cache.get(cache_key)
            if expiry is None:
                continue
            retry_after = int(float(expiry) - now.timestamp() + 0.999)
            if retry_after > 0:
                return ThrottleDecision(False, scope, retry_after)
            cache.delete(cache_key)

        with Session() as session:
            for scope, key, model, identity in checks:
                record = session.get(model, identity)
                if record is not None and record.locked_until is not None:
                    if record.locked_until > now:
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
        now: datetime,
        threshold: int,
        window_seconds: int,
        block_seconds: int,
    ) -> datetime | None:
        if now >= record.window_started_at + timedelta(seconds=window_seconds):
            record.window_started_at = now
            record.failed_attempts = 1
        else:
            record.failed_attempts += 1
        record.last_attempt = now
        if record.failed_attempts >= threshold:
            record.locked_until = now + timedelta(seconds=block_seconds)
            return record.locked_until
        record.locked_until = None
        return None

    @staticmethod
    def _update_account(
        record: AccountThrottle, now: datetime, policy: AuthThrottlePolicy
    ) -> datetime | None:
        if now >= record.last_attempt + timedelta(seconds=policy.account_reset_seconds):
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
            record.locked_until = now + timedelta(seconds=delay)
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

        now = _utc_now()
        locked: list[tuple[ThrottleScope, tuple[str, ...], datetime]] = []
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
            locked_until=locked_until.isoformat(),
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
        cache = ProviderManager().caching
        for key in cache_keys:
            cache.delete(cls._cache_key(key))

    @classmethod
    def _maybe_cleanup(cls, policy: AuthThrottlePolicy) -> None:
        if time.monotonic() - cls._last_cleanup_monotonic < 3600:
            return
        if not cls._cleanup_lock.acquire(blocking=False):
            return
        try:
            if time.monotonic() - cls._last_cleanup_monotonic < 3600:
                return
            now = _utc_now()
            cutoff = now - timedelta(days=policy.record_retention_days)
            with Session.begin() as session:
                for model in (AccountThrottle, LoginThrottle, TrafficThrottle):
                    session.query(model).filter(
                        model.last_attempt < cutoff,
                        or_(model.locked_until.is_(None), model.locked_until <= now),
                    ).delete(synchronize_session=False)
            cls._last_cleanup_monotonic = time.monotonic()
        finally:
            cls._cleanup_lock.release()
