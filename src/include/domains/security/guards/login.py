"""
Login Guard system. Protects from brute force attacks.
"""

import ipaddress
import threading
import time
from datetime import datetime, timedelta
from typing import Optional, Union

from loguru import logger as log

from include.database.models.security import (
    BannedSubnet,
    LoginThrottle,
    TrafficThrottle,
)
from include.database.session import Session
from include.providers.manager import ProviderManager

logger = log.bind(name="login_guard")


class LoginGuard:
    _banned_networks: list[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
    _networks_loaded: bool = False
    _network_lock = threading.Lock()

    @classmethod
    def reload_networks(cls) -> None:
        networks: list[Union[ipaddress.IPv4Network, ipaddress.IPv6Network]] = []
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
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return False
        with cls._network_lock:
            networks = cls._banned_networks
        return any(addr in network for network in networks)

    @classmethod
    def check_access(cls, ip_address: str, username: Optional[str] = None) -> bool:
        if not cls._networks_loaded:
            cls.reload_networks()
        if ip_address and cls._is_ip_banned_by_subnet(ip_address):
            return False

        keys_to_check = []
        if ip_address:
            keys_to_check.append(
                (TrafficThrottle, TrafficThrottle.make_cache_key(ip_address))
            )
        if username and ip_address:
            keys_to_check.append(
                (LoginThrottle, LoginThrottle.make_cache_key(username, ip_address))
            )

        now_ts = time.time()
        cache = ProviderManager().caching

        for model_cls, key in keys_to_check:
            cache_key = f"guard:{key}"
            expiry_str = cache.get(cache_key)
            if expiry_str:
                expiry = float(expiry_str)
                if now_ts < expiry:
                    return False
                else:
                    cache.delete(cache_key)

        with Session() as session:
            for model_cls, key in keys_to_check:
                if model_cls == TrafficThrottle:
                    record = model_cls.get_record(session, ip_address)
                else:
                    record = model_cls.get_record(session, username, ip_address)

                if record is not None and record.is_locked():
                    if record.locked_until is not None:
                        cache_key = f"guard:{key}"
                        ttl = max(
                            0, (record.locked_until - datetime.now()).total_seconds()
                        )
                        if ttl > 0:
                            cache.set(
                                cache_key, str(record.locked_until.timestamp()), ttl=ttl
                            )
                        return False
        return True

    @classmethod
    def report_failure(
        cls,
        ip_address: str,
        username: Optional[str] = None,
        max_attempts: int = 5,
        lock_minutes: int = 15,
        ip_max_attempts: int = 20,
        ip_lock_minutes: int = 15,
    ):
        now = datetime.now()
        cache = ProviderManager().caching

        with Session() as session:
            if ip_address:
                ip_key = TrafficThrottle.make_cache_key(ip_address)
                ip_record = TrafficThrottle.get_record(session, ip_address)
                if not ip_record:
                    ip_record = TrafficThrottle(
                        ip_address=ip_address, failed_attempts=1
                    )
                    session.add(ip_record)
                else:
                    if ip_record.last_attempt < now - timedelta(hours=1):
                        ip_record.failed_attempts = 1
                    else:
                        ip_record.failed_attempts += 1
                    ip_record.last_attempt = now

                if ip_record.failed_attempts >= ip_max_attempts:
                    lock_time = now + timedelta(minutes=ip_lock_minutes)
                    ip_record.locked_until = lock_time
                    cache_key = f"guard:{ip_key}"
                    cache.set(
                        cache_key, str(lock_time.timestamp()), ttl=ip_lock_minutes * 60
                    )
                    logger.warning(
                        f"Security: IP '{ip_address}' locked until {lock_time}"
                    )

            if username and ip_address:
                u_key = LoginThrottle.make_cache_key(username, ip_address)
                u_record = LoginThrottle.get_record(session, username, ip_address)
                if not u_record:
                    u_record = LoginThrottle(
                        username=username, ip_address=ip_address, failed_attempts=1
                    )
                    session.add(u_record)
                else:
                    if u_record.last_attempt < now - timedelta(hours=1):
                        u_record.failed_attempts = 1
                    else:
                        u_record.failed_attempts += 1
                    u_record.last_attempt = now

                if u_record.failed_attempts >= max_attempts:
                    lock_time = now + timedelta(minutes=lock_minutes)
                    u_record.locked_until = lock_time
                    cache_key = f"guard:{u_key}"
                    cache.set(
                        cache_key, str(lock_time.timestamp()), ttl=lock_minutes * 60
                    )
                    logger.warning(
                        f"Security: User '{username}' on IP '{ip_address}' locked until {lock_time}"
                    )

            session.commit()

    @classmethod
    def report_success(cls, ip_address: str, username: Optional[str] = None):
        with Session() as session:
            keys_to_clear = []

            if ip_address:
                ip_key = TrafficThrottle.make_cache_key(ip_address)
                keys_to_clear.append(ip_key)
                ip_record = TrafficThrottle.get_record(session, ip_address)
                if ip_record:
                    session.delete(ip_record)

            if username and ip_address:
                u_key = LoginThrottle.make_cache_key(username, ip_address)
                keys_to_clear.append(u_key)
                u_record = LoginThrottle.get_record(session, username, ip_address)
                if u_record:
                    session.delete(u_record)

            session.commit()

            for k in keys_to_clear:
                ProviderManager().caching.delete(f"guard:{k}")
