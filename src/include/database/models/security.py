__all__ = [
    "AccountThrottle",
    "BannedSubnet",
    "LoginThrottle",
    "TrafficThrottle",
]

from datetime import UTC, datetime

from sqlalchemy import DateTime, Integer, String, func
from sqlalchemy.orm import Mapped, mapped_column

from include.config.constants import USERNAME_DATABASE_MAX_LENGTH
from include.database.session import Base


def _utc_now() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class BannedSubnet(Base):
    """
    Represents a manually blocked IP subnet (CIDR notation).

    Administrators can add CIDR ranges here (e.g. '192.168.1.0/24' or
    '2001:db8::/32') to permanently block all addresses within that range
    at the LoginGuard level, independent of per-identifier lockout records.
    """

    __tablename__ = "banned_subnets"

    subnet: Mapped[str] = mapped_column(String(128), primary_key=True)
    reason: Mapped[str | None] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, server_default=func.now(), nullable=False
    )


class LoginThrottle(Base):
    __tablename__ = "login_throttles"

    username: Mapped[str] = mapped_column(String(255), primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), primary_key=True, index=True)

    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    window_started_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    last_attempt: Mapped[datetime] = mapped_column(
        DateTime, default=_utc_now, index=True
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def is_locked(self) -> bool:
        if self.locked_until is not None:
            return self.locked_until > _utc_now()
        return False

    @classmethod
    def get_record(cls, session, username: str, ip_address: str):
        return session.get(cls, (username, ip_address))

    @classmethod
    def make_cache_key(cls, username: str, ip_address: str) -> tuple[str, str, str]:
        return ("user_ip", username, ip_address)


class TrafficThrottle(Base):
    __tablename__ = "traffic_throttles"

    ip_address: Mapped[str] = mapped_column(String(45), primary_key=True)

    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    window_started_at: Mapped[datetime] = mapped_column(
        DateTime, default=func.now(), nullable=False
    )
    last_attempt: Mapped[datetime] = mapped_column(
        DateTime, default=_utc_now, index=True
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def is_locked(self) -> bool:
        if self.locked_until is not None:
            return self.locked_until > _utc_now()
        return False

    @classmethod
    def get_record(cls, session, ip_address: str):
        return session.get(cls, ip_address)

    @classmethod
    def make_cache_key(cls, ip_address: str) -> tuple[str, str]:
        return ("ip", ip_address)


class AccountThrottle(Base):
    __tablename__ = "account_throttles"

    username: Mapped[str] = mapped_column(
        String(USERNAME_DATABASE_MAX_LENGTH), primary_key=True
    )
    factor: Mapped[str] = mapped_column(String(16), primary_key=True)
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_attempt: Mapped[datetime] = mapped_column(
        DateTime, default=_utc_now, index=True
    )
    locked_until: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > _utc_now()

    @classmethod
    def get_record(cls, session, username: str, factor: str):
        return session.get(cls, (username, factor))

    @classmethod
    def make_cache_key(cls, username: str, factor: str) -> tuple[str, str, str]:
        return ("account", username, factor)
