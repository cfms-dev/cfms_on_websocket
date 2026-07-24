__all__ = [
    "AccountThrottle",
    "BannedSubnet",
    "LoginThrottle",
    "TrafficThrottle",
]

import time
from typing import TYPE_CHECKING

from sqlalchemy import BigInteger, Double, ForeignKey, Integer, String
from sqlalchemy.orm import Mapped, mapped_column, relationship

from include.config.constants import USERNAME_DATABASE_MAX_LENGTH
from include.database.session import Base

if TYPE_CHECKING:
    from include.database.models.comments import Comment


class BannedSubnet(Base):
    """
    Represents a manually scheduled IP subnet block (CIDR notation).

    Administrators can add CIDR ranges here (e.g. '192.168.1.0/24' or
    '2001:db8::/32') to permanently block all addresses within that range
    at the LoginGuard level, independent of per-identifier lockout records.
    """

    __tablename__ = "banned_subnets"

    subnet: Mapped[str] = mapped_column(String(128), primary_key=True)
    reason_comment_id: Mapped[int | None] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        ForeignKey("comments.comment_id", ondelete="SET NULL"),
        nullable=True,
    )
    reason_comment: Mapped[Comment | None] = relationship("Comment")
    created_at: Mapped[float] = mapped_column(Double, default=time.time, nullable=False)
    starts_at: Mapped[float] = mapped_column(Double, default=time.time, nullable=False)
    expires_at: Mapped[float | None] = mapped_column(Double, nullable=True)

    @property
    def reason(self) -> str | None:
        return self.reason_comment.comment_text if self.reason_comment else None


class LoginThrottle(Base):
    __tablename__ = "login_throttles"

    username: Mapped[str] = mapped_column(String(255), primary_key=True)
    ip_address: Mapped[str] = mapped_column(String(45), primary_key=True, index=True)

    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    window_started_at: Mapped[float] = mapped_column(
        Double, default=time.time, nullable=False
    )
    last_attempt: Mapped[float] = mapped_column(Double, default=time.time, index=True)
    locked_until: Mapped[float | None] = mapped_column(Double, nullable=True)

    def is_locked(self) -> bool:
        if self.locked_until is not None:
            return self.locked_until > time.time()
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
    window_started_at: Mapped[float] = mapped_column(
        Double, default=time.time, nullable=False
    )
    last_attempt: Mapped[float] = mapped_column(Double, default=time.time, index=True)
    locked_until: Mapped[float | None] = mapped_column(Double, nullable=True)

    def is_locked(self) -> bool:
        if self.locked_until is not None:
            return self.locked_until > time.time()
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
    last_attempt: Mapped[float] = mapped_column(Double, default=time.time, index=True)
    locked_until: Mapped[float | None] = mapped_column(Double, nullable=True)

    def is_locked(self) -> bool:
        return self.locked_until is not None and self.locked_until > time.time()

    @classmethod
    def get_record(cls, session, username: str, factor: str):
        return session.get(cls, (username, factor))

    @classmethod
    def make_cache_key(cls, username: str, factor: str) -> tuple[str, str, str]:
        return ("account", username, factor)
