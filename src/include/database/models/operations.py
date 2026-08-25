import secrets
import time
from typing import TYPE_CHECKING

from sqlalchemy import (
    JSON,
    VARCHAR,
    BigInteger,
    CheckConstraint,
    Double,
    ForeignKey,
    Integer,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from include.database.session import Base

if TYPE_CHECKING:
    from include.database.models.identity import User


class AuditEntry(Base):
    __tablename__ = "audit_entries"
    id: Mapped[str] = mapped_column(
        VARCHAR(255), primary_key=True, default=lambda: secrets.token_hex(32)
    )
    action: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    username: Mapped[str] = mapped_column(ForeignKey("users.username"), nullable=True)
    user: Mapped["User"] = relationship("User", back_populates="audit_entries")
    target: Mapped[str] = mapped_column(VARCHAR(255), nullable=True)
    data: Mapped[dict] = mapped_column(JSON, nullable=True)
    result: Mapped[int] = mapped_column(Integer, nullable=False)
    remote_address: Mapped[str | None] = mapped_column(VARCHAR(64), nullable=True)
    logged_time: Mapped[float | None] = mapped_column(
        Double, nullable=False, default=time.time, index=True
    )


class RateLimitBucket(Base):
    __tablename__ = "rate_limit_buckets"

    namespace: Mapped[str] = mapped_column(VARCHAR(64), primary_key=True)
    scope: Mapped[str] = mapped_column(VARCHAR(16), primary_key=True)
    identity: Mapped[str] = mapped_column(VARCHAR(256), primary_key=True)
    tokens: Mapped[float] = mapped_column(Double, nullable=False)
    last_refill_at: Mapped[float] = mapped_column(Double, nullable=False)
    denial_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_denied_at: Mapped[float | None] = mapped_column(Double, nullable=True)
    last_attempt: Mapped[float] = mapped_column(
        Double, nullable=False, default=time.time, index=True
    )


class RiskIPAccount(Base):
    __tablename__ = "risk_ip_accounts"

    namespace: Mapped[str] = mapped_column(VARCHAR(64), primary_key=True)
    ip_address: Mapped[str] = mapped_column(VARCHAR(45), primary_key=True)
    username: Mapped[str] = mapped_column(VARCHAR(256), primary_key=True)
    last_attempt: Mapped[float] = mapped_column(
        Double, nullable=False, default=time.time, index=True
    )


class SystemStateEntry(Base):
    __tablename__ = "system_states"
    __table_args__ = (
        CheckConstraint(
            "schema_version > 0", name="ck_system_states_schema_version_positive"
        ),
        CheckConstraint("revision > 0", name="ck_system_states_revision_positive"),
    )

    owner: Mapped[str] = mapped_column(VARCHAR(255), primary_key=True)
    state_key: Mapped[str] = mapped_column(VARCHAR(128), primary_key=True)
    schema_version: Mapped[int] = mapped_column(Integer, nullable=False)
    revision: Mapped[int] = mapped_column(BigInteger, nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, nullable=False)
    updated_at: Mapped[float] = mapped_column(Double, nullable=False)
