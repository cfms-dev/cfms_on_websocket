import secrets
import time
from typing import TYPE_CHECKING

from sqlalchemy import JSON, VARCHAR, Float, ForeignKey, Integer
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
        Float, nullable=False, default=time.time, index=True
    )


class DocumentCreationRateBucket(Base):
    __tablename__ = "document_creation_rate_buckets"

    scope: Mapped[str] = mapped_column(VARCHAR(16), primary_key=True)
    identity: Mapped[str] = mapped_column(VARCHAR(256), primary_key=True)
    tokens: Mapped[float] = mapped_column(Float, nullable=False)
    last_refill_at: Mapped[float] = mapped_column(Float, nullable=False)
    denial_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    last_denied_at: Mapped[float | None] = mapped_column(Float, nullable=True)
    last_attempt: Mapped[float] = mapped_column(
        Float, nullable=False, default=time.time, index=True
    )


class DocumentCreationIPAccount(Base):
    __tablename__ = "document_creation_ip_accounts"

    ip_address: Mapped[str] = mapped_column(VARCHAR(45), primary_key=True)
    username: Mapped[str] = mapped_column(VARCHAR(256), primary_key=True)
    last_attempt: Mapped[float] = mapped_column(
        Float, nullable=False, default=time.time, index=True
    )
