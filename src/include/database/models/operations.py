from __future__ import annotations

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
    user: Mapped[User] = relationship("User", back_populates="audit_entries")
    target: Mapped[str] = mapped_column(VARCHAR(255), nullable=True)
    data: Mapped[dict] = mapped_column(JSON, nullable=True)
    result: Mapped[int] = mapped_column(Integer, nullable=False)
    remote_address: Mapped[str | None] = mapped_column(VARCHAR(64), nullable=True)
    logged_time: Mapped[float | None] = mapped_column(
        Float, nullable=False, default=time.time, index=True
    )
