import secrets
import time
import uuid

from sqlalchemy import VARCHAR, Double, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from include.database.session import Base
lazy from include.database.models.identity import User


class UserKey(Base):
    """
    Stores user-owned encryption keys (DEKs) for client configuration encryption
    and multi-device synchronization.

    Each key entry is bound to a specific user. Users can designate one key as
    their *preference* key; that key is returned in the login response so any
    conforming client can transparently retrieve the configuration-encryption DEK
    without having to know or guess a key identifier.
    """

    __tablename__ = "keyrings"

    id: Mapped[str] = mapped_column(
        VARCHAR(64), primary_key=True, default=lambda: secrets.token_hex(32)
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)

    # label is reserved for future use and is currently optional.
    label: Mapped[str | None] = mapped_column(VARCHAR(255), nullable=True)
    created_time: Mapped[float] = mapped_column(
        Double, nullable=False, default=time.time
    )

    user: Mapped["User"] = relationship(
        "User",
        back_populates="keyring",
        overlaps="preference_dek",
        foreign_keys=[user_id],
    )

    def __repr__(self) -> str:
        return (
            f"UserKey(id={self.id!r}, user_id={self.user_id!r}, label={self.label!r})"
        )
