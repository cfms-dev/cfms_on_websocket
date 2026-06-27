import secrets
from typing import TYPE_CHECKING

from sqlalchemy import VARCHAR, Float, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from include.database.session import Base

if TYPE_CHECKING:
    from include.domains.identity.models import User


class UserBlockEntry(Base):
    __tablename__ = "userblock_entries"
    block_id: Mapped[str] = mapped_column(
        VARCHAR(32), primary_key=True, default=lambda: secrets.token_hex(16)
    )
    username: Mapped[str] = mapped_column(
        ForeignKey("users.username", ondelete="CASCADE")
    )
    user: Mapped["User"] = relationship("User", back_populates="block_entries")
    sub_entries: Mapped[list["UserBlockSubEntry"]] = relationship(
        "UserBlockSubEntry", back_populates="parent_entry", cascade="all, delete-orphan"
    )
    timestamp: Mapped[float] = mapped_column(Float, nullable=False)

    not_before: Mapped[float] = mapped_column(Float, nullable=False)
    not_after: Mapped[float] = mapped_column(Float, nullable=False)

    # Due to technical issues in the implementation of ORM, target_type and target_id are
    # stored as two separate columns, but when 'target_type' is 'all', target_id can be
    # left empty.
    target_type: Mapped[str] = mapped_column(VARCHAR(32), nullable=False)
    target_id: Mapped[str] = mapped_column(VARCHAR(255), nullable=True)


class UserBlockSubEntry(Base):
    __tablename__ = "userblock_sub_entries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    parent_id: Mapped[str] = mapped_column(
        ForeignKey("userblock_entries.block_id", ondelete="CASCADE")
    )
    parent_entry: Mapped[UserBlockEntry] = relationship(
        "UserBlockEntry", back_populates="sub_entries"
    )
    block_type: Mapped[str] = mapped_column(VARCHAR(64))


class ObjectAccessEntry(Base):
    """
    Model for `User`/`UserGroup` access.
    """

    __tablename__ = "object_access_entries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # User / UserGroup
    entity_type: Mapped[str] = mapped_column(VARCHAR(16), nullable=False)
    entity_identifier: Mapped[str] = mapped_column(
        VARCHAR(255), nullable=False, index=True
    )

    # Document / Folder
    target_type: Mapped[str] = mapped_column(VARCHAR(16), nullable=False)
    target_identifier: Mapped[str] = mapped_column(
        VARCHAR(255), nullable=False, index=True
    )

    # read, write, move
    access_type: Mapped[str] = mapped_column(VARCHAR(16), nullable=False)

    start_time: Mapped[float] = mapped_column(Float, nullable=False)
    end_time: Mapped[float | None] = mapped_column(Float, nullable=True)
