import secrets
import time
from typing import TYPE_CHECKING

from sqlalchemy import VARCHAR, Boolean, Float, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from include.database.session import Base

if TYPE_CHECKING:
    from include.database.models.documents import Node
    from include.database.models.identity import User


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


class CompiledAccessRule(Base):
    """
    Persisted representation of document/folder JSON access rules.
    """

    __tablename__ = "compiled_access_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    rule_set_id: Mapped[str] = mapped_column(
        VARCHAR(32),
        ForeignKey("compiled_access_rule_sets.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    access_type: Mapped[str] = mapped_column(VARCHAR(64), nullable=False, index=True)
    match_mode: Mapped[str] = mapped_column(VARCHAR(8), nullable=False)

    rule_set: Mapped["CompiledAccessRuleSet"] = relationship(
        "CompiledAccessRuleSet", back_populates="rules"
    )
    match_groups: Mapped[list["CompiledAccessRuleGroup"]] = relationship(
        "CompiledAccessRuleGroup",
        back_populates="rule",
        cascade="all, delete-orphan",
        order_by="CompiledAccessRuleGroup.group_index",
    )


class CompiledAccessRuleSet(Base):
    __tablename__ = "compiled_access_rule_sets"

    id: Mapped[str] = mapped_column(
        VARCHAR(32), primary_key=True, default=lambda: secrets.token_hex(16)
    )
    node_id: Mapped[str] = mapped_column(
        VARCHAR(255),
        ForeignKey("nodes.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    created_at: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time()
    )

    node: Mapped["Node"] = relationship(
        "Node",
        back_populates="access_rule_sets",
        foreign_keys=[node_id],
    )
    rules: Mapped[list[CompiledAccessRule]] = relationship(
        "CompiledAccessRule",
        back_populates="rule_set",
        cascade="all, delete-orphan",
        order_by="CompiledAccessRule.id",
    )


class CompiledAccessRuleGroup(Base):
    __tablename__ = "compiled_access_rule_groups"

    id: Mapped[str] = mapped_column(
        VARCHAR(32), primary_key=True, default=lambda: secrets.token_hex(16)
    )
    rule_id: Mapped[int] = mapped_column(
        ForeignKey("compiled_access_rules.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    group_index: Mapped[int] = mapped_column(Integer, nullable=False)
    match_mode: Mapped[str] = mapped_column(VARCHAR(8), nullable=False)
    rights_match_mode: Mapped[str] = mapped_column(VARCHAR(8), nullable=False)
    rights_empty: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    groups_match_mode: Mapped[str] = mapped_column(VARCHAR(8), nullable=False)
    groups_empty: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    rule: Mapped[CompiledAccessRule] = relationship(
        "CompiledAccessRule", back_populates="match_groups"
    )
    rights: Mapped[list["CompiledAccessRuleRight"]] = relationship(
        "CompiledAccessRuleRight",
        back_populates="group",
        cascade="all, delete-orphan",
        order_by="CompiledAccessRuleRight.id",
    )
    groups: Mapped[list["CompiledAccessRuleMembership"]] = relationship(
        "CompiledAccessRuleMembership",
        back_populates="group",
        cascade="all, delete-orphan",
        order_by="CompiledAccessRuleMembership.id",
    )


class CompiledAccessRuleRight(Base):
    __tablename__ = "compiled_access_rule_rights"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    group_id: Mapped[str] = mapped_column(
        ForeignKey("compiled_access_rule_groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    permission: Mapped[str] = mapped_column(VARCHAR(64), nullable=False, index=True)

    group: Mapped[CompiledAccessRuleGroup] = relationship(
        "CompiledAccessRuleGroup", back_populates="rights"
    )


class CompiledAccessRuleMembership(Base):
    __tablename__ = "compiled_access_rule_memberships"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    group_id: Mapped[str] = mapped_column(
        ForeignKey("compiled_access_rule_groups.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    group_name: Mapped[str] = mapped_column(VARCHAR(255), nullable=False, index=True)

    group: Mapped[CompiledAccessRuleGroup] = relationship(
        "CompiledAccessRuleGroup", back_populates="groups"
    )
