__all__ = [
    "NodeDaclAtom",
    "NodeDaclClause",
    "NodeDaclRule",
    "UtcEpochMicros",
    "datetime_to_epoch_us",
    "epoch_us_to_datetime",
]

import datetime

from sqlalchemy import (
    VARCHAR,
    BigInteger,
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Text,
    TypeDecorator,
)
from sqlalchemy.engine import Dialect
from sqlalchemy.orm import Mapped, mapped_column, relationship

from include.database.session import Base
lazy from include.database.models.documents import Node

_EPOCH_UTC = datetime.datetime(1970, 1, 1, tzinfo=datetime.UTC)


def datetime_to_epoch_us(dt: datetime.datetime) -> int:
    if dt.tzinfo is None or dt.utcoffset() is None:
        raise ValueError("Timestamp must be timezone-aware")

    # See: https://docs.python.org/3/library/datetime.html#datetime-objects
    delta = dt.astimezone(datetime.UTC) - _EPOCH_UTC
    return (delta.days * 86_400 + delta.seconds) * 1_000_000 + delta.microseconds


def epoch_us_to_datetime(epoch_us: int) -> datetime.datetime:
    return _EPOCH_UTC + datetime.timedelta(microseconds=epoch_us)


class UtcEpochMicros(TypeDecorator[datetime.datetime]):
    """Store timezone-aware UTC datetimes as exact 64-bit epoch microseconds."""

    impl = BigInteger
    cache_ok = True

    def process_bind_param(
        self,
        value: datetime.datetime | None,
        dialect: Dialect,
    ) -> int | None:
        if value is None:
            return None
        return datetime_to_epoch_us(value)

    def process_result_value(
        self,
        value: int | None,
        dialect: Dialect,
    ) -> datetime.datetime | None:
        if value is None:
            return None
        return epoch_us_to_datetime(value)


class NodeDaclRule(Base):
    """Persisted CEP-0002 compiled DACL rule (SSOT)."""

    __tablename__ = "dacl_rules"
    __table_args__ = (
        CheckConstraint("effect IN ('allow', 'deny')", name="ck_dacl_rules_effect"),
        CheckConstraint("permission_mask > 0", name="ck_dacl_rules_permission_mask"),
        CheckConstraint(
            "scope IN ('self', 'dirs', 'docs', 'all')", name="ck_dacl_rules_scope"
        ),
        CheckConstraint(
            "valid_from IS NULL OR valid_until IS NULL OR valid_from < valid_until",
            name="ck_dacl_rules_valid_window",
        ),
        Index("ix_dacl_rules_node_effect_scope", "node_id", "effect", "scope"),
        Index("ix_dacl_rules_validity", "node_id", "valid_from", "valid_until"),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    node_id: Mapped[str] = mapped_column(
        VARCHAR(255),
        ForeignKey("nodes.id", ondelete="CASCADE"),
        nullable=False,
        # NOTE: Index already defined in __table_args__; no need for
        # redundant `index=True`.
    )
    effect: Mapped[str] = mapped_column(VARCHAR(8), nullable=False)
    permission_mask: Mapped[int] = mapped_column(BigInteger, nullable=False)
    scope: Mapped[str] = mapped_column(VARCHAR(8), nullable=False)
    valid_from: Mapped[datetime.datetime | None] = mapped_column(
        UtcEpochMicros(), nullable=True
    )
    valid_until: Mapped[datetime.datetime | None] = mapped_column(
        UtcEpochMicros(), nullable=True
    )
    remark: Mapped[str | None] = mapped_column(Text, nullable=True)

    node: Mapped["Node"] = relationship("Node", back_populates="dacl_rules")
    clauses: Mapped[list["NodeDaclClause"]] = relationship(
        "NodeDaclClause",
        back_populates="rule",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="NodeDaclClause.id",
    )


class NodeDaclClause(Base):
    """Single DNF conjunction clause belonging to a NodeDaclRule."""

    __tablename__ = "dacl_rule_clauses"

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    rule_id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        ForeignKey("dacl_rules.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    rule: Mapped[NodeDaclRule] = relationship("NodeDaclRule", back_populates="clauses")
    atoms: Mapped[list["NodeDaclAtom"]] = relationship(
        "NodeDaclAtom",
        back_populates="clause",
        cascade="all, delete-orphan",
        passive_deletes=True,
        order_by="NodeDaclAtom.id",
    )


class NodeDaclAtom(Base):
    """Single predicate literal within a NodeDaclClause."""

    __tablename__ = "dacl_rule_atoms"
    __table_args__ = (
        CheckConstraint(
            "predicate_kind IN ('user', 'group', 'perm')",
            name="ck_dacl_rule_atoms_kind",
        ),
        Index(
            "ix_dacl_rule_atoms_principal",
            "predicate_kind",
            "predicate_value",
        ),
    )

    id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    clause_id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        ForeignKey("dacl_rule_clauses.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    predicate_kind: Mapped[str] = mapped_column(VARCHAR(16), nullable=False)
    predicate_value: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    is_negated: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)

    clause: Mapped[NodeDaclClause] = relationship(
        "NodeDaclClause", back_populates="atoms"
    )
