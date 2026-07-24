"""reuse comments for banned subnet reasons

Revision ID: 18adc63ce5b1
Revises: 052c13c19603
Create Date: 2026-07-24 21:25:16.632684

"""

import hashlib
from collections.abc import Sequence

import orjson
import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "18adc63ce5b1"
down_revision: str | Sequence[str] | None = "052c13c19603"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DIGEST_VERSION = 1


def _serialize(text: str, data: dict[str, object] | None = None) -> bytes:
    return orjson.dumps({"data": data, "text": text}, option=orjson.OPT_SORT_KEYS)


def _content_digest(serialized: bytes) -> bytes:
    namespace = f"cfms-comment:v{DIGEST_VERSION}\0".encode()
    return hashlib.sha256(namespace + serialized).digest()


def _comments_table() -> sa.TableClause:
    return sa.table(
        "comments",
        sa.column("comment_id", sa.BigInteger()),
        sa.column("digest_version", sa.SmallInteger()),
        sa.column("content_digest", sa.LargeBinary(32)),
        sa.column("comment_text", sa.Text()),
        sa.column("comment_data", sa.JSON()),
    )


def _banned_subnets_table(*columns) -> sa.TableClause:
    return sa.table("banned_subnets", *columns)


def _get_or_create_comment_id(text: str) -> int:
    connection = op.get_bind()
    comments = _comments_table()
    serialized = _serialize(text)
    content_digest = _content_digest(serialized)
    statement = sa.select(comments).where(
        comments.c.digest_version == DIGEST_VERSION,
        comments.c.content_digest == content_digest,
    )
    row = connection.execute(statement).mappings().one_or_none()
    if row is None:
        connection.execute(
            sa.insert(comments).values(
                digest_version=DIGEST_VERSION,
                content_digest=content_digest,
                comment_text=text,
                comment_data=None,
            )
        )
        row = connection.execute(statement).mappings().one()
    if _serialize(row["comment_text"], row["comment_data"]) != serialized:
        raise RuntimeError("Comment content digest matched different stored content")
    return row["comment_id"]


def _backfill_comment_references() -> None:
    banned_subnets = _banned_subnets_table(
        sa.column("subnet", sa.String(128)),
        sa.column("reason", sa.String(255)),
        sa.column("reason_comment_id", sa.BigInteger()),
    )
    connection = op.get_bind()
    rows = connection.execute(
        sa.select(banned_subnets.c.subnet, banned_subnets.c.reason).where(
            banned_subnets.c.reason.is_not(None)
        )
    ).mappings()
    comment_ids: dict[str, int] = {}
    for row in rows:
        reason = row["reason"]
        comment_id = comment_ids.get(reason)
        if comment_id is None:
            comment_id = _get_or_create_comment_id(reason)
            comment_ids[reason] = comment_id
        connection.execute(
            sa.update(banned_subnets)
            .where(banned_subnets.c.subnet == row["subnet"])
            .values(reason_comment_id=comment_id)
        )


def _restore_reasons() -> None:
    banned_subnets = _banned_subnets_table(
        sa.column("subnet", sa.String(128)),
        sa.column("reason", sa.String(255)),
        sa.column("reason_comment_id", sa.BigInteger()),
    )
    comments = _comments_table()
    connection = op.get_bind()
    rows = connection.execute(
        sa.select(banned_subnets.c.subnet, comments.c.comment_text)
        .select_from(
            banned_subnets.join(
                comments,
                banned_subnets.c.reason_comment_id == comments.c.comment_id,
            )
        )
        .where(banned_subnets.c.reason_comment_id.is_not(None))
    ).mappings()
    for row in rows:
        reason = row["comment_text"]
        if len(reason) > 255:
            raise RuntimeError(
                "Banned subnet reason exceeds the legacy 255-character limit"
            )
        connection.execute(
            sa.update(banned_subnets)
            .where(banned_subnets.c.subnet == row["subnet"])
            .values(reason=reason)
        )


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("banned_subnets", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "reason_comment_id",
                sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
                nullable=True,
            )
        )
        batch_op.create_foreign_key(
            batch_op.f("fk_banned_subnets_reason_comment_id_comments"),
            "comments",
            ["reason_comment_id"],
            ["comment_id"],
            ondelete="SET NULL",
        )

    _backfill_comment_references()

    with op.batch_alter_table("banned_subnets", schema=None) as batch_op:
        batch_op.drop_column("reason")


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("banned_subnets", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("reason", sa.String(length=255), nullable=True)
        )

    _restore_reasons()

    with op.batch_alter_table("banned_subnets", schema=None) as batch_op:
        batch_op.drop_constraint(
            batch_op.f("fk_banned_subnets_reason_comment_id_comments"),
            type_="foreignkey",
        )
        batch_op.drop_column("reason_comment_id")
