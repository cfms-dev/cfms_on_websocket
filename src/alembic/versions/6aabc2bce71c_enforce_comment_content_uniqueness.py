"""enforce comment content uniqueness

Revision ID: 6aabc2bce71c
Revises: 6664804d2860
Create Date: 2026-07-15 22:51:18.766505

"""
import hashlib
import zlib
from collections.abc import Sequence

import orjson
import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "6aabc2bce71c"
down_revision: str | Sequence[str] | None = "6664804d2860"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DIGEST_VERSION = 1


def _serialize(text: str, data: dict[str, object] | None) -> bytes:
    return orjson.dumps({"data": data, "text": text}, option=orjson.OPT_SORT_KEYS)


def _content_digest(serialized: bytes) -> str:
    namespace = f"cfms-comment:v{DIGEST_VERSION}\0".encode()
    return hashlib.sha256(namespace + serialized).hexdigest()


def _legacy_hash(serialized: bytes) -> int:
    unsigned_hash = zlib.crc32(serialized)
    return unsigned_hash if unsigned_hash < 2**31 else unsigned_hash - 2**32


def _comments_table(*columns: sa.Column) -> sa.TableClause:
    return sa.table("comments", *columns)


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("comments", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("digest_version", sa.SmallInteger(), nullable=True)
        )
        batch_op.add_column(
            sa.Column("content_digest", sa.String(length=64), nullable=True)
        )

    comments = _comments_table(
        sa.column("comment_id", sa.BigInteger()),
        sa.column("digest_version", sa.SmallInteger()),
        sa.column("content_digest", sa.String(length=64)),
        sa.column("comment_text", sa.Text()),
        sa.column("comment_data", sa.JSON()),
    )
    users = sa.table(
        "users",
        sa.column("status_comment_id", sa.BigInteger()),
    )
    connection = op.get_bind()
    rows = (
        connection.execute(
            sa.select(
                comments.c.comment_id,
                comments.c.comment_text,
                comments.c.comment_data,
            ).order_by(comments.c.comment_id)
        )
        .mappings()
        .all()
    )
    seen: dict[str, tuple[int, bytes]] = {}

    for row in rows:
        serialized = _serialize(row["comment_text"], row["comment_data"])
        content_digest = _content_digest(serialized)
        existing = seen.get(content_digest)
        if existing is not None:
            existing_id, existing_serialized = existing
            if existing_serialized != serialized:
                raise RuntimeError(
                    f"Comment digest collision during migration: {content_digest}"
                )
            connection.execute(
                sa.update(users)
                .where(users.c.status_comment_id == row["comment_id"])
                .values(status_comment_id=existing_id)
            )
            connection.execute(
                sa.delete(comments).where(
                    comments.c.comment_id == row["comment_id"]
                )
            )
            continue

        seen[content_digest] = (row["comment_id"], serialized)
        connection.execute(
            sa.update(comments)
            .where(comments.c.comment_id == row["comment_id"])
            .values(
                digest_version=DIGEST_VERSION,
                content_digest=content_digest,
            )
        )

    with op.batch_alter_table("comments", schema=None) as batch_op:
        batch_op.alter_column(
            "digest_version",
            existing_type=sa.SmallInteger(),
            nullable=False,
        )
        batch_op.alter_column(
            "content_digest",
            existing_type=sa.String(length=64),
            nullable=False,
        )
        batch_op.drop_index(batch_op.f("ix_comments_comment_hash"))
        batch_op.create_unique_constraint(
            "uq_comments_content_digest",
            ["digest_version", "content_digest"],
        )
        batch_op.drop_column("comment_hash")


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("comments", schema=None) as batch_op:
        batch_op.add_column(sa.Column("comment_hash", sa.Integer(), nullable=True))
        batch_op.drop_constraint("uq_comments_content_digest", type_="unique")

    comments = _comments_table(
        sa.column("comment_id", sa.BigInteger()),
        sa.column("comment_hash", sa.Integer()),
        sa.column("comment_text", sa.Text()),
        sa.column("comment_data", sa.JSON()),
    )
    connection = op.get_bind()
    rows = (
        connection.execute(
            sa.select(
                comments.c.comment_id,
                comments.c.comment_text,
                comments.c.comment_data,
            )
        )
        .mappings()
        .all()
    )
    for row in rows:
        serialized = _serialize(row["comment_text"], row["comment_data"])
        connection.execute(
            sa.update(comments)
            .where(comments.c.comment_id == row["comment_id"])
            .values(comment_hash=_legacy_hash(serialized))
        )

    with op.batch_alter_table("comments", schema=None) as batch_op:
        batch_op.alter_column(
            "comment_hash",
            existing_type=sa.Integer(),
            nullable=False,
        )
        batch_op.create_index(
            batch_op.f("ix_comments_comment_hash"),
            ["comment_hash"],
            unique=False,
        )
        batch_op.drop_column("content_digest")
        batch_op.drop_column("digest_version")
