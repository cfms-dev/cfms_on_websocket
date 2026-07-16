"""store comment digests as binary

Revision ID: 5be1fb8b72af
Revises: 6aabc2bce71c
Create Date: 2026-07-16 10:49:11.989834

"""

import re
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import mysql


# revision identifiers, used by Alembic.
revision: str = "5be1fb8b72af"
down_revision: str | Sequence[str] | None = "6aabc2bce71c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

BATCH_SIZE = 1_000
BINARY_DIGEST_TYPE = sa.LargeBinary(32).with_variant(mysql.BINARY(32), "mysql")
HEX_DIGEST_PATTERN = re.compile(r"[0-9a-fA-F]{64}")


def _comments_table(*columns: sa.Column) -> sa.TableClause:
    return sa.table("comments", *columns)


def _status_comment_references() -> list[dict[str, object]]:
    users = sa.table(
        "users",
        sa.column("username", sa.String()),
        sa.column("status_comment_id", sa.BigInteger()),
    )
    rows = (
        op.get_bind()
        .execute(
            sa.select(users.c.username, users.c.status_comment_id).where(
                users.c.status_comment_id.is_not(None)
            )
        )
        .mappings()
    )
    return [dict(row) for row in rows]


def _restore_status_comment_references(
    references: list[dict[str, object]],
) -> None:
    if not references:
        return
    users = sa.table(
        "users",
        sa.column("username", sa.String()),
        sa.column("status_comment_id", sa.BigInteger()),
    )
    op.get_bind().execute(
        sa.update(users)
        .where(users.c.username == sa.bindparam("b_username"))
        .values(status_comment_id=sa.bindparam("b_status_comment_id")),
        [
            {
                "b_username": reference["username"],
                "b_status_comment_id": reference["status_comment_id"],
            }
            for reference in references
        ],
    )


def _backfill_binary_digests() -> None:
    comments = _comments_table(
        sa.column("comment_id", sa.BigInteger()),
        sa.column("digest_version", sa.SmallInteger()),
        sa.column("content_digest", sa.String(64)),
        sa.column("content_digest_binary", BINARY_DIGEST_TYPE),
    )
    connection = op.get_bind()
    rows = (
        connection.execute(
            sa.select(
                comments.c.comment_id,
                comments.c.digest_version,
                comments.c.content_digest,
            ).order_by(comments.c.comment_id)
        )
        .mappings()
    )
    seen: set[tuple[int, bytes]] = set()

    while batch := rows.fetchmany(BATCH_SIZE):
        updates = []
        for row in batch:
            digest = row["content_digest"]
            if not isinstance(digest, str) or not HEX_DIGEST_PATTERN.fullmatch(digest):
                raise RuntimeError(
                    f"Invalid hexadecimal comment digest for ID {row['comment_id']}"
                )
            binary_digest = bytes.fromhex(digest)
            key = (row["digest_version"], binary_digest)
            if key in seen:
                raise RuntimeError(
                    "Duplicate comment digest after binary conversion for "
                    f"version {row['digest_version']}"
                )
            seen.add(key)
            updates.append(
                {
                    "b_comment_id": row["comment_id"],
                    "b_content_digest": binary_digest,
                }
            )

        connection.execute(
            sa.update(comments)
            .where(comments.c.comment_id == sa.bindparam("b_comment_id"))
            .values(content_digest_binary=sa.bindparam("b_content_digest")),
            updates,
        )


def _backfill_hex_digests() -> None:
    comments = _comments_table(
        sa.column("comment_id", sa.BigInteger()),
        sa.column("content_digest", BINARY_DIGEST_TYPE),
        sa.column("content_digest_hex", sa.String(64)),
    )
    connection = op.get_bind()
    rows = (
        connection.execute(
            sa.select(comments.c.comment_id, comments.c.content_digest).order_by(
                comments.c.comment_id
            )
        )
        .mappings()
    )

    while batch := rows.fetchmany(BATCH_SIZE):
        updates = []
        for row in batch:
            digest = row["content_digest"]
            if not isinstance(digest, (bytes, bytearray, memoryview)):
                raise RuntimeError(
                    f"Invalid binary comment digest for ID {row['comment_id']}"
                )
            binary_digest = bytes(digest)
            if len(binary_digest) != 32:
                raise RuntimeError(
                    f"Invalid binary comment digest length for ID {row['comment_id']}"
                )
            updates.append(
                {
                    "b_comment_id": row["comment_id"],
                    "b_content_digest": binary_digest.hex(),
                }
            )

        connection.execute(
            sa.update(comments)
            .where(comments.c.comment_id == sa.bindparam("b_comment_id"))
            .values(content_digest_hex=sa.bindparam("b_content_digest")),
            updates,
        )


def upgrade() -> None:
    """Upgrade schema."""
    references = _status_comment_references()
    with op.batch_alter_table("comments", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("content_digest_binary", BINARY_DIGEST_TYPE, nullable=True)
        )

    _backfill_binary_digests()

    with op.batch_alter_table("comments", schema=None) as batch_op:
        batch_op.drop_constraint("uq_comments_content_digest", type_="unique")
        batch_op.drop_column("content_digest")

    with op.batch_alter_table("comments", schema=None) as batch_op:
        batch_op.alter_column(
            "content_digest_binary",
            new_column_name="content_digest",
            existing_type=BINARY_DIGEST_TYPE,
            nullable=False,
        )

    with op.batch_alter_table("comments", schema=None) as batch_op:
        batch_op.create_unique_constraint(
            "uq_comments_content_digest",
            ["digest_version", "content_digest"],
        )
    _restore_status_comment_references(references)


def downgrade() -> None:
    """Downgrade schema."""
    references = _status_comment_references()
    with op.batch_alter_table("comments", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("content_digest_hex", sa.String(64), nullable=True)
        )

    _backfill_hex_digests()

    with op.batch_alter_table("comments", schema=None) as batch_op:
        batch_op.drop_constraint("uq_comments_content_digest", type_="unique")
        batch_op.drop_column("content_digest")

    with op.batch_alter_table("comments", schema=None) as batch_op:
        batch_op.alter_column(
            "content_digest_hex",
            new_column_name="content_digest",
            existing_type=sa.String(64),
            nullable=False,
        )

    with op.batch_alter_table("comments", schema=None) as batch_op:
        batch_op.create_unique_constraint(
            "uq_comments_content_digest",
            ["digest_version", "content_digest"],
        )
    _restore_status_comment_references(references)
