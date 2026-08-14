"""add user block reasons

Revision ID: 76f1c7621e23
Revises: b4b3061f385c
Create Date: 2026-08-14 10:52:29.992582

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "76f1c7621e23"
down_revision: str | Sequence[str] | None = "b4b3061f385c"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("userblock_entries", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "reason_comment_id",
                sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
                nullable=True,
            )
        )
        batch_op.create_foreign_key(
            batch_op.f("fk_userblock_entries_reason_comment_id_comments"),
            "comments",
            ["reason_comment_id"],
            ["comment_id"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("userblock_entries", schema=None) as batch_op:
        batch_op.drop_constraint(
            batch_op.f("fk_userblock_entries_reason_comment_id_comments"),
            type_="foreignkey",
        )
        batch_op.drop_column("reason_comment_id")
