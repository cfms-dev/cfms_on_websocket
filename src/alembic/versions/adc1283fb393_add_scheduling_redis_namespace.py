"""add scheduling redis namespace

Revision ID: adc1283fb393
Revises: 39084f380eaa
Create Date: 2026-09-07 13:29:40.753289

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "adc1283fb393"
down_revision: str | Sequence[str] | None = "39084f380eaa"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("scheduling_runtime_state", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("redis_namespace", sa.VARCHAR(length=63), nullable=True)
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("scheduling_runtime_state", schema=None) as batch_op:
        batch_op.drop_column("redis_namespace")
