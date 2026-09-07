"""add scheduling dispatch timestamps

Revision ID: 6dba0956fa9d
Revises: adc1283fb393
Create Date: 2026-09-07 19:05:31.413040

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "6dba0956fa9d"
down_revision: str | Sequence[str] | None = "adc1283fb393"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("schedule_executions", schema=None) as batch_op:
        batch_op.add_column(sa.Column("dispatched_at", sa.Double(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("schedule_executions", schema=None) as batch_op:
        batch_op.drop_column("dispatched_at")
