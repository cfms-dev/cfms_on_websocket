"""snapshot scheduled execution contracts

Revision ID: 3c496a214a87
Revises: 6dba0956fa9d
Create Date: 2026-09-07 19:11:46.092693

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "3c496a214a87"
down_revision: str | Sequence[str] | None = "6dba0956fa9d"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("schedule_executions", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("task_name", sa.VARCHAR(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column("task_contract_version", sa.Integer(), nullable=True)
        )
        batch_op.add_column(sa.Column("payload", sa.JSON(), nullable=True))

    schedules = sa.table(
        "schedules",
        sa.column("id", sa.VARCHAR(length=32)),
        sa.column("task_name", sa.VARCHAR(length=255)),
        sa.column("task_contract_version", sa.Integer()),
        sa.column("payload", sa.JSON()),
    )
    executions = sa.table(
        "schedule_executions",
        sa.column("schedule_id", sa.VARCHAR(length=32)),
        sa.column("task_name", sa.VARCHAR(length=255)),
        sa.column("task_contract_version", sa.Integer()),
        sa.column("payload", sa.JSON()),
    )
    op.get_bind().execute(
        executions.update().values(
            task_name=sa.select(schedules.c.task_name)
            .where(schedules.c.id == executions.c.schedule_id)
            .scalar_subquery(),
            task_contract_version=sa.select(schedules.c.task_contract_version)
            .where(schedules.c.id == executions.c.schedule_id)
            .scalar_subquery(),
            payload=sa.select(schedules.c.payload)
            .where(schedules.c.id == executions.c.schedule_id)
            .scalar_subquery(),
        )
    )

    with op.batch_alter_table("schedule_executions", schema=None) as batch_op:
        batch_op.alter_column(
            "task_name", existing_type=sa.VARCHAR(length=255), nullable=False
        )
        batch_op.alter_column(
            "task_contract_version", existing_type=sa.Integer(), nullable=False
        )
        batch_op.alter_column(
            "payload", existing_type=sa.JSON(), nullable=False
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("schedule_executions", schema=None) as batch_op:
        batch_op.drop_column("payload")
        batch_op.drop_column("task_contract_version")
        batch_op.drop_column("task_name")
