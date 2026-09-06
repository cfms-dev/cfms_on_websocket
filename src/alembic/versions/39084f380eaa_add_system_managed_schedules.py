"""add system-managed schedules

Revision ID: 39084f380eaa
Revises: 8c130010a943
Create Date: 2026-09-02 22:24:18.128009

"""
from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "39084f380eaa"
down_revision: str | Sequence[str] | None = "8c130010a943"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("schedules", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "system_managed",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch_op.alter_column(
            "created_by", existing_type=sa.VARCHAR(length=256), nullable=True
        )
        batch_op.alter_column(
            "updated_by", existing_type=sa.VARCHAR(length=256), nullable=True
        )
        batch_op.create_check_constraint(
            "ck_schedules_system_ownership",
            "(system_managed = true AND created_by IS NULL AND updated_by IS NULL) "
            "OR (system_managed = false AND created_by IS NOT NULL "
            "AND updated_by IS NOT NULL)",
        )


def downgrade() -> None:
    """Downgrade schema."""
    connection = op.get_bind()
    schedules = sa.table(
        "schedules",
        sa.column("id", sa.String()),
        sa.column("system_managed", sa.Boolean()),
    )
    executions = sa.table(
        "schedule_executions",
        sa.column("schedule_id", sa.String()),
    )
    system_schedule_ids = sa.select(schedules.c.id).where(
        schedules.c.system_managed == sa.true()
    )
    connection.execute(
        executions.delete().where(executions.c.schedule_id.in_(system_schedule_ids))
    )
    connection.execute(
        schedules.delete().where(schedules.c.system_managed == sa.true())
    )

    with op.batch_alter_table("schedules", schema=None) as batch_op:
        batch_op.drop_constraint("ck_schedules_system_ownership", type_="check")
        batch_op.alter_column(
            "updated_by", existing_type=sa.VARCHAR(length=256), nullable=False
        )
        batch_op.alter_column(
            "created_by", existing_type=sa.VARCHAR(length=256), nullable=False
        )
        batch_op.drop_column("system_managed")
