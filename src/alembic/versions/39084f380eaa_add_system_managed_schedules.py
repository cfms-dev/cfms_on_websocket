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
        batch_op.drop_constraint(
            "fk_schedules_created_by_users", type_="foreignkey"
        )
        batch_op.drop_constraint(
            "fk_schedules_updated_by_users", type_="foreignkey"
        )
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
        batch_op.create_foreign_key(
            "fk_schedules_created_by_users",
            "users",
            ["created_by"],
            ["username"],
            ondelete="SET NULL",
        )
        batch_op.create_foreign_key(
            "fk_schedules_updated_by_users",
            "users",
            ["updated_by"],
            ["username"],
            ondelete="SET NULL",
        )


def downgrade() -> None:
    """Downgrade schema."""
    connection = op.get_bind()
    schedules = sa.table(
        "schedules",
        sa.column("id", sa.String()),
        sa.column("system_managed", sa.Boolean()),
        sa.column("created_by", sa.String()),
        sa.column("updated_by", sa.String()),
    )
    executions = sa.table(
        "schedule_executions",
        sa.column("schedule_id", sa.String()),
    )
    incompatible_schedule_filter = sa.or_(
        schedules.c.system_managed == sa.true(),
        schedules.c.created_by.is_(None),
        schedules.c.updated_by.is_(None),
    )
    incompatible_schedule_ids = sa.select(schedules.c.id).where(
        incompatible_schedule_filter
    )
    connection.execute(
        executions.delete().where(
            executions.c.schedule_id.in_(incompatible_schedule_ids)
        )
    )
    connection.execute(
        schedules.delete().where(incompatible_schedule_filter)
    )

    with op.batch_alter_table("schedules", schema=None) as batch_op:
        batch_op.drop_constraint(
            "fk_schedules_created_by_users", type_="foreignkey"
        )
        batch_op.drop_constraint(
            "fk_schedules_updated_by_users", type_="foreignkey"
        )
        batch_op.alter_column(
            "updated_by", existing_type=sa.VARCHAR(length=256), nullable=False
        )
        batch_op.alter_column(
            "created_by", existing_type=sa.VARCHAR(length=256), nullable=False
        )
        batch_op.create_foreign_key(
            "fk_schedules_created_by_users",
            "users",
            ["created_by"],
            ["username"],
        )
        batch_op.create_foreign_key(
            "fk_schedules_updated_by_users",
            "users",
            ["updated_by"],
            ["username"],
        )
        batch_op.drop_column("system_managed")
