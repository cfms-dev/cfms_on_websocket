"""index permission entry expiry

Revision ID: f239d439f893
Revises: 76f1c7621e23
Create Date: 2026-08-21 19:21:23.678471

"""
from collections.abc import Sequence

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "f239d439f893"
down_revision: str | Sequence[str] | None = "76f1c7621e23"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("group_permissions", schema=None) as batch_op:
        batch_op.create_index(
            "ix_group_permissions_end_time_id",
            ["end_time", "id"],
            unique=False,
        )

    with op.batch_alter_table("user_permissions", schema=None) as batch_op:
        batch_op.create_index(
            "ix_user_permissions_end_time_id",
            ["end_time", "id"],
            unique=False,
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("user_permissions", schema=None) as batch_op:
        batch_op.drop_index("ix_user_permissions_end_time_id")

    with op.batch_alter_table("group_permissions", schema=None) as batch_op:
        batch_op.drop_index("ix_group_permissions_end_time_id")
