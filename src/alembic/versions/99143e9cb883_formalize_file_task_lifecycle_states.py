"""formalize file task lifecycle states.

Revision ID: 99143e9cb883
Revises: fe8863687aa4
Create Date: 2026-07-27 21:47:54.943145

"""
import time
from collections.abc import Sequence

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "99143e9cb883"
down_revision: str | Sequence[str] | None = "fe8863687aa4"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    grace_deadline = time.time() + 86400
    op.execute(
        "UPDATE file_tasks SET end_time = "
        f"CASE WHEN end_time IS NULL OR end_time < {grace_deadline!r} "
        f"THEN {grace_deadline!r} ELSE end_time END "
        "WHERE mode = 1 AND status = 0"
    )
    with op.batch_alter_table("file_tasks") as batch_op:
        batch_op.create_check_constraint(
            "ck_file_tasks_status_value", "status IN (0, 1, 2, 3, 4)"
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("file_tasks") as batch_op:
        batch_op.drop_constraint("ck_file_tasks_status_value", type_="check")
