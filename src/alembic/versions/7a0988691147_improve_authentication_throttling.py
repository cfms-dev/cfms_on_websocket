"""improve authentication throttling

Revision ID: 7a0988691147
Revises: 5be1fb8b72af
Create Date: 2026-07-23 23:54:38.450336

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "7a0988691147"
down_revision: str | Sequence[str] | None = "5be1fb8b72af"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "account_throttles",
        sa.Column("username", sa.String(length=64), nullable=False),
        sa.Column("factor", sa.String(length=16), nullable=False),
        sa.Column("failed_attempts", sa.Integer(), nullable=False),
        sa.Column("last_attempt", sa.DateTime(), nullable=False),
        sa.Column("locked_until", sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint(
            "username", "factor", name=op.f("pk_account_throttles")
        ),
    )
    with op.batch_alter_table("account_throttles", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_account_throttles_last_attempt"),
            ["last_attempt"],
            unique=False,
        )

    with op.batch_alter_table("login_throttles", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("window_started_at", sa.DateTime(), nullable=True)
        )
        batch_op.create_index(
            batch_op.f("ix_login_throttles_last_attempt"),
            ["last_attempt"],
            unique=False,
        )
    op.execute(
        sa.text(
            "UPDATE login_throttles "
            "SET window_started_at = last_attempt "
            "WHERE window_started_at IS NULL"
        )
    )
    with op.batch_alter_table("login_throttles", schema=None) as batch_op:
        batch_op.alter_column(
            "window_started_at", existing_type=sa.DateTime(), nullable=False
        )

    with op.batch_alter_table("traffic_throttles", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("window_started_at", sa.DateTime(), nullable=True)
        )
        batch_op.create_index(
            batch_op.f("ix_traffic_throttles_last_attempt"),
            ["last_attempt"],
            unique=False,
        )
    op.execute(
        sa.text(
            "UPDATE traffic_throttles "
            "SET window_started_at = last_attempt "
            "WHERE window_started_at IS NULL"
        )
    )
    with op.batch_alter_table("traffic_throttles", schema=None) as batch_op:
        batch_op.alter_column(
            "window_started_at", existing_type=sa.DateTime(), nullable=False
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("traffic_throttles", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_traffic_throttles_last_attempt"))
        batch_op.drop_column("window_started_at")

    with op.batch_alter_table("login_throttles", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_login_throttles_last_attempt"))
        batch_op.drop_column("window_started_at")

    with op.batch_alter_table("account_throttles", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_account_throttles_last_attempt"))

    op.drop_table("account_throttles")
