"""Add persistent options.

Revision ID: 2a32581dc561
Revises: 0460356a5ba6
"""

import sqlalchemy as sa
from alembic import op

revision = "2a32581dc561"
down_revision = "0460356a5ba6"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "options",
        sa.Column("owner", sa.VARCHAR(255), nullable=False),
        sa.Column("option_key", sa.VARCHAR(128), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("updated_at", sa.Double(), nullable=False),
        sa.CheckConstraint("revision > 0", name="ck_options_revision_positive"),
        sa.CheckConstraint("schema_version > 0", name="ck_options_schema_version_positive"),
        sa.PrimaryKeyConstraint("owner", "option_key", name=op.f("pk_options")),
    )


def downgrade() -> None:
    options = sa.table("options")
    if op.get_bind().execute(sa.select(sa.literal(1)).select_from(options).limit(1)).first():
        raise RuntimeError("Cannot downgrade while options contains persistent configuration")
    op.drop_table("options")
