"""add namespaced persistent options

Revision ID: 16c86712512a
Revises: 03197fed3401
Create Date: 2026-11-11 19:41:15.122936

"""

import sqlalchemy as sa
from sqlalchemy.dialects import mysql

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "16c86712512a"
down_revision: str | None = "03197fed3401"
branch_labels: str | tuple[str, ...] | None = None
depends_on: str | tuple[str, ...] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "options",
        sa.Column("namespace", sa.VARCHAR(length=111), nullable=False),
        sa.Column("owner", sa.VARCHAR(length=255), nullable=False),
        sa.Column("option_key", sa.VARCHAR(length=128), nullable=False),
        sa.Column("schema_version", sa.Integer(), nullable=False),
        sa.Column("revision", sa.BigInteger(), nullable=False),
        sa.Column("value_type", sa.VARCHAR(length=8), nullable=False),
        sa.Column(
            "option_value",
            sa.Text().with_variant(mysql.LONGTEXT(), "mysql"),
            nullable=False,
        ),
        sa.Column("updated_at", sa.Double(), nullable=False),
        sa.CheckConstraint(
            "value_type IN ('str', 'int', 'float', 'bool', 'null', 'json')",
            name="ck_options_value_type",
        ),
        sa.CheckConstraint("revision > 0", name="ck_options_revision_positive"),
        sa.CheckConstraint("schema_version > 0", name="ck_options_schema_version_positive"),
        sa.PrimaryKeyConstraint("namespace", "option_key", name=op.f("pk_options")),
    )
    op.create_index("ix_options_owner", "options", ["owner"], unique=False)



def downgrade() -> None:
    """Downgrade schema."""
    connection = op.get_bind()
    if connection.execute(sa.text("SELECT 1 FROM options LIMIT 1")).first():
        raise RuntimeError("Cannot drop persistent configuration; export and remove options explicitly before downgrading")
    states = sa.table("system_states", sa.column("owner"), sa.column("state_key"))
    connection.execute(
        states.delete().where(
            states.c.owner == "core",
            states.c.state_key.startswith("options_revision.", autoescape=True),
        )
    )
    op.drop_index("ix_options_owner", table_name="options")
    op.drop_table("options")
