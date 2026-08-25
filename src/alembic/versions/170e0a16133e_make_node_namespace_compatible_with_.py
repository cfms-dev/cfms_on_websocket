"""make node namespace compatible with mysql

Revision ID: 170e0a16133e
Revises: f239d439f893
Create Date: 2026-08-25 22:47:17.174266

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "170e0a16133e"
down_revision: str | Sequence[str] | None = "f239d439f893"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    columns = {
        column["name"]
        for column in sa.inspect(op.get_bind()).get_columns("nodes")
    }
    if "active_name" in columns:
        return
    if "active_parent_id" not in columns:
        raise RuntimeError(
            "Cannot migrate the node namespace: neither the legacy "
            "active_parent_id column nor active_name exists"
        )

    with op.batch_alter_table(
        "nodes", schema=None, recreate="always"
    ) as batch_op:
        batch_op.drop_constraint("uq_nodes_active_parent_name", type_="unique")
        batch_op.drop_column("active_parent_id")
        batch_op.add_column(
            sa.Column(
                "active_name",
                sa.VARCHAR(length=255),
                sa.Computed(
                    "CASE WHEN status = 1 THEN NULL ELSE name END",
                    persisted=True,
                ),
                nullable=True,
            )
        )
        batch_op.create_unique_constraint(
            "uq_nodes_active_parent_name",
            ["parent_id", "active_name"],
        )


def downgrade() -> None:
    """Downgrade schema."""
    connection = op.get_bind()
    columns = {
        column["name"]
        for column in sa.inspect(connection).get_columns("nodes")
    }
    if "active_parent_id" in columns:
        return
    if "active_name" not in columns:
        raise RuntimeError(
            "Cannot downgrade the node namespace: neither active_name nor the "
            "legacy active_parent_id column exists"
        )
    if connection.dialect.name == "mysql":
        raise RuntimeError(
            "Cannot restore the legacy node namespace on MySQL because its "
            "generated column is incompatible with the cascading parent foreign key"
        )

    with op.batch_alter_table(
        "nodes", schema=None, recreate="always"
    ) as batch_op:
        batch_op.drop_constraint("uq_nodes_active_parent_name", type_="unique")
        batch_op.drop_column("active_name")
        batch_op.add_column(
            sa.Column(
                "active_parent_id",
                sa.VARCHAR(length=255),
                sa.Computed(
                    "CASE WHEN status = 1 THEN NULL ELSE parent_id END",
                    persisted=True,
                ),
                nullable=True,
            )
        )
        batch_op.create_unique_constraint(
            "uq_nodes_active_parent_name",
            ["active_parent_id", "name"],
        )
