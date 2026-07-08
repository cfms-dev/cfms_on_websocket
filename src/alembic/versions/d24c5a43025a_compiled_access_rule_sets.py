"""compiled access rule sets

Revision ID: d24c5a43025a
Revises: 96916de60390
Create Date: 2026-07-08 13:46:50.472538

"""
import secrets
import time
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "d24c5a43025a"
down_revision: Union[str, Sequence[str], None] = "96916de60390"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "compiled_access_rule_sets",
        sa.Column("id", sa.VARCHAR(length=32), nullable=False),
        sa.Column("node_id", sa.VARCHAR(length=255), nullable=False),
        sa.Column("created_at", sa.Float(), nullable=False),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["nodes.id"],
            name=op.f("fk_compiled_access_rule_sets_node_id_nodes"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compiled_access_rule_sets")),
    )
    with op.batch_alter_table("compiled_access_rule_sets", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_compiled_access_rule_sets_node_id"),
            ["node_id"],
            unique=False,
        )

    with op.batch_alter_table("nodes", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column(
                "active_access_rule_set_id",
                sa.VARCHAR(length=32),
                nullable=True,
            )
        )

    with op.batch_alter_table("compiled_access_rules", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("rule_set_id", sa.VARCHAR(length=32), nullable=True)
        )
        batch_op.create_index(
            batch_op.f("ix_compiled_access_rules_rule_set_id"),
            ["rule_set_id"],
            unique=False,
        )

    _backfill_rule_sets()

    with op.batch_alter_table("compiled_access_rules", schema=None) as batch_op:
        batch_op.alter_column(
            "rule_set_id",
            existing_type=sa.VARCHAR(length=32),
            nullable=False,
        )
        batch_op.create_foreign_key(
            batch_op.f(
                "fk_compiled_access_rules_rule_set_id_compiled_access_rule_sets"
            ),
            "compiled_access_rule_sets",
            ["rule_set_id"],
            ["id"],
            ondelete="CASCADE",
        )

    with op.batch_alter_table("nodes", schema=None) as batch_op:
        batch_op.create_foreign_key(
            "fk_nodes_active_access_rule_set_id_compiled_access_rule_sets",
            "compiled_access_rule_sets",
            ["active_access_rule_set_id"],
            ["id"],
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("nodes", schema=None) as batch_op:
        batch_op.drop_constraint(
            "fk_nodes_active_access_rule_set_id_compiled_access_rule_sets",
            type_="foreignkey",
        )
        batch_op.drop_column("active_access_rule_set_id")

    with op.batch_alter_table("compiled_access_rules", schema=None) as batch_op:
        batch_op.drop_constraint(
            batch_op.f(
                "fk_compiled_access_rules_rule_set_id_compiled_access_rule_sets"
            ),
            type_="foreignkey",
        )
        batch_op.drop_index(batch_op.f("ix_compiled_access_rules_rule_set_id"))
        batch_op.drop_column("rule_set_id")

    with op.batch_alter_table("compiled_access_rule_sets", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_compiled_access_rule_sets_node_id"))
    op.drop_table("compiled_access_rule_sets")


def _backfill_rule_sets() -> None:
    conn = op.get_bind()
    metadata = sa.MetaData()
    nodes = sa.Table(
        "nodes",
        metadata,
        sa.Column("id", sa.String()),
        sa.Column("active_access_rule_set_id", sa.String()),
    )
    rule_sets = sa.Table(
        "compiled_access_rule_sets",
        metadata,
        sa.Column("id", sa.String()),
        sa.Column("node_id", sa.String()),
        sa.Column("created_at", sa.Float()),
    )
    rules = sa.Table(
        "compiled_access_rules",
        metadata,
        sa.Column("id", sa.Integer()),
        sa.Column("node_id", sa.String()),
        sa.Column("rule_set_id", sa.String()),
    )

    node_ids = [
        row[0]
        for row in conn.execute(
            sa.select(rules.c.node_id)
            .select_from(rules.join(nodes, rules.c.node_id == nodes.c.id))
            .distinct()
            .order_by(rules.c.node_id)
        )
    ]
    for node_id in node_ids:
        rule_set_id = secrets.token_hex(16)
        conn.execute(
            rule_sets.insert().values(
                id=rule_set_id,
                node_id=node_id,
                created_at=time.time(),
            )
        )
        conn.execute(
            rules.update()
            .where(rules.c.node_id == node_id)
            .values(rule_set_id=rule_set_id)
        )
        conn.execute(
            nodes.update()
            .where(nodes.c.id == node_id)
            .values(active_access_rule_set_id=rule_set_id)
        )
