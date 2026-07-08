"""drop compiled access rule node id

Revision ID: 4f0e9a7b6c2d
Revises: d24c5a43025a
Create Date: 2026-07-08 18:25:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "4f0e9a7b6c2d"
down_revision: Union[str, Sequence[str], None] = "d24c5a43025a"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("compiled_access_rules", schema=None) as batch_op:
        batch_op.drop_constraint(
            batch_op.f("fk_compiled_access_rules_node_id_nodes"),
            type_="foreignkey",
        )
        batch_op.drop_index("ix_compiled_access_rules_node_id_access")
        batch_op.drop_index(batch_op.f("ix_compiled_access_rules_node_id"))
        batch_op.drop_column("node_id")


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("compiled_access_rules", schema=None) as batch_op:
        batch_op.add_column(sa.Column("node_id", sa.VARCHAR(length=255), nullable=True))

    op.execute(
        """
        UPDATE compiled_access_rules
        SET node_id = (
            SELECT compiled_access_rule_sets.node_id
            FROM compiled_access_rule_sets
            WHERE compiled_access_rule_sets.id = compiled_access_rules.rule_set_id
        )
        """
    )

    with op.batch_alter_table("compiled_access_rules", schema=None) as batch_op:
        batch_op.alter_column(
            "node_id",
            existing_type=sa.VARCHAR(length=255),
            nullable=False,
        )
        batch_op.create_index(
            batch_op.f("ix_compiled_access_rules_node_id"),
            ["node_id"],
            unique=False,
        )
        batch_op.create_index(
            "ix_compiled_access_rules_node_id_access",
            ["node_id", "access_type"],
            unique=False,
        )
        batch_op.create_foreign_key(
            batch_op.f("fk_compiled_access_rules_node_id_nodes"),
            "nodes",
            ["node_id"],
            ["id"],
            ondelete="CASCADE",
        )
