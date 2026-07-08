"""node inheritance for compiled rules

Revision ID: 96916de60390
Revises: 3c105b0f959d
Create Date: 2026-07-08 12:43:18.081173

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "96916de60390"
down_revision: Union[str, Sequence[str], None] = "3c105b0f959d"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "nodes",
        sa.Column("id", sa.VARCHAR(length=255), nullable=False),
        sa.Column("type", sa.VARCHAR(length=16), nullable=False),
        sa.Column("inherit", sa.Boolean(), nullable=False),
        sa.Column("status", sa.Integer(), nullable=False),
        sa.Column("status_operation_id", sa.VARCHAR(length=255), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_nodes")),
    )
    with op.batch_alter_table("nodes", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_nodes_status_operation_id"),
            ["status_operation_id"],
            unique=False,
        )
        batch_op.create_index(batch_op.f("ix_nodes_type"), ["type"], unique=False)

    _raise_for_duplicate_node_ids()
    _backfill_nodes()
    _delete_orphan_compiled_rules()

    with op.batch_alter_table("compiled_access_rules", schema=None) as batch_op:
        batch_op.add_column(sa.Column("node_id", sa.VARCHAR(length=255), nullable=True))

    op.execute("UPDATE compiled_access_rules SET node_id = target_id")

    with op.batch_alter_table("compiled_access_rules", schema=None) as batch_op:
        batch_op.alter_column(
            "node_id",
            existing_type=sa.VARCHAR(length=255),
            nullable=False,
        )
        batch_op.drop_index(batch_op.f("ix_compiled_access_rules_target_id"))
        batch_op.drop_index(batch_op.f("ix_compiled_access_rules_target_type"))
        batch_op.drop_index("ix_compiled_access_rules_target_type_id_access")
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
        batch_op.drop_column("target_type")
        batch_op.drop_column("target_id")

    with op.batch_alter_table("documents", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_documents_status_operation_id"))
        batch_op.create_foreign_key(
            batch_op.f("fk_documents_id_nodes"),
            "nodes",
            ["id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.drop_column("status")
        batch_op.drop_column("status_operation_id")
        batch_op.drop_column("inherit")

    with op.batch_alter_table("folders", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_folders_status_operation_id"))
        batch_op.create_foreign_key(
            batch_op.f("fk_folders_id_nodes"),
            "nodes",
            ["id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.drop_column("status")
        batch_op.drop_column("status_operation_id")
        batch_op.drop_column("inherit")


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("folders", schema=None) as batch_op:
        batch_op.add_column(sa.Column("inherit", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("status", sa.Integer(), nullable=True))
        batch_op.add_column(
            sa.Column("status_operation_id", sa.VARCHAR(length=255), nullable=True)
        )

    with op.batch_alter_table("documents", schema=None) as batch_op:
        batch_op.add_column(sa.Column("inherit", sa.Boolean(), nullable=True))
        batch_op.add_column(sa.Column("status", sa.Integer(), nullable=True))
        batch_op.add_column(
            sa.Column("status_operation_id", sa.VARCHAR(length=255), nullable=True)
        )

    op.execute(
        """
        UPDATE folders
        SET inherit = (
                SELECT nodes.inherit FROM nodes WHERE nodes.id = folders.id
            ),
            status = (
                SELECT nodes.status FROM nodes WHERE nodes.id = folders.id
            ),
            status_operation_id = (
                SELECT nodes.status_operation_id FROM nodes WHERE nodes.id = folders.id
            )
        """
    )
    op.execute(
        """
        UPDATE documents
        SET inherit = (
                SELECT nodes.inherit FROM nodes WHERE nodes.id = documents.id
            ),
            status = (
                SELECT nodes.status FROM nodes WHERE nodes.id = documents.id
            ),
            status_operation_id = (
                SELECT nodes.status_operation_id FROM nodes WHERE nodes.id = documents.id
            )
        """
    )

    with op.batch_alter_table("folders", schema=None) as batch_op:
        batch_op.alter_column(
            "inherit", existing_type=sa.Boolean(), nullable=False
        )
        batch_op.alter_column("status", existing_type=sa.Integer(), nullable=False)
        batch_op.drop_constraint(
            batch_op.f("fk_folders_id_nodes"),
            type_="foreignkey",
        )
        batch_op.create_index(
            batch_op.f("ix_folders_status_operation_id"),
            ["status_operation_id"],
            unique=False,
        )

    with op.batch_alter_table("documents", schema=None) as batch_op:
        batch_op.alter_column(
            "inherit", existing_type=sa.Boolean(), nullable=False
        )
        batch_op.alter_column("status", existing_type=sa.Integer(), nullable=False)
        batch_op.drop_constraint(
            batch_op.f("fk_documents_id_nodes"),
            type_="foreignkey",
        )
        batch_op.create_index(
            batch_op.f("ix_documents_status_operation_id"),
            ["status_operation_id"],
            unique=False,
        )

    with op.batch_alter_table("compiled_access_rules", schema=None) as batch_op:
        batch_op.add_column(sa.Column("target_id", sa.VARCHAR(length=255), nullable=True))
        batch_op.add_column(
            sa.Column("target_type", sa.VARCHAR(length=16), nullable=True)
        )

    op.execute(
        """
        UPDATE compiled_access_rules
        SET target_id = node_id,
            target_type = (
                SELECT nodes.type FROM nodes
                WHERE nodes.id = compiled_access_rules.node_id
            )
        """
    )

    with op.batch_alter_table("compiled_access_rules", schema=None) as batch_op:
        batch_op.alter_column(
            "target_id",
            existing_type=sa.VARCHAR(length=255),
            nullable=False,
        )
        batch_op.alter_column(
            "target_type",
            existing_type=sa.VARCHAR(length=16),
            nullable=False,
        )
        batch_op.drop_constraint(
            batch_op.f("fk_compiled_access_rules_node_id_nodes"),
            type_="foreignkey",
        )
        batch_op.drop_index("ix_compiled_access_rules_node_id_access")
        batch_op.drop_index(batch_op.f("ix_compiled_access_rules_node_id"))
        batch_op.create_index(
            batch_op.f("ix_compiled_access_rules_target_id"),
            ["target_id"],
            unique=False,
        )
        batch_op.create_index(
            batch_op.f("ix_compiled_access_rules_target_type"),
            ["target_type"],
            unique=False,
        )
        batch_op.create_index(
            "ix_compiled_access_rules_target_type_id_access",
            ["target_type", "target_id", "access_type"],
            unique=False,
        )
        batch_op.drop_column("node_id")

    with op.batch_alter_table("nodes", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_nodes_type"))
        batch_op.drop_index(batch_op.f("ix_nodes_status_operation_id"))
    op.drop_table("nodes")


def _raise_for_duplicate_node_ids() -> None:
    conn = op.get_bind()
    duplicates = conn.execute(
        sa.text(
            """
            SELECT documents.id
            FROM documents
            INNER JOIN folders ON folders.id = documents.id
            ORDER BY documents.id
            LIMIT 10
            """
        )
    ).fetchall()
    if duplicates:
        duplicate_ids = ", ".join(str(row[0]) for row in duplicates)
        raise RuntimeError(
            "Cannot migrate Document/Folder to nodes because IDs overlap: "
            f"{duplicate_ids}"
        )


def _backfill_nodes() -> None:
    op.execute(
        """
        INSERT INTO nodes (id, type, inherit, status, status_operation_id)
        SELECT id, 'directory', inherit, status, status_operation_id
        FROM folders
        """
    )
    op.execute(
        """
        INSERT INTO nodes (id, type, inherit, status, status_operation_id)
        SELECT id, 'document', inherit, status, status_operation_id
        FROM documents
        """
    )


def _delete_orphan_compiled_rules() -> None:
    op.execute(
        """
        DELETE FROM compiled_access_rules
        WHERE NOT EXISTS (
            SELECT 1
            FROM nodes
            WHERE nodes.id = compiled_access_rules.target_id
              AND nodes.type = compiled_access_rules.target_type
        )
        """
    )
