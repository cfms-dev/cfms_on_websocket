"""enforce node name uniqueness

Revision ID: fe8863687aa4
Revises: 18adc63ce5b1
Create Date: 2026-07-27 11:27:39.529427

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op


revision: str = "fe8863687aa4"
down_revision: str | Sequence[str] | None = "18adc63ce5b1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

DELETED_STATUS = 1
ROOT_DIRECTORY_ID = "/"


def upgrade() -> None:
    """Upgrade schema."""
    _validate_existing_namespace()

    with op.batch_alter_table("nodes", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("name", sa.VARCHAR(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column("parent_id", sa.VARCHAR(length=255), nullable=True)
        )

    op.execute(
        """
        UPDATE nodes
        SET name = (SELECT folders.name FROM folders WHERE folders.id = nodes.id),
            parent_id = (
                SELECT folders.parent_id FROM folders WHERE folders.id = nodes.id
            )
        WHERE type = 'directory'
        """
    )
    op.execute(
        """
        UPDATE nodes
        SET name = (
                SELECT documents.title FROM documents WHERE documents.id = nodes.id
            ),
            parent_id = (
                SELECT documents.folder_id FROM documents WHERE documents.id = nodes.id
            )
        WHERE type = 'document'
        """
    )
    _validate_backfill()

    with op.batch_alter_table(
        "nodes", schema=None, recreate="always"
    ) as batch_op:
        batch_op.alter_column(
            "name",
            existing_type=sa.VARCHAR(length=255),
            nullable=False,
        )
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
        batch_op.create_check_constraint(
            "ck_nodes_root_parent",
            "(id = '/' AND parent_id IS NULL AND type = 'directory') OR "
            "(id <> '/' AND parent_id IS NOT NULL)",
        )
        batch_op.create_unique_constraint(
            "uq_nodes_active_parent_name",
            ["active_parent_id", "name"],
        )
        batch_op.create_foreign_key(
            "fk_nodes_parent_id_folders",
            "folders",
            ["parent_id"],
            ["id"],
            ondelete="CASCADE",
            use_alter=True,
        )
        batch_op.create_index(
            batch_op.f("ix_nodes_name"), ["name"], unique=False
        )

    with op.batch_alter_table("documents", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_documents_title"))
        batch_op.drop_constraint(
            batch_op.f("fk_documents_folder_id_folders"), type_="foreignkey"
        )
        batch_op.drop_column("title")
        batch_op.drop_column("folder_id")

    with op.batch_alter_table("folders", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_folders_name"))
        batch_op.drop_constraint(
            batch_op.f("fk_folders_parent_id_folders"), type_="foreignkey"
        )
        batch_op.drop_column("parent_id")
        batch_op.drop_column("name")

    op.create_index(
        "ix_nodes_parent_status_lower_name_id",
        "nodes",
        ["parent_id", "status", sa.text("lower(name)"), "id"],
        unique=False,
    )
    op.create_index(
        "ix_nodes_status_lower_name_id",
        "nodes",
        ["status", sa.text("lower(name)"), "id"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index("ix_nodes_status_lower_name_id", table_name="nodes")
    op.drop_index(
        "ix_nodes_parent_status_lower_name_id", table_name="nodes"
    )

    with op.batch_alter_table("folders", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("name", sa.VARCHAR(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column("parent_id", sa.VARCHAR(length=255), nullable=True)
        )

    with op.batch_alter_table("documents", schema=None) as batch_op:
        batch_op.add_column(
            sa.Column("folder_id", sa.VARCHAR(length=255), nullable=True)
        )
        batch_op.add_column(
            sa.Column("title", sa.VARCHAR(length=255), nullable=True)
        )

    op.execute(
        """
        UPDATE folders
        SET name = (SELECT nodes.name FROM nodes WHERE nodes.id = folders.id),
            parent_id = (
                SELECT nodes.parent_id FROM nodes WHERE nodes.id = folders.id
            )
        """
    )
    op.execute(
        """
        UPDATE documents
        SET title = (SELECT nodes.name FROM nodes WHERE nodes.id = documents.id),
            folder_id = (
                SELECT nodes.parent_id FROM nodes WHERE nodes.id = documents.id
            )
        """
    )

    with op.batch_alter_table("folders", schema=None) as batch_op:
        batch_op.alter_column(
            "name",
            existing_type=sa.VARCHAR(length=255),
            nullable=False,
        )
        batch_op.create_foreign_key(
            batch_op.f("fk_folders_parent_id_folders"),
            "folders",
            ["parent_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_index(
            batch_op.f("ix_folders_name"), ["name"], unique=False
        )

    with op.batch_alter_table("documents", schema=None) as batch_op:
        batch_op.alter_column(
            "title",
            existing_type=sa.VARCHAR(length=255),
            nullable=False,
        )
        batch_op.create_foreign_key(
            batch_op.f("fk_documents_folder_id_folders"),
            "folders",
            ["folder_id"],
            ["id"],
            ondelete="CASCADE",
        )
        batch_op.create_index(
            batch_op.f("ix_documents_title"), ["title"], unique=False
        )

    with op.batch_alter_table(
        "nodes", schema=None, recreate="always"
    ) as batch_op:
        batch_op.drop_constraint(
            "fk_nodes_parent_id_folders", type_="foreignkey"
        )
        batch_op.drop_constraint("uq_nodes_active_parent_name", type_="unique")
        batch_op.drop_constraint("ck_nodes_root_parent", type_="check")
        batch_op.drop_index(batch_op.f("ix_nodes_name"))
        batch_op.drop_column("active_parent_id")
        batch_op.drop_column("parent_id")
        batch_op.drop_column("name")


def _namespace_rows() -> sa.TextClause:
    return sa.text(
        """
        SELECT nodes.id, nodes.type, nodes.status,
               folders.parent_id AS parent_id, folders.name AS name
        FROM nodes
        INNER JOIN folders ON folders.id = nodes.id
        WHERE nodes.type = 'directory'
        UNION ALL
        SELECT nodes.id, nodes.type, nodes.status,
               documents.folder_id AS parent_id, documents.title AS name
        FROM nodes
        INNER JOIN documents ON documents.id = nodes.id
        WHERE nodes.type = 'document'
        """
    )


def _validate_existing_namespace() -> None:
    connection = op.get_bind()
    rows = connection.execute(_namespace_rows()).mappings().all()
    node_ids = set(connection.execute(sa.text("SELECT id FROM nodes")).scalars())
    namespace_ids = {row["id"] for row in rows}
    missing_namespace = sorted(node_ids - namespace_ids)
    if missing_namespace:
        raise RuntimeError(
            "Cannot migrate node names: nodes are missing matching document or "
            "directory rows: " + ", ".join(missing_namespace[:10])
        )

    root_rows = [row for row in rows if row["id"] == ROOT_DIRECTORY_ID]
    if len(root_rows) != 1 or root_rows[0]["type"] != "directory":
        raise RuntimeError(
            "Cannot migrate node names: '/' must identify exactly one directory"
        )
    if root_rows[0]["parent_id"] is not None:
        raise RuntimeError("Cannot migrate node names: root directory has a parent")

    folder_ids = {row["id"] for row in rows if row["type"] == "directory"}
    missing_parent = [
        row
        for row in rows
        if row["id"] != ROOT_DIRECTORY_ID
        and (
            row["parent_id"] is None or row["parent_id"] not in folder_ids
        )
    ]
    if missing_parent:
        identifiers = ", ".join(str(row["id"]) for row in missing_parent[:10])
        raise RuntimeError(
            "Cannot migrate node names: non-root nodes without a parent: "
            f"{identifiers}"
        )

    duplicates = connection.execute(
        sa.text(
            """
            SELECT parent_id, name, COUNT(*) AS item_count
            FROM (
                SELECT nodes.status, folders.parent_id AS parent_id,
                       folders.name AS name
                FROM nodes
                INNER JOIN folders ON folders.id = nodes.id
                WHERE nodes.type = 'directory'
                UNION ALL
                SELECT nodes.status, documents.folder_id AS parent_id,
                       documents.title AS name
                FROM nodes
                INNER JOIN documents ON documents.id = nodes.id
                WHERE nodes.type = 'document'
            ) AS namespace
            WHERE status <> :deleted_status
            GROUP BY parent_id, name
            HAVING COUNT(*) > 1
            ORDER BY parent_id, name
            LIMIT 10
            """
        ),
        {"deleted_status": DELETED_STATUS},
    ).mappings()
    duplicate_groups = duplicates.all()
    if not duplicate_groups:
        return

    details = []
    for group in duplicate_groups:
        matching = connection.execute(
            sa.text(
                """
                SELECT id, type
                FROM (
                    SELECT nodes.id, nodes.type, nodes.status,
                           folders.parent_id AS parent_id, folders.name AS name
                    FROM nodes
                    INNER JOIN folders ON folders.id = nodes.id
                    WHERE nodes.type = 'directory'
                    UNION ALL
                    SELECT nodes.id, nodes.type, nodes.status,
                           documents.folder_id AS parent_id,
                           documents.title AS name
                    FROM nodes
                    INNER JOIN documents ON documents.id = nodes.id
                    WHERE nodes.type = 'document'
                ) AS namespace
                WHERE status <> :deleted_status
                  AND ((parent_id = :parent_id) OR
                       (parent_id IS NULL AND :parent_id IS NULL))
                  AND name = :name
                ORDER BY type, id
                """
            ),
            {
                "deleted_status": DELETED_STATUS,
                "parent_id": group["parent_id"],
                "name": group["name"],
            },
        ).mappings()
        nodes = ", ".join(f"{row['type']}:{row['id']}" for row in matching)
        details.append(f"{group['parent_id']!r}/{group['name']!r} [{nodes}]")
    raise RuntimeError(
        "Cannot migrate node names because active siblings have duplicate names: "
        + "; ".join(details)
    )


def _validate_backfill() -> None:
    connection = op.get_bind()
    missing = connection.execute(
        sa.text(
            """
            SELECT id
            FROM nodes
            WHERE name IS NULL OR (id <> '/' AND parent_id IS NULL)
            ORDER BY id
            LIMIT 10
            """
        )
    ).scalars()
    identifiers = list(missing)
    if identifiers:
        raise RuntimeError(
            "Node namespace backfill was incomplete for IDs: "
            + ", ".join(str(identifier) for identifier in identifiers)
        )
