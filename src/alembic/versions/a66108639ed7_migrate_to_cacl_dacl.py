"""migrate to cacl dacl

Revision ID: a66108639ed7
Revises: e952c02c1454
Create Date: 2026-11-24 16:20:40.698440

"""

import time
from collections.abc import Sequence
from dataclasses import dataclass
from graphlib import TopologicalSorter

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "a66108639ed7"
down_revision: str | Sequence[str] | None = "e952c02c1454"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MIGRATION_OWNER = "migration:a66108639ed7"
_ADDED_SYSOP_PERMISSIONS = ("bypass_dacl", "bypass_traverse_checking")
_REMOVED_PERMISSIONS = (
    "move",
    "create_document",
    "delete_document",
    "rename_document",
    "create_directory",
    "delete_directory",
    "rename_directory",
    "list_deleted_items",
    "restore",
    "super_create_document",
    "super_create_directory",
    "super_list_directory",
    "view_access_rules",
    "set_access_rules",
    "view_metadata",
    "set_metadata_tags",
    "manage_access",
    "view_access_entries",
    "block",
    "unblock",
    "list_user_blocks",
    "list_revisions",
    "view_revision",
    "set_current_revision",
)
_ROOT_DIRECTORY_ID = "/"
# Frozen CEP-0002 v1 bitmasks corresponding to DEFAULT_ROOT_DACL_SOURCE:
# allow [PRESET_READ] to any;
# allow [PRESET_RW, PRESET_TRASH_RW, PRESET_ACL_RW, READ_REVISION, DELETE_REVISION] to group("sysop");
_PRESET_READ_MASK = 1043  # TRAVERSE | LIST_DIRECTORY | READ_CONTENT | READ_METADATA
_DEFAULT_SYSOP_ALL_OPS_MASK = 2097151  # All 21 CEP-0002 v1 AtomicOps (bits 0..20)


@dataclass(frozen=True, slots=True)
class _MigrationTables:
    nodes: sa.TableClause
    dacl_rules: sa.Table
    dacl_rule_clauses: sa.Table
    dacl_rule_atoms: sa.Table
    user_groups: sa.TableClause
    group_permissions: sa.Table
    user_permissions: sa.TableClause
    options: sa.TableClause
    system_states: sa.TableClause


def _data_tables() -> _MigrationTables:
    metadata = sa.MetaData()
    return _MigrationTables(
        nodes=sa.table(
            "nodes",
            sa.column("id", sa.String()),
            sa.column("inherit", sa.Boolean()),
        ),
        dacl_rules=sa.Table(
            "dacl_rules",
            metadata,
            sa.Column(
                "id",
                sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
                primary_key=True,
                autoincrement=True,
            ),
            sa.Column("node_id", sa.String()),
            sa.Column("effect", sa.String()),
            sa.Column("permission_mask", sa.BigInteger()),
            sa.Column("scope", sa.String()),
            sa.Column("valid_from", sa.BigInteger()),
            sa.Column("valid_until", sa.BigInteger()),
            sa.Column("remark", sa.Text()),
        ),
        dacl_rule_clauses=sa.Table(
            "dacl_rule_clauses",
            metadata,
            sa.Column(
                "id",
                sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
                primary_key=True,
                autoincrement=True,
            ),
            sa.Column("rule_id", sa.BigInteger()),
        ),
        dacl_rule_atoms=sa.Table(
            "dacl_rule_atoms",
            metadata,
            sa.Column(
                "id",
                sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
                primary_key=True,
                autoincrement=True,
            ),
            sa.Column("clause_id", sa.BigInteger()),
            sa.Column("predicate_kind", sa.String()),
            sa.Column("predicate_value", sa.String()),
            sa.Column("is_negated", sa.Boolean()),
        ),
        user_groups=sa.table("user_groups", sa.column("group_name", sa.String())),
        group_permissions=sa.Table(
            "group_permissions",
            metadata,
            sa.Column("id", sa.Integer(), primary_key=True, autoincrement=True),
            sa.Column("group_name", sa.String()),
            sa.Column("permission", sa.String()),
            sa.Column("granted", sa.Boolean()),
            sa.Column("start_time", sa.Double()),
            sa.Column("end_time", sa.Double()),
        ),
        user_permissions=sa.table(
            "user_permissions", sa.column("permission", sa.String())
        ),
        options=sa.table(
            "options",
            sa.column("namespace", sa.String()),
            sa.column("option_key", sa.String()),
        ),
        system_states=sa.table(
            "system_states",
            sa.column("owner", sa.String()),
            sa.column("state_key", sa.String()),
            sa.column("schema_version", sa.Integer()),
            sa.column("revision", sa.BigInteger()),
            sa.column("payload", sa.JSON()),
            sa.column("updated_at", sa.Double()),
        ),
    )


def _seed_default_root_dacl(
    connection: sa.Connection,
    tables: _MigrationTables,
) -> None:
    nodes = tables.nodes
    dacl_rules = tables.dacl_rules
    dacl_rule_clauses = tables.dacl_rule_clauses
    dacl_rule_atoms = tables.dacl_rule_atoms
    root_exists = connection.execute(
        sa.select(nodes.c.id).where(nodes.c.id == _ROOT_DIRECTORY_ID)
    ).first()
    if not root_exists:
        return

    connection.execute(
        nodes.update()
        .where(nodes.c.id == _ROOT_DIRECTORY_ID)
        .values(inherit=False)
    )
    has_rules = connection.execute(
        sa.select(dacl_rules.c.id).where(dacl_rules.c.node_id == _ROOT_DIRECTORY_ID)
    ).first()
    if has_rules:
        return

    read_rule = connection.execute(
        dacl_rules.insert().values(
            node_id=_ROOT_DIRECTORY_ID,
            effect="allow",
            permission_mask=_PRESET_READ_MASK,
            scope="all",
            valid_from=None,
            valid_until=None,
            remark="Default read access for authenticated users",
        )
    )
    # Empty clause (0 atoms) represents `any`.
    connection.execute(
        dacl_rule_clauses.insert().values(rule_id=read_rule.inserted_primary_key[0])
    )

    admin_rule = connection.execute(
        dacl_rules.insert().values(
            node_id=_ROOT_DIRECTORY_ID,
            effect="allow",
            permission_mask=_DEFAULT_SYSOP_ALL_OPS_MASK,
            scope="all",
            valid_from=None,
            valid_until=None,
            remark="Default administrator full access",
        )
    )
    admin_clause = connection.execute(
        dacl_rule_clauses.insert().values(rule_id=admin_rule.inserted_primary_key[0])
    )
    connection.execute(
        dacl_rule_atoms.insert().values(
            clause_id=admin_clause.inserted_primary_key[0],
            predicate_kind="group",
            predicate_value="sysop",
            is_negated=False,
        )
    )


_SQLITE_FK_NAMING = {
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"
}


@dataclass(frozen=True, slots=True)
class _SqliteNodeMigrationSnapshot:
    saved_current_revisions: list[tuple[str, str]]
    saved_parent_revisions: list[tuple[str, str]]
    detached_fks: list[tuple[str, list[dict]]]
    saved_nodes: list[dict]
    saved_folders: list[dict]


def _detach_sqlite_node_dependents(
    connection: sa.Connection,
) -> _SqliteNodeMigrationSnapshot:
    inspector = sa.inspect(connection)
    existing_tables = set(inspector.get_table_names())

    saved_current_revisions: list[tuple[str, str]] = []
    if "documents" in existing_tables:
        saved_current_revisions = [
            (row[0], row[1])
            for row in connection.execute(
                sa.text(
                    "SELECT id, current_revision_id FROM documents "
                    "WHERE current_revision_id IS NOT NULL"
                )
            ).all()
        ]
        if saved_current_revisions:
            connection.execute(
                sa.text("UPDATE documents SET current_revision_id = NULL")
            )

    saved_parent_revisions: list[tuple[str, str]] = []
    if "document_revisions" in existing_tables:
        saved_parent_revisions = [
            (row[0], row[1])
            for row in connection.execute(
                sa.text(
                    "SELECT id, parent_revision_id FROM document_revisions "
                    "WHERE parent_revision_id IS NOT NULL"
                )
            ).all()
        ]
        if saved_parent_revisions:
            connection.execute(
                sa.text("UPDATE document_revisions SET parent_revision_id = NULL")
            )

    foreign_keys = {
        name: inspector.get_foreign_keys(name) for name in existing_tables
    }
    affected = {"nodes", "folders"} & existing_tables
    while additional := {
        name
        for name, keys in foreign_keys.items()
        if name not in affected
        and any(key["referred_table"] in affected for key in keys)
    }:
        affected.update(additional)

    references: dict[str, list[dict]] = {}
    for name in affected - {"nodes", "folders"}:
        relevant_fks = [
            fk
            for fk in foreign_keys[name]
            if fk["referred_table"] in affected
            and fk["referred_table"] != name
            and not (
                name == "documents"
                and fk["referred_table"] == "document_revisions"
            )
        ]
        if relevant_fks:
            references[name] = relevant_fks

    order = tuple(
        TopologicalSorter(
            {
                name: {fk["referred_table"] for fk in keys} - {"nodes", "folders"}
                for name, keys in references.items()
            }
        ).static_order()
    )

    detached_fks: list[tuple[str, list[dict]]] = []
    for table_name in reversed(order):
        fks_to_drop = references[table_name]
        detached_fks.append((table_name, fks_to_drop))
        with op.batch_alter_table(
            table_name, naming_convention=_SQLITE_FK_NAMING
        ) as batch_op:
            for fk in fks_to_drop:
                constraint_name = fk["name"] or (
                    f"fk_{table_name}_{fk['constrained_columns'][0]}_"
                    f"{fk['referred_table']}"
                )
                batch_op.drop_constraint(constraint_name, type_="foreignkey")

    saved_nodes = [
        dict(row)
        for row in connection.execute(
            sa.text(
                "SELECT id, type, name, parent_id, inherit, status, status_operation_id "
                "FROM nodes"
            )
        )
        .mappings()
        .all()
    ]
    saved_folders = [
        dict(row)
        for row in connection.execute(
            sa.text("SELECT id, created_time FROM folders")
        )
        .mappings()
        .all()
    ]
    if saved_nodes:
        connection.execute(sa.text("DELETE FROM nodes"))

    return _SqliteNodeMigrationSnapshot(
        saved_current_revisions=saved_current_revisions,
        saved_parent_revisions=saved_parent_revisions,
        detached_fks=detached_fks,
        saved_nodes=saved_nodes,
        saved_folders=saved_folders,
    )


def _reinsert_sqlite_nodes_and_folders(
    connection: sa.Connection,
    saved_nodes: list[dict],
    saved_folders: list[dict],
) -> None:
    if not saved_nodes:
        return

    insert_node_sql = sa.text(
        "INSERT INTO nodes (id, type, name, parent_id, inherit, status, status_operation_id) "
        "VALUES (:id, :type, :name, :parent_id, :inherit, :status, :status_operation_id)"
    )
    insert_folder_sql = sa.text(
        "INSERT INTO folders (id, created_time) VALUES (:id, :created_time)"
    )
    folders_by_id = {row["id"]: row for row in saved_folders}
    folder_nodes: dict[str, dict] = {}
    other_nodes: list[dict] = []
    for row in saved_nodes:
        if row["id"] in folders_by_id:
            folder_nodes[row["id"]] = row
        else:
            other_nodes.append(row)

    children_by_parent: dict[str | None, list[dict]] = {}
    for row in folder_nodes.values():
        children_by_parent.setdefault(row["parent_id"], []).append(row)

    level = children_by_parent.get(None, [])
    inserted_count = 0
    while level:
        connection.execute(insert_node_sql, level)
        connection.execute(
            insert_folder_sql, [folders_by_id[row["id"]] for row in level]
        )
        inserted_count += len(level)
        next_level: list[dict] = []
        for row in level:
            next_level.extend(children_by_parent.get(row["id"], ()))
        level = next_level

    if inserted_count != len(folder_nodes):
        raise RuntimeError(
            "Unable to restore folder hierarchy during nodes migration: cycle detected"
        )

    if other_nodes:
        connection.execute(insert_node_sql, other_nodes)


def _restore_sqlite_node_dependents(
    connection: sa.Connection,
    snapshot: _SqliteNodeMigrationSnapshot,
) -> None:
    op.execute(
        sa.text(
            "CREATE INDEX IF NOT EXISTS ix_nodes_parent_status_lower_name_id "
            "ON nodes (parent_id, status, lower(name), id)"
        )
    )
    op.execute(
        sa.text(
            "CREATE INDEX IF NOT EXISTS ix_nodes_status_lower_name_id "
            "ON nodes (status, lower(name), id)"
        )
    )

    _reinsert_sqlite_nodes_and_folders(
        connection, snapshot.saved_nodes, snapshot.saved_folders
    )

    for table_name, fks in reversed(snapshot.detached_fks):
        with op.batch_alter_table(
            table_name, naming_convention=_SQLITE_FK_NAMING
        ) as batch_op:
            for fk in fks:
                batch_op.create_foreign_key(
                    fk["name"],
                    fk["referred_table"],
                    fk["constrained_columns"],
                    fk["referred_columns"],
                    referent_schema=fk["referred_schema"],
                    **fk["options"],
                )

    if snapshot.saved_parent_revisions:
        connection.execute(
            sa.text(
                "UPDATE document_revisions SET parent_revision_id = :parent_rev_id "
                "WHERE id = :rev_id"
            ),
            [
                {"rev_id": rev_id, "parent_rev_id": parent_rev_id}
                for rev_id, parent_rev_id in snapshot.saved_parent_revisions
            ],
        )

    if snapshot.saved_current_revisions:
        connection.execute(
            sa.text(
                "UPDATE documents SET current_revision_id = :rev_id WHERE id = :doc_id"
            ),
            [
                {"doc_id": doc_id, "rev_id": rev_id}
                for doc_id, rev_id in snapshot.saved_current_revisions
            ],
        )


def _alter_nodes_access_rule_set_column(*, drop: bool) -> None:
    """Drop or restore nodes.access_rule_set_id without losing SQLite rows via FK cascade."""
    connection = op.get_bind()
    is_sqlite = connection.dialect.name == "sqlite"
    snapshot = _detach_sqlite_node_dependents(connection) if is_sqlite else None

    with op.batch_alter_table("nodes", schema=None) as batch_op:
        if is_sqlite:
            batch_op.drop_constraint("uq_nodes_active_parent_name", type_="unique")
            batch_op.drop_column("active_name")
        if drop:
            batch_op.drop_constraint(
                batch_op.f("fk_nodes_access_rule_set_id_compiled_access_rule_sets"),
                type_="foreignkey",
            )
            batch_op.drop_index(batch_op.f("ix_nodes_access_rule_set_id"))
            batch_op.drop_column("access_rule_set_id")
        else:
            batch_op.add_column(
                sa.Column("access_rule_set_id", sa.VARCHAR(length=32), nullable=True)
            )
            batch_op.create_index(
                batch_op.f("ix_nodes_access_rule_set_id"),
                ["access_rule_set_id"],
                unique=False,
            )
            batch_op.create_foreign_key(
                batch_op.f("fk_nodes_access_rule_set_id_compiled_access_rule_sets"),
                "compiled_access_rule_sets",
                ["access_rule_set_id"],
                ["id"],
            )
        if is_sqlite:
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
                "uq_nodes_active_parent_name", ["parent_id", "active_name"]
            )

    if snapshot is not None:
        _restore_sqlite_node_dependents(connection, snapshot)


def upgrade() -> None:
    """Upgrade schema to CEP-0002 CACL DACL tables and drop legacy access/block tables."""
    connection = op.get_bind()
    tables = _data_tables()
    connection.execute(sa.text("UPDATE nodes SET access_rule_set_id = NULL"))
    connection.execute(sa.text("DELETE FROM compiled_access_rule_sets"))

    # Drop legacy FK on nodes before dropping compiled_access_rule_sets (child -> parent order).
    _alter_nodes_access_rule_set_column(drop=True)

    op.create_table(
        "dacl_rules",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column("node_id", sa.VARCHAR(length=255), nullable=False),
        sa.Column("effect", sa.VARCHAR(length=8), nullable=False),
        sa.Column("permission_mask", sa.BigInteger(), nullable=False),
        sa.Column("scope", sa.VARCHAR(length=8), nullable=False),
        sa.Column("valid_from", sa.BigInteger(), nullable=True),
        sa.Column("valid_until", sa.BigInteger(), nullable=True),
        sa.Column("remark", sa.Text(), nullable=True),
        sa.CheckConstraint("effect IN ('allow', 'deny')", name="ck_dacl_rules_effect"),
        sa.CheckConstraint(
            "scope IN ('self', 'dirs', 'docs', 'all')", name="ck_dacl_rules_scope"
        ),
        sa.CheckConstraint("permission_mask > 0", name="ck_dacl_rules_permission_mask"),
        sa.CheckConstraint(
            "valid_from IS NULL OR valid_until IS NULL OR valid_from < valid_until",
            name="ck_dacl_rules_valid_window",
        ),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["nodes.id"],
            name=op.f("fk_dacl_rules_node_id_nodes"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_dacl_rules")),
    )
    op.create_index(
        "ix_dacl_rules_node_effect_scope",
        "dacl_rules",
        ["node_id", "effect", "scope"],
        unique=False,
    )
    op.create_index(
        "ix_dacl_rules_validity",
        "dacl_rules",
        ["node_id", "valid_from", "valid_until"],
        unique=False,
    )

    op.create_table(
        "dacl_rule_clauses",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column(
            "rule_id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["dacl_rules.id"],
            name=op.f("fk_dacl_rule_clauses_rule_id_dacl_rules"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_dacl_rule_clauses")),
    )
    op.create_index(
        op.f("ix_dacl_rule_clauses_rule_id"),
        "dacl_rule_clauses",
        ["rule_id"],
        unique=False,
    )

    op.create_table(
        "dacl_rule_atoms",
        sa.Column(
            "id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            autoincrement=True,
            nullable=False,
        ),
        sa.Column(
            "clause_id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            nullable=False,
        ),
        sa.Column("predicate_kind", sa.VARCHAR(length=16), nullable=False),
        sa.Column("predicate_value", sa.VARCHAR(length=255), nullable=False),
        sa.Column("is_negated", sa.Boolean(), nullable=False),
        sa.CheckConstraint(
            "predicate_kind IN ('user', 'group', 'perm')",
            name="ck_dacl_rule_atoms_kind",
        ),
        sa.ForeignKeyConstraint(
            ["clause_id"],
            ["dacl_rule_clauses.id"],
            name=op.f("fk_dacl_rule_atoms_clause_id_dacl_rule_clauses"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_dacl_rule_atoms")),
    )
    op.create_index(
        op.f("ix_dacl_rule_atoms_clause_id"),
        "dacl_rule_atoms",
        ["clause_id"],
        unique=False,
    )
    op.create_index(
        "ix_dacl_rule_atoms_principal",
        "dacl_rule_atoms",
        ["predicate_kind", "predicate_value"],
        unique=False,
    )

    op.drop_table("compiled_access_rule_rights")
    op.drop_table("compiled_access_rule_memberships")
    op.drop_table("compiled_access_rule_groups")
    op.drop_table("compiled_access_rules")
    op.drop_table("compiled_access_rule_sets")
    op.drop_table("userblock_sub_entries")
    op.drop_table("userblock_entries")
    op.drop_table("object_access_entries")

    _seed_default_root_dacl(connection, tables)

    # Remove obsolete recursive-check option row so startup option loading stays clean.
    connection.execute(
        tables.options.delete().where(
            tables.options.c.namespace == "access",
            tables.options.c.option_key == "enable_access_recursive_check",
        )
    )

    # Remove deleted core permissions from existing permission tables.
    connection.execute(
        tables.group_permissions.delete().where(
            tables.group_permissions.c.permission.in_(_REMOVED_PERMISSIONS)
        )
    )
    connection.execute(
        tables.user_permissions.delete().where(
            tables.user_permissions.c.permission.in_(_REMOVED_PERMISSIONS)
        )
    )

    # Grant new CEP-0002 global capability permissions to sysop if present.
    sysop_exists = connection.execute(
        sa.select(tables.user_groups.c.group_name).where(
            tables.user_groups.c.group_name == "sysop"
        )
    ).first()
    if sysop_exists:
        for permission in _ADDED_SYSOP_PERMISSIONS:
            grant_exists = connection.execute(
                sa.select(tables.group_permissions.c.permission).where(
                    tables.group_permissions.c.group_name == "sysop",
                    tables.group_permissions.c.permission == permission,
                    tables.group_permissions.c.granted == sa.true(),
                    tables.group_permissions.c.end_time.is_(None),
                )
            ).first()
            if grant_exists:
                continue
            inserted_grant = connection.execute(
                tables.group_permissions.insert().values(
                    group_name="sysop",
                    permission=permission,
                    granted=True,
                    start_time=0.0,
                    end_time=None,
                )
            )
            connection.execute(
                tables.system_states.insert().values(
                    owner=_MIGRATION_OWNER,
                    state_key=permission,
                    schema_version=2,
                    revision=1,
                    payload={
                        "group_permission_id": inserted_grant.inserted_primary_key[0]
                    },
                    updated_at=time.time(),
                )
            )


def downgrade() -> None:
    """Downgrade schema back to legacy access-rule and user-block tables.

    Note: legacy access-rule/user-block rows and the 24 pruned permission grants
    removed by ``upgrade()`` cannot be recovered automatically; restore a database
    backup for full data rollback.
    """
    connection = op.get_bind()
    tables = _data_tables()

    for permission in _ADDED_SYSOP_PERMISSIONS:
        marker = connection.execute(
            sa.select(tables.system_states.c.payload).where(
                tables.system_states.c.owner == _MIGRATION_OWNER,
                tables.system_states.c.state_key == permission,
            )
        ).first()
        if marker is None:
            continue
        group_permission_id = marker.payload.get("group_permission_id")
        if group_permission_id is not None:
            connection.execute(
                tables.group_permissions.delete().where(
                    tables.group_permissions.c.id == group_permission_id
                )
            )
        connection.execute(
            tables.system_states.delete().where(
                tables.system_states.c.owner == _MIGRATION_OWNER,
                tables.system_states.c.state_key == permission,
            )
        )

    connection.execute(
        tables.options.delete().where(
            tables.options.c.namespace == "access",
            tables.options.c.option_key == "bypass_traverse_checking",
        )
    )

    op.create_table(
        "object_access_entries",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("entity_type", sa.VARCHAR(length=16), nullable=False),
        sa.Column("entity_identifier", sa.VARCHAR(length=255), nullable=False),
        sa.Column("target_type", sa.VARCHAR(length=16), nullable=False),
        sa.Column("target_identifier", sa.VARCHAR(length=255), nullable=False),
        sa.Column("access_type", sa.VARCHAR(length=16), nullable=False),
        sa.Column("start_time", sa.Double(), nullable=False),
        sa.Column("end_time", sa.Double(), nullable=True),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_object_access_entries")),
    )
    op.create_index(
        op.f("ix_object_access_entries_target_identifier"),
        "object_access_entries",
        ["target_identifier"],
        unique=False,
    )
    op.create_index(
        op.f("ix_object_access_entries_entity_identifier"),
        "object_access_entries",
        ["entity_identifier"],
        unique=False,
    )

    op.create_table(
        "userblock_entries",
        sa.Column("block_id", sa.VARCHAR(length=32), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("timestamp", sa.Double(), nullable=False),
        sa.Column("not_before", sa.Double(), nullable=False),
        sa.Column("not_after", sa.Double(), nullable=False),
        sa.Column("target_type", sa.VARCHAR(length=32), nullable=False),
        sa.Column("target_id", sa.VARCHAR(length=255), nullable=True),
        sa.Column(
            "reason_comment_id",
            sa.BigInteger().with_variant(sa.Integer(), "sqlite"),
            nullable=True,
        ),
        sa.ForeignKeyConstraint(
            ["reason_comment_id"],
            ["comments.comment_id"],
            name=op.f("fk_userblock_entries_reason_comment_id_comments"),
            ondelete="SET NULL",
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.id"],
            name=op.f("fk_userblock_entries_user_id_users"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("block_id", name=op.f("pk_userblock_entries")),
    )
    op.create_table(
        "userblock_sub_entries",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("parent_id", sa.VARCHAR(length=32), nullable=False),
        sa.Column("block_type", sa.VARCHAR(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["parent_id"],
            ["userblock_entries.block_id"],
            name=op.f("fk_userblock_sub_entries_parent_id_userblock_entries"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_userblock_sub_entries")),
    )

    op.create_table(
        "compiled_access_rule_sets",
        sa.Column("id", sa.VARCHAR(length=32), nullable=False),
        sa.Column("node_id", sa.VARCHAR(length=255), nullable=False),
        sa.Column("created_at", sa.Double(), nullable=False),
        sa.ForeignKeyConstraint(
            ["node_id"],
            ["nodes.id"],
            name=op.f("fk_compiled_access_rule_sets_node_id_nodes"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compiled_access_rule_sets")),
    )
    op.create_index(
        op.f("ix_compiled_access_rule_sets_node_id"),
        "compiled_access_rule_sets",
        ["node_id"],
        unique=False,
    )

    op.create_table(
        "compiled_access_rules",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("rule_set_id", sa.VARCHAR(length=32), nullable=False),
        sa.Column("access_type", sa.VARCHAR(length=64), nullable=False),
        sa.Column("match_mode", sa.VARCHAR(length=8), nullable=False),
        sa.ForeignKeyConstraint(
            ["rule_set_id"],
            ["compiled_access_rule_sets.id"],
            name=op.f("fk_compiled_access_rules_rule_set_id_compiled_access_rule_sets"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compiled_access_rules")),
    )
    op.create_index(
        op.f("ix_compiled_access_rules_rule_set_id"),
        "compiled_access_rules",
        ["rule_set_id"],
        unique=False,
    )
    op.create_index(
        op.f("ix_compiled_access_rules_access_type"),
        "compiled_access_rules",
        ["access_type"],
        unique=False,
    )

    op.create_table(
        "compiled_access_rule_groups",
        sa.Column("id", sa.VARCHAR(length=32), nullable=False),
        sa.Column("rule_id", sa.Integer(), nullable=False),
        sa.Column("group_index", sa.Integer(), nullable=False),
        sa.Column("match_mode", sa.VARCHAR(length=8), nullable=False),
        sa.Column("rights_match_mode", sa.VARCHAR(length=8), nullable=False),
        sa.Column("rights_empty", sa.Boolean(), nullable=False),
        sa.Column("groups_match_mode", sa.VARCHAR(length=8), nullable=False),
        sa.Column("groups_empty", sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(
            ["rule_id"],
            ["compiled_access_rules.id"],
            name=op.f("fk_compiled_access_rule_groups_rule_id_compiled_access_rules"),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compiled_access_rule_groups")),
    )
    op.create_index(
        op.f("ix_compiled_access_rule_groups_rule_id"),
        "compiled_access_rule_groups",
        ["rule_id"],
        unique=False,
    )

    op.create_table(
        "compiled_access_rule_memberships",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("group_id", sa.VARCHAR(length=32), nullable=False),
        sa.Column("group_name", sa.VARCHAR(length=255), nullable=False),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["compiled_access_rule_groups.id"],
            name=op.f(
                "fk_compiled_access_rule_memberships_group_id_compiled_access_rule_groups"
            ),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compiled_access_rule_memberships")),
    )
    op.create_index(
        op.f("ix_compiled_access_rule_memberships_group_name"),
        "compiled_access_rule_memberships",
        ["group_name"],
        unique=False,
    )
    op.create_index(
        op.f("ix_compiled_access_rule_memberships_group_id"),
        "compiled_access_rule_memberships",
        ["group_id"],
        unique=False,
    )

    op.create_table(
        "compiled_access_rule_rights",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("group_id", sa.VARCHAR(length=32), nullable=False),
        sa.Column("permission", sa.VARCHAR(length=64), nullable=False),
        sa.ForeignKeyConstraint(
            ["group_id"],
            ["compiled_access_rule_groups.id"],
            name=op.f(
                "fk_compiled_access_rule_rights_group_id_compiled_access_rule_groups"
            ),
            ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_compiled_access_rule_rights")),
    )
    op.create_index(
        op.f("ix_compiled_access_rule_rights_permission"),
        "compiled_access_rule_rights",
        ["permission"],
        unique=False,
    )
    op.create_index(
        op.f("ix_compiled_access_rule_rights_group_id"),
        "compiled_access_rule_rights",
        ["group_id"],
        unique=False,
    )

    op.drop_table("dacl_rule_atoms")
    op.drop_table("dacl_rule_clauses")
    op.drop_table("dacl_rules")

    _alter_nodes_access_rule_set_column(drop=False)
