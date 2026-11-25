"""Tests for Alembic migration a66108639ed7 (CACL DACL schema & data migration)."""

import ast
import importlib.util
import io
import uuid
from collections.abc import Callable
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from cacl_compiler import CompilerConfig, ObjectType, compile_cacl
from sqlalchemy import Connection, inspect
from sqlalchemy.orm import Session

import include.database.models  # noqa: F401
from alembic import command
from include.database.session import Base
from include.domains.access.authorization.storage import (
    DEFAULT_ROOT_DACL_SOURCE,
    load_node_policies,
)
from include.domains.access.permissions import Permissions

pytestmark = pytest.mark.component
_ROOT = Path(__file__).resolve().parents[3]
_MIGRATION_PATH = (
    _ROOT / "src" / "alembic" / "versions" / "a66108639ed7_migrate_to_cacl_dacl.py"
)


def _load_cacl_migration_module():
    spec = importlib.util.spec_from_file_location(
        "cacl_migration_a66108639ed7", _MIGRATION_PATH
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def run_cacl_migration_round_trip(
    connection: Connection,
    config: Config,
    *,
    after_transition: Callable[[Connection], None] | None = None,
) -> None:
    """Exercise downgrade -> seed -> upgrade -> downgrade -> re-upgrade on any dialect."""
    command.downgrade(config, "e952c02c1454")
    tables_before = set(inspect(connection).get_table_names())
    assert {
        "compiled_access_rule_sets",
        "compiled_access_rules",
        "object_access_entries",
        "userblock_entries",
        "userblock_sub_entries",
    } <= tables_before

    nodes_tbl = sa.table(
        "nodes",
        sa.column("id", sa.String()),
        sa.column("type", sa.String()),
        sa.column("name", sa.String()),
        sa.column("parent_id", sa.String()),
        sa.column("inherit", sa.Boolean()),
        sa.column("status", sa.Integer()),
        sa.column("status_operation_id", sa.String()),
        sa.column("access_rule_set_id", sa.String()),
    )
    folders_tbl = sa.table(
        "folders",
        sa.column("id", sa.String()),
        sa.column("created_time", sa.Double()),
    )
    documents_tbl = sa.table(
        "documents",
        sa.column("id", sa.String()),
        sa.column("created_time", sa.Double()),
        sa.column("current_revision_id", sa.String()),
    )
    files_tbl = sa.table(
        "files",
        sa.column("id", sa.String()),
        sa.column("path", sa.String()),
        sa.column("active", sa.Boolean()),
        sa.column("size", sa.BigInteger()),
        sa.column("created_time", sa.Double()),
    )
    revisions_tbl = sa.table(
        "document_revisions",
        sa.column("id", sa.String()),
        sa.column("document_id", sa.String()),
        sa.column("file_id", sa.String()),
        sa.column("created_time", sa.Double()),
        sa.column("parent_revision_id", sa.String()),
        sa.column("status", sa.Integer()),
    )
    metadata_tbl = sa.table("document_metadata", sa.column("document_id", sa.String()))
    tags_tbl = sa.table(
        "document_metadata_tags",
        sa.column("document_id", sa.String()),
        sa.column("tag", sa.String()),
        sa.column("position", sa.Integer()),
    )
    user_groups_tbl = sa.table(
        "user_groups",
        sa.column("group_name", sa.String()),
        sa.column("group_display_name", sa.String()),
    )
    group_perms_tbl = sa.table(
        "group_permissions",
        sa.column("group_name", sa.String()),
        sa.column("permission", sa.String()),
        sa.column("granted", sa.Boolean()),
        sa.column("start_time", sa.Double()),
        sa.column("end_time", sa.Double()),
    )
    users_tbl = sa.table(
        "users",
        sa.column("id", sa.Uuid()),
        sa.column("username", sa.String()),
        sa.column("created_time", sa.Double()),
        sa.column("status", sa.Integer()),
        sa.column("secret_key", sa.String()),
    )
    user_perms_tbl = sa.table(
        "user_permissions",
        sa.column("user_id", sa.Uuid()),
        sa.column("permission", sa.String()),
        sa.column("granted", sa.Boolean()),
        sa.column("start_time", sa.Double()),
        sa.column("end_time", sa.Double()),
    )
    rule_sets_tbl = sa.table(
        "compiled_access_rule_sets",
        sa.column("id", sa.String()),
        sa.column("node_id", sa.String()),
        sa.column("created_at", sa.Double()),
    )
    rules_tbl = sa.table(
        "compiled_access_rules",
        sa.column("id", sa.Integer()),
        sa.column("rule_set_id", sa.String()),
        sa.column("access_type", sa.String()),
        sa.column("match_mode", sa.String()),
    )
    rule_groups_tbl = sa.table(
        "compiled_access_rule_groups",
        sa.column("id", sa.String()),
        sa.column("rule_id", sa.Integer()),
        sa.column("group_index", sa.Integer()),
        sa.column("match_mode", sa.String()),
        sa.column("rights_match_mode", sa.String()),
        sa.column("rights_empty", sa.Boolean()),
        sa.column("groups_match_mode", sa.String()),
        sa.column("groups_empty", sa.Boolean()),
    )
    rule_memberships_tbl = sa.table(
        "compiled_access_rule_memberships",
        sa.column("group_id", sa.String()),
        sa.column("group_name", sa.String()),
    )
    rule_rights_tbl = sa.table(
        "compiled_access_rule_rights",
        sa.column("group_id", sa.String()),
        sa.column("permission", sa.String()),
    )
    access_entries_tbl = sa.table(
        "object_access_entries",
        sa.column("entity_type", sa.String()),
        sa.column("entity_identifier", sa.String()),
        sa.column("target_type", sa.String()),
        sa.column("target_identifier", sa.String()),
        sa.column("access_type", sa.String()),
        sa.column("start_time", sa.Double()),
        sa.column("end_time", sa.Double()),
    )
    block_entries_tbl = sa.table(
        "userblock_entries",
        sa.column("block_id", sa.String()),
        sa.column("user_id", sa.Uuid()),
        sa.column("timestamp", sa.Double()),
        sa.column("not_before", sa.Double()),
        sa.column("not_after", sa.Double()),
        sa.column("target_type", sa.String()),
        sa.column("target_id", sa.String()),
    )
    block_sub_entries_tbl = sa.table(
        "userblock_sub_entries",
        sa.column("parent_id", sa.String()),
        sa.column("block_type", sa.String()),
    )

    # Seed representative pre-migration data including nested folders, active and
    # soft-deleted documents, chained revisions, legacy rules/blocks, and permissions.
    # Root initially has inherit=True so upgrade() must flip it to False.
    for fid, name, parent_id, inherit, created_time in (
        ("/", "/", None, True, 1.0),
        ("sub-dir", "SubDir", "/", True, 2.0),
        ("leaf-dir", "LeafDir", "sub-dir", True, 3.0),
    ):
        connection.execute(
            nodes_tbl.insert().values(
                id=fid,
                type="directory",
                name=name,
                parent_id=parent_id,
                inherit=inherit,
                status=0,
                status_operation_id=None,
                access_rule_set_id=None,
            )
        )
        connection.execute(
            folders_tbl.insert().values(id=fid, created_time=created_time)
        )

    connection.execute(
        nodes_tbl.insert(),
        [
            {
                "id": "doc-1",
                "type": "document",
                "name": "Doc1",
                "parent_id": "leaf-dir",
                "inherit": True,
                "status": 0,
                "status_operation_id": None,
                "access_rule_set_id": None,
            },
            {
                "id": "doc-deleted",
                "type": "document",
                "name": "DocDeleted",
                "parent_id": "leaf-dir",
                "inherit": True,
                "status": 1,
                "status_operation_id": "op-del-1",
                "access_rule_set_id": None,
            },
        ],
    )
    connection.execute(
        documents_tbl.insert(),
        [
            {"id": "doc-1", "created_time": 4.0, "current_revision_id": None},
            {"id": "doc-deleted", "created_time": 4.5, "current_revision_id": None},
        ],
    )
    connection.execute(
        files_tbl.insert(),
        [
            {
                "id": "file-1",
                "path": "/f1",
                "active": True,
                "size": 10,
                "created_time": 1.0,
            },
            {
                "id": "file-2",
                "path": "/f2",
                "active": True,
                "size": 20,
                "created_time": 2.0,
            },
        ],
    )
    connection.execute(
        revisions_tbl.insert(),
        [
            {
                "id": "rev-parent-z",
                "document_id": "doc-1",
                "file_id": "file-1",
                "created_time": 4.0,
                "parent_revision_id": None,
                "status": 0,
            },
            {
                "id": "rev-child-a",
                "document_id": "doc-1",
                "file_id": "file-2",
                "created_time": 5.0,
                "parent_revision_id": "rev-parent-z",
                "status": 0,
            },
        ],
    )
    connection.execute(
        documents_tbl.update()
        .where(documents_tbl.c.id == "doc-1")
        .values(current_revision_id="rev-child-a")
    )
    connection.execute(metadata_tbl.insert().values(document_id="doc-1"))
    connection.execute(
        tags_tbl.insert(),
        [
            {"document_id": "doc-1", "tag": "alpha", "position": 0},
            {"document_id": "doc-1", "tag": "beta", "position": 1},
        ],
    )

    # Seed legacy compiled access rules, object access entries, and user blocks.
    connection.execute(
        rule_sets_tbl.insert().values(id="ruleset-1", node_id="sub-dir", created_at=2.0)
    )
    connection.execute(
        nodes_tbl.update()
        .where(nodes_tbl.c.id == "sub-dir")
        .values(access_rule_set_id="ruleset-1")
    )
    inserted_rule = connection.execute(
        rules_tbl.insert().values(
            id=1, rule_set_id="ruleset-1", access_type="read", match_mode="any"
        )
    )
    del inserted_rule
    connection.execute(
        rule_groups_tbl.insert().values(
            id="rulegroup-1",
            rule_id=1,
            group_index=0,
            match_mode="all",
            rights_match_mode="all",
            rights_empty=False,
            groups_match_mode="all",
            groups_empty=False,
        )
    )
    connection.execute(
        rule_memberships_tbl.insert().values(group_id="rulegroup-1", group_name="user")
    )
    connection.execute(
        rule_rights_tbl.insert().values(group_id="rulegroup-1", permission="search")
    )
    connection.execute(
        access_entries_tbl.insert().values(
            entity_type="group",
            entity_identifier="user",
            target_type="folder",
            target_identifier="sub-dir",
            access_type="read",
            start_time=0.0,
            end_time=None,
        )
    )

    test_uid = uuid.UUID("11111111-1111-4111-8111-111111111111")
    connection.execute(
        users_tbl.insert().values(
            id=test_uid,
            username="migrated_user",
            created_time=1.0,
            status=0,
            secret_key="s" * 64,
        )
    )
    connection.execute(
        block_entries_tbl.insert().values(
            block_id="blk-1",
            user_id=test_uid,
            timestamp=1.0,
            not_before=1.0,
            not_after=2.0,
            target_type="document",
            target_id="doc-1",
        )
    )
    connection.execute(
        block_sub_entries_tbl.insert().values(parent_id="blk-1", block_type="read")
    )
    connection.execute(
        user_groups_tbl.insert(),
        [
            {"group_name": "sysop", "group_display_name": "Sysop"},
            {"group_name": "user", "group_display_name": "User"},
        ],
    )
    connection.execute(
        group_perms_tbl.insert(),
        [
            {
                "group_name": "sysop",
                "permission": "search",
                "granted": True,
                "start_time": 0.0,
                "end_time": None,
            },
            {
                "group_name": "sysop",
                "permission": "manage_access",
                "granted": True,
                "start_time": 0.0,
                "end_time": None,
            },
            {
                "group_name": "sysop",
                "permission": "move",
                "granted": True,
                "start_time": 0.0,
                "end_time": None,
            },
            {
                "group_name": "sysop",
                "permission": Permissions.BYPASS_DACL,
                "granted": True,
                "start_time": 0.0,
                "end_time": 1.0,
            },
            {
                "group_name": "user",
                "permission": "search",
                "granted": True,
                "start_time": 0.0,
                "end_time": None,
            },
            {
                "group_name": "user",
                "permission": "create_document",
                "granted": True,
                "start_time": 0.0,
                "end_time": None,
            },
        ],
    )
    connection.execute(
        user_perms_tbl.insert(),
        [
            {
                "user_id": test_uid,
                "permission": "search",
                "granted": True,
                "start_time": 0.0,
                "end_time": None,
            },
            {
                "user_id": test_uid,
                "permission": "move",
                "granted": True,
                "start_time": 0.0,
                "end_time": None,
            },
        ],
    )
    options_table = Base.metadata.tables["options"]
    connection.execute(
        options_table.insert().values(
            namespace="access",
            owner="core",
            option_key="enable_access_recursive_check",
            schema_version=1,
            revision=1,
            value_type="bool",
            option_value="false",
            updated_at=1.0,
        )
    )
    connection.commit()

    # Upgrade to CACL head.
    command.upgrade(config, "a66108639ed7")
    tables_after = set(inspect(connection).get_table_names())
    assert {
        "dacl_rules",
        "dacl_rule_clauses",
        "dacl_rule_atoms",
    } <= tables_after
    assert tables_after.isdisjoint(
        {
            "compiled_access_rule_sets",
            "compiled_access_rules",
            "compiled_access_rule_groups",
            "compiled_access_rule_rights",
            "compiled_access_rule_memberships",
            "object_access_entries",
            "userblock_entries",
            "userblock_sub_entries",
        }
    )

    # Verify root DACL seeded by migration matches compile_cacl(DEFAULT_ROOT_DACL_SOURCE) exactly.
    expected_root_compile = compile_cacl(
        DEFAULT_ROOT_DACL_SOURCE,
        config=CompilerConfig(target_object_type=ObjectType.DIRECTORY),
    )
    assert expected_root_compile.ok
    assert expected_root_compile.policy is not None
    with Session(bind=connection) as orm_session:
        loaded_root_policy = load_node_policies(orm_session, ["/"])["/"]
    assert loaded_root_policy == expected_root_compile.policy

    # Verify sysop received permanent capabilities (despite prior expired grant) and
    # obsolete permissions were pruned from both group_permissions and user_permissions.
    sysop_permanent_perms = set(
        connection.execute(
            sa.select(group_perms_tbl.c.permission).where(
                group_perms_tbl.c.group_name == "sysop",
                group_perms_tbl.c.end_time.is_(None),
            )
        ).scalars()
    )
    assert sysop_permanent_perms == {
        Permissions.SEARCH,
        Permissions.BYPASS_DACL,
        Permissions.BYPASS_TRAVERSE_CHECKING,
    }

    user_perms = set(
        connection.execute(
            sa.select(group_perms_tbl.c.permission).where(
                group_perms_tbl.c.group_name == "user"
            )
        ).scalars()
    )
    assert user_perms == {Permissions.SEARCH}

    direct_user_perms = set(
        connection.execute(
            sa.select(user_perms_tbl.c.permission).where(
                user_perms_tbl.c.user_id == test_uid
            )
        ).scalars()
    )
    assert direct_user_perms == {Permissions.SEARCH}

    # Verify obsolete option was removed.
    opt_rows = connection.execute(
        sa.text(
            "SELECT option_key FROM options "
            "WHERE namespace = 'access' AND option_key = 'enable_access_recursive_check'"
        )
    ).fetchall()
    assert opt_rows == []

    # Verify node unique constraint and dacl_rules indexes (without redundant node_id index).
    inspector = inspect(connection)
    node_unique_constraints = {
        c["name"] for c in inspector.get_unique_constraints("nodes")
    }
    assert "uq_nodes_active_parent_name" in node_unique_constraints
    dacl_rule_indexes = {idx["name"] for idx in inspector.get_indexes("dacl_rules")}
    assert {
        "ix_dacl_rules_node_effect_scope",
        "ix_dacl_rules_validity",
    } <= dacl_rule_indexes
    assert "ix_dacl_rules_node_id" not in dacl_rule_indexes

    def _assert_content_preserved() -> None:
        nodes_rows = {
            tuple(row)
            for row in connection.execute(
                sa.text(
                    "SELECT id, type, parent_id, status, status_operation_id FROM nodes"
                )
            ).fetchall()
        }
        assert nodes_rows == {
            ("/", "directory", None, 0, None),
            ("sub-dir", "directory", "/", 0, None),
            ("leaf-dir", "directory", "sub-dir", 0, None),
            ("doc-1", "document", "leaf-dir", 0, None),
            ("doc-deleted", "document", "leaf-dir", 1, "op-del-1"),
        }
        doc_rows = {
            tuple(row)
            for row in connection.execute(
                sa.text("SELECT id, current_revision_id FROM documents")
            ).fetchall()
        }
        assert doc_rows == {("doc-1", "rev-child-a"), ("doc-deleted", None)}
        rev_rows = {
            tuple(row)
            for row in connection.execute(
                sa.text(
                    "SELECT id, document_id, parent_revision_id FROM document_revisions"
                )
            ).fetchall()
        }
        assert rev_rows == {
            ("rev-parent-z", "doc-1", None),
            ("rev-child-a", "doc-1", "rev-parent-z"),
        }
        meta_rows = [
            tuple(row)
            for row in connection.execute(
                sa.text("SELECT document_id FROM document_metadata")
            ).fetchall()
        ]
        assert meta_rows == [("doc-1",)]
        tag_rows = [
            tuple(row)
            for row in connection.execute(
                sa.text(
                    "SELECT document_id, tag, position FROM document_metadata_tags ORDER BY position"
                )
            ).fetchall()
        ]
        assert tag_rows == [("doc-1", "alpha", 0), ("doc-1", "beta", 1)]

    _assert_content_preserved()
    if after_transition is not None:
        after_transition(connection)
    connection.commit()

    # Seed new bypass_traverse_checking option before downgrade to verify cleanup.
    connection.execute(
        options_table.insert().values(
            namespace="access",
            owner="core",
            option_key="bypass_traverse_checking",
            schema_version=1,
            revision=1,
            value_type="bool",
            option_value="true",
            updated_at=2.0,
        )
    )
    connection.commit()

    # Downgrade back to e952c02c1454 and verify schema restoration & cleanup.
    command.downgrade(config, "e952c02c1454")
    tables_downgraded = set(inspect(connection).get_table_names())
    assert {
        "compiled_access_rule_sets",
        "object_access_entries",
        "userblock_entries",
    } <= tables_downgraded
    assert tables_downgraded.isdisjoint(
        {"dacl_rules", "dacl_rule_clauses", "dacl_rule_atoms"}
    )
    sysop_permanent_down = set(
        connection.execute(
            sa.select(group_perms_tbl.c.permission).where(
                group_perms_tbl.c.group_name == "sysop",
                group_perms_tbl.c.end_time.is_(None),
            )
        ).scalars()
    )
    assert Permissions.BYPASS_DACL not in sysop_permanent_down
    assert Permissions.BYPASS_TRAVERSE_CHECKING not in sysop_permanent_down
    # Pre-existing expired grant was NOT removed by downgrade.
    expired_down = connection.execute(
        sa.select(group_perms_tbl.c.end_time).where(
            group_perms_tbl.c.group_name == "sysop",
            group_perms_tbl.c.permission == Permissions.BYPASS_DACL,
        )
    ).all()
    assert expired_down == [(1.0,)]
    assert (
        connection.execute(
            sa.text(
                "SELECT option_key FROM options "
                "WHERE namespace = 'access' AND option_key = 'bypass_traverse_checking'"
            )
        ).fetchall()
        == []
    )
    _assert_content_preserved()
    if after_transition is not None:
        after_transition(connection)
    connection.commit()

    # Re-upgrade to head to verify repeatability.
    command.upgrade(config, "head")
    _assert_content_preserved()
    if after_transition is not None:
        after_transition(connection)


def test_cacl_migration_upgrade_and_downgrade_round_trip(sqlite_engine_factory):
    engine = sqlite_engine_factory()
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        config = Config(_ROOT / "src/alembic.ini")
        config.attributes["connection"] = connection
        command.stamp(config, "head")

        def _check_sqlite_fks(conn: Connection) -> None:
            raw = conn.connection.driver_connection
            assert raw is not None
            assert raw.execute("PRAGMA foreign_key_check").fetchall() == []
            sqlite_node_indexes = {
                row[0]
                for row in conn.execute(
                    sa.text(
                        "SELECT name FROM sqlite_master "
                        "WHERE type = 'index' AND tbl_name = 'nodes'"
                    )
                ).fetchall()
            }
            assert {
                "ix_nodes_parent_status_lower_name_id",
                "ix_nodes_status_lower_name_id",
            } <= sqlite_node_indexes

        run_cacl_migration_round_trip(
            connection, config, after_transition=_check_sqlite_fks
        )


def test_cacl_migration_preserves_extension_tables_referencing_nodes(
    sqlite_engine_factory,
):
    engine = sqlite_engine_factory()
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        config = Config(_ROOT / "src/alembic.ini")
        config.attributes["connection"] = connection
        command.stamp(config, "head")
        command.downgrade(config, "e952c02c1454")

        connection.execute(
            sa.text(
                "CREATE TABLE ext_node_notes ("
                "id INTEGER PRIMARY KEY, "
                "node_id VARCHAR(255) NOT NULL REFERENCES nodes(id) ON DELETE CASCADE, "
                "note TEXT NOT NULL)"
            )
        )
        connection.execute(
            sa.text(
                "CREATE TABLE ext_doc_bookmarks ("
                "id INTEGER PRIMARY KEY, "
                "document_id VARCHAR(255) NOT NULL REFERENCES documents(id) ON DELETE CASCADE, "
                "label TEXT NOT NULL)"
            )
        )
        connection.execute(
            sa.text(
                "INSERT INTO nodes (id, type, name, parent_id, inherit, status) "
                "VALUES ('/', 'directory', '/', NULL, FALSE, 0)"
            )
        )
        connection.execute(
            sa.text("INSERT INTO folders (id, created_time) VALUES ('/', 1.0)")
        )
        connection.execute(
            sa.text(
                "INSERT INTO nodes (id, type, name, parent_id, inherit, status) "
                "VALUES ('ext-doc', 'document', 'ExtDoc', '/', TRUE, 0)"
            )
        )
        connection.execute(
            sa.text(
                "INSERT INTO documents (id, created_time, current_revision_id) "
                "VALUES ('ext-doc', 2.0, NULL)"
            )
        )
        connection.execute(
            sa.text(
                "INSERT INTO ext_node_notes (id, node_id, note) "
                "VALUES (1, 'ext-doc', 'keep-node-note')"
            )
        )
        connection.execute(
            sa.text(
                "INSERT INTO ext_doc_bookmarks (id, document_id, label) "
                "VALUES (1, 'ext-doc', 'keep-doc-bookmark')"
            )
        )
        connection.commit()

        command.upgrade(config, "a66108639ed7")
        assert connection.execute(
            sa.text("SELECT id, node_id, note FROM ext_node_notes")
        ).fetchall() == [(1, "ext-doc", "keep-node-note")]
        assert connection.execute(
            sa.text("SELECT id, document_id, label FROM ext_doc_bookmarks")
        ).fetchall() == [(1, "ext-doc", "keep-doc-bookmark")]
        raw = connection.connection.driver_connection
        assert raw is not None
        assert raw.execute("PRAGMA foreign_key_check").fetchall() == []

        command.downgrade(config, "e952c02c1454")
        assert connection.execute(
            sa.text("SELECT id, node_id, note FROM ext_node_notes")
        ).fetchall() == [(1, "ext-doc", "keep-node-note")]
        assert connection.execute(
            sa.text("SELECT id, document_id, label FROM ext_doc_bookmarks")
        ).fetchall() == [(1, "ext-doc", "keep-doc-bookmark")]
        assert raw.execute("PRAGMA foreign_key_check").fetchall() == []


def test_cacl_migration_mysql_ddl_drops_fks_before_indexes():
    module = _load_cacl_migration_module()

    drop_buf = io.StringIO()
    drop_ctx = MigrationContext.configure(
        dialect_name="mysql",
        opts={"as_sql": True, "output_buffer": drop_buf, "target_metadata": None},
    )
    with Operations.context(drop_ctx):
        module._alter_nodes_access_rule_set_column(drop=True)
    drop_sql = drop_buf.getvalue()
    fk_drop_pos = drop_sql.index("DROP FOREIGN KEY")
    idx_drop_pos = drop_sql.index("DROP INDEX")
    col_drop_pos = drop_sql.index("DROP COLUMN")
    assert fk_drop_pos < idx_drop_pos < col_drop_pos

    restore_buf = io.StringIO()
    restore_ctx = MigrationContext.configure(
        dialect_name="mysql",
        opts={"as_sql": True, "output_buffer": restore_buf, "target_metadata": None},
    )
    with Operations.context(restore_ctx):
        module._alter_nodes_access_rule_set_column(drop=False)
    restore_sql = restore_buf.getvalue()
    add_col_pos = restore_sql.index("ADD COLUMN")
    create_idx_pos = restore_sql.index("CREATE INDEX")
    add_fk_pos = restore_sql.index("FOREIGN KEY")
    assert add_col_pos < create_idx_pos < add_fk_pos

    # Neither upgrade() nor downgrade() should issue drop_index before drop_table().
    tree = ast.parse(_MIGRATION_PATH.read_text(encoding="utf-8"))
    for func in tree.body:
        if isinstance(func, ast.FunctionDef) and func.name in ("upgrade", "downgrade"):
            drop_index_calls = [
                node
                for node in ast.walk(func)
                if isinstance(node, ast.Attribute) and node.attr == "drop_index"
            ]
            assert drop_index_calls == []
