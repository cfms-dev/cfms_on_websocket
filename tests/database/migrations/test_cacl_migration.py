"""Tests for Alembic migration a66108639ed7 (CACL DACL schema & data migration)."""

import ast
import importlib.util
import io
from collections.abc import Callable
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.config import Config
from alembic.operations import Operations
from alembic.runtime.migration import MigrationContext
from sqlalchemy import Connection, inspect

import include.database.models  # noqa: F401
from alembic import command
from include.database.session import Base
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

    # Seed representative pre-migration data including nested folders, documents,
    # chained revisions, and metadata to verify FK-safe preservation.
    for fid, name, parent_id, inherit, created_time in (
        ("/", "/", None, 0, 1.0),
        ("sub-dir", "SubDir", "/", 1, 2.0),
        ("leaf-dir", "LeafDir", "sub-dir", 1, 3.0),
    ):
        connection.execute(
            sa.text(
                "INSERT INTO nodes (id, type, name, parent_id, inherit, status) "
                "VALUES (:id, 'directory', :name, :parent_id, :inherit, 0)"
            ),
            {"id": fid, "name": name, "parent_id": parent_id, "inherit": inherit},
        )
        connection.execute(
            sa.text(
                "INSERT INTO folders (id, created_time) VALUES (:id, :created_time)"
            ),
            {"id": fid, "created_time": created_time},
        )
    connection.execute(
        sa.text(
            "INSERT INTO nodes (id, type, name, parent_id, inherit, status) "
            "VALUES ('doc-1', 'document', 'Doc1', 'leaf-dir', 1, 0)"
        )
    )
    connection.execute(
        sa.text(
            "INSERT INTO documents (id, created_time, current_revision_id) "
            "VALUES ('doc-1', 4.0, NULL)"
        )
    )
    connection.execute(
        sa.text(
            "INSERT INTO files (id, path, active, size, created_time) "
            "VALUES ('file-1', '/f1', 1, 10, 1.0), ('file-2', '/f2', 1, 20, 2.0)"
        )
    )
    connection.execute(
        sa.text(
            "INSERT INTO document_revisions "
            "(id, document_id, file_id, created_time, parent_revision_id, status) "
            "VALUES "
            "('rev-parent-z', 'doc-1', 'file-1', 4.0, NULL, 0), "
            "('rev-child-a', 'doc-1', 'file-2', 5.0, 'rev-parent-z', 0)"
        )
    )
    connection.execute(
        sa.text(
            "UPDATE documents SET current_revision_id = 'rev-child-a' WHERE id = 'doc-1'"
        )
    )
    connection.execute(
        sa.text("INSERT INTO document_metadata (document_id) VALUES ('doc-1')")
    )
    connection.execute(
        sa.text(
            "INSERT INTO document_metadata_tags (document_id, tag, position) "
            "VALUES ('doc-1', 'alpha', 0), ('doc-1', 'beta', 1)"
        )
    )
    connection.execute(
        sa.text(
            "INSERT INTO user_groups (group_name, group_display_name) "
            "VALUES ('sysop', 'Sysop'), ('user', 'User')"
        )
    )
    connection.execute(
        sa.text(
            "INSERT INTO group_permissions (group_name, permission, granted, start_time) "
            "VALUES "
            "('sysop', 'search', 1, 0.0), "
            "('sysop', 'manage_access', 1, 0.0), "
            "('sysop', 'move', 1, 0.0), "
            "('user', 'search', 1, 0.0), "
            "('user', 'create_document', 1, 0.0)"
        )
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

    # Verify root DACL seeded with frozen CEP-0002 v1 masks and root inherit=False.
    root_inherit = connection.execute(
        sa.text("SELECT inherit FROM nodes WHERE id = '/'")
    ).scalar_one()
    assert bool(root_inherit) is False
    root_rules = connection.execute(
        sa.text(
            "SELECT effect, permission_mask, scope FROM dacl_rules WHERE node_id = '/'"
        )
    ).fetchall()
    assert len(root_rules) == 2
    assert all(row[0] == "allow" for row in root_rules)
    assert all(row[2] == "all" for row in root_rules)
    assert {int(row[1]) for row in root_rules} == {1043, 2097151}

    # Verify sysop received new permissions and obsolete permissions were pruned.
    sysop_perms = set(
        connection.execute(
            sa.text(
                "SELECT permission FROM group_permissions WHERE group_name = 'sysop'"
            )
        ).scalars()
    )
    assert Permissions.BYPASS_DACL in sysop_perms
    assert Permissions.BYPASS_TRAVERSE_CHECKING in sysop_perms
    assert Permissions.SEARCH in sysop_perms
    assert "manage_access" not in sysop_perms
    assert "move" not in sysop_perms

    user_perms = set(
        connection.execute(
            sa.text(
                "SELECT permission FROM group_permissions WHERE group_name = 'user'"
            )
        ).scalars()
    )
    assert user_perms == {Permissions.SEARCH}

    # Verify obsolete option was removed.
    opt_rows = connection.execute(
        sa.text(
            "SELECT option_key FROM options "
            "WHERE namespace = 'access' AND option_key = 'enable_access_recursive_check'"
        )
    ).fetchall()
    assert opt_rows == []

    def _assert_content_preserved() -> None:
        nodes_rows = {
            tuple(row)
            for row in connection.execute(
                sa.text("SELECT id, type, parent_id FROM nodes")
            ).fetchall()
        }
        assert nodes_rows == {
            ("/", "directory", None),
            ("sub-dir", "directory", "/"),
            ("leaf-dir", "directory", "sub-dir"),
            ("doc-1", "document", "leaf-dir"),
        }
        doc_rows = [
            tuple(row)
            for row in connection.execute(
                sa.text("SELECT id, current_revision_id FROM documents")
            ).fetchall()
        ]
        assert doc_rows == [("doc-1", "rev-child-a")]
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
    sysop_perms_down = set(
        connection.execute(
            sa.text(
                "SELECT permission FROM group_permissions WHERE group_name = 'sysop'"
            )
        ).scalars()
    )
    assert Permissions.BYPASS_DACL not in sysop_perms_down
    assert Permissions.BYPASS_TRAVERSE_CHECKING not in sysop_perms_down
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

        run_cacl_migration_round_trip(
            connection, config, after_transition=_check_sqlite_fks
        )


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
