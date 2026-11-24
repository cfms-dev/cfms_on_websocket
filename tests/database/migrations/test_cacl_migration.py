"""Tests for Alembic migration a66108639ed7 (CACL DACL schema & data migration)."""

from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import inspect

import include.database.models  # noqa: F401
from alembic import command
from include.database.session import Base
from include.domains.access.permissions import Permissions

pytestmark = pytest.mark.component
_ROOT = Path(__file__).resolve().parents[3]


def test_cacl_migration_upgrade_and_downgrade_round_trip(sqlite_engine_factory):
    engine = sqlite_engine_factory()
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        config = Config(_ROOT / "src/alembic.ini")
        config.attributes["connection"] = connection

        command.stamp(config, "head")
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
        # chained revisions, and metadata to verify SQLite FK-safe preservation.
        for fid, name, parent_id, inherit, created_time in (
            ("/", "/", None, 0, 1.0),
            ("sub-dir", "SubDir", "/", 1, 2.0),
            ("leaf-dir", "LeafDir", "sub-dir", 1, 3.0),
        ):
            connection.exec_driver_sql(
                "INSERT INTO nodes (id, type, name, parent_id, inherit, status) "
                "VALUES (?, 'directory', ?, ?, ?, 0)",
                (fid, name, parent_id, inherit),
            )
            connection.exec_driver_sql(
                "INSERT INTO folders (id, created_time) VALUES (?, ?)",
                (fid, created_time),
            )
        connection.exec_driver_sql(
            "INSERT INTO nodes (id, type, name, parent_id, inherit, status) "
            "VALUES ('doc-1', 'document', 'Doc1', 'leaf-dir', 1, 0)"
        )
        connection.exec_driver_sql(
            "INSERT INTO documents (id, created_time, current_revision_id) "
            "VALUES ('doc-1', 4.0, NULL)"
        )
        connection.exec_driver_sql(
            "INSERT INTO files (id, path, active, size, created_time) "
            "VALUES ('file-1', '/f1', 1, 10, 1.0), ('file-2', '/f2', 1, 20, 2.0)"
        )
        connection.exec_driver_sql(
            "INSERT INTO document_revisions "
            "(id, document_id, file_id, created_time, parent_revision_id, status) "
            "VALUES "
            "('rev-parent-z', 'doc-1', 'file-1', 4.0, NULL, 0), "
            "('rev-child-a', 'doc-1', 'file-2', 5.0, 'rev-parent-z', 0)"
        )
        connection.exec_driver_sql(
            "UPDATE documents SET current_revision_id = 'rev-child-a' WHERE id = 'doc-1'"
        )
        connection.exec_driver_sql(
            "INSERT INTO document_metadata (document_id) VALUES ('doc-1')"
        )
        connection.exec_driver_sql(
            "INSERT INTO document_metadata_tags (document_id, tag, position) "
            "VALUES ('doc-1', 'alpha', 0), ('doc-1', 'beta', 1)"
        )
        connection.exec_driver_sql(
            "INSERT INTO user_groups (group_name, group_display_name) "
            "VALUES ('sysop', 'Sysop'), ('user', 'User')"
        )
        connection.exec_driver_sql(
            "INSERT INTO group_permissions (group_name, permission, granted, start_time) "
            "VALUES "
            "('sysop', 'search', 1, 0.0), "
            "('sysop', 'manage_access', 1, 0.0), "
            "('sysop', 'move', 1, 0.0), "
            "('user', 'search', 1, 0.0), "
            "('user', 'create_document', 1, 0.0)"
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

        # Verify root DACL seeded and root inherit=0.
        root_rules = connection.exec_driver_sql(
            "SELECT effect, permission_mask, scope FROM dacl_rules WHERE node_id = '/'"
        ).fetchall()
        assert len(root_rules) == 2
        assert all(row[0] == "allow" for row in root_rules)

        # Verify sysop received new permissions and obsolete permissions were pruned.
        sysop_perms = set(
            connection.exec_driver_sql(
                "SELECT permission FROM group_permissions WHERE group_name = 'sysop'"
            ).scalars()
        )
        assert Permissions.BYPASS_DACL in sysop_perms
        assert Permissions.BYPASS_TRAVERSE_CHECKING in sysop_perms
        assert Permissions.SEARCH in sysop_perms
        assert "manage_access" not in sysop_perms
        assert "move" not in sysop_perms

        user_perms = set(
            connection.exec_driver_sql(
                "SELECT permission FROM group_permissions WHERE group_name = 'user'"
            ).scalars()
        )
        assert user_perms == {Permissions.SEARCH}

        # Verify obsolete option was removed.
        opt_rows = connection.exec_driver_sql(
            "SELECT option_key FROM options WHERE namespace = 'access' AND option_key = 'enable_access_recursive_check'"
        ).fetchall()
        assert opt_rows == []

        def _assert_content_preserved() -> None:
            nodes_rows = set(
                connection.exec_driver_sql(
                    "SELECT id, type, parent_id FROM nodes"
                ).fetchall()
            )
            assert nodes_rows == {
                ("/", "directory", None),
                ("sub-dir", "directory", "/"),
                ("leaf-dir", "directory", "sub-dir"),
                ("doc-1", "document", "leaf-dir"),
            }
            doc_rows = connection.exec_driver_sql(
                "SELECT id, current_revision_id FROM documents"
            ).fetchall()
            assert doc_rows == [("doc-1", "rev-child-a")]
            rev_rows = set(
                connection.exec_driver_sql(
                    "SELECT id, document_id, parent_revision_id FROM document_revisions"
                ).fetchall()
            )
            assert rev_rows == {
                ("rev-parent-z", "doc-1", None),
                ("rev-child-a", "doc-1", "rev-parent-z"),
            }
            meta_rows = connection.exec_driver_sql(
                "SELECT document_id FROM document_metadata"
            ).fetchall()
            assert meta_rows == [("doc-1",)]
            tag_rows = connection.exec_driver_sql(
                "SELECT document_id, tag, position FROM document_metadata_tags ORDER BY position"
            ).fetchall()
            assert tag_rows == [("doc-1", "alpha", 0), ("doc-1", "beta", 1)]

        _assert_content_preserved()

        raw = connection.connection.driver_connection
        assert raw.execute("PRAGMA foreign_key_check").fetchall() == []

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
            connection.exec_driver_sql(
                "SELECT permission FROM group_permissions WHERE group_name = 'sysop'"
            ).scalars()
        )
        assert Permissions.BYPASS_DACL not in sysop_perms_down
        assert Permissions.BYPASS_TRAVERSE_CHECKING not in sysop_perms_down
        _assert_content_preserved()
        assert raw.execute("PRAGMA foreign_key_check").fetchall() == []

        # Re-upgrade to head to verify repeatability.
        command.upgrade(config, "head")
        _assert_content_preserved()
        assert raw.execute("PRAGMA foreign_key_check").fetchall() == []
