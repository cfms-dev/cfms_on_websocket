from sqlalchemy import insert, select, update

from .roundtrip_support import _seed_source
from .support import (
    _new_database,
    _read_jsonl,
    _RootedStorage,
    _write_jsonl,
)


def test_legacy_access_rule_backup_rows_restore_as_compiled_rules(
    backup_context, tmp_path
):
    from maintenance.backup.archive import _validate_manifest
    from maintenance.backup.format import BACKUP_FORMAT_VERSION
    from maintenance.backup.restore import _restore_database

    base = backup_context.Base
    target_engine, target_session = _new_database(base, tmp_path / "target.db")
    extract_dir = tmp_path / "legacy-payload"
    tables_dir = extract_dir / "tables"

    folder_rows = [
        {
            "id": "folder-legacy",
            "name": "Legacy Folder",
            "created_time": 1_700_000_000.0,
            "parent_id": None,
            "status": 0,
            "status_operation_id": None,
            "inherit": True,
        }
    ]
    document_rows = [
        {
            "id": "doc-legacy",
            "title": "Legacy Document",
            "created_time": 1_700_000_001.0,
            "folder_id": "folder-legacy",
            "current_revision_id": None,
            "status": 0,
            "status_operation_id": None,
            "inherit": True,
        }
    ]
    folder_rule_rows = [
        {
            "id": 1,
            "folder_id": "folder-legacy",
            "access_type": "read",
            "rule_data": {
                "match": "all",
                "match_groups": [{"groups": {"match": "all", "require": ["sysop"]}}],
            },
        }
    ]
    document_rule_rows = [
        {
            "id": 2,
            "document_id": "doc-legacy",
            "access_type": "manage",
            "rule_data": {
                "match": "all",
                "match_groups": [
                    {"rights": {"match": "all", "require": ["list_users"]}}
                ],
            },
        }
    ]

    _write_jsonl(tables_dir / "folders.jsonl", folder_rows)
    _write_jsonl(tables_dir / "documents.jsonl", document_rows)
    _write_jsonl(tables_dir / "folder_access_rules.jsonl", folder_rule_rows)
    _write_jsonl(tables_dir / "document_access_rules.jsonl", document_rule_rows)

    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["documents"],
        "tables": {
            "folders": {"rows": len(folder_rows)},
            "documents": {"rows": len(document_rows)},
            "folder_access_rules": {"rows": len(folder_rule_rows)},
            "document_access_rules": {"rows": len(document_rule_rows)},
        },
        "files": [],
        "configuration": {},
    }

    _validate_manifest(manifest)
    _restore_database(extract_dir, manifest, target_session)

    with target_engine.connect() as connection:
        tables = base.metadata.tables
        compiled_rules_table = tables["compiled_access_rules"]
        rule_sets_table = tables["compiled_access_rule_sets"]
        compiled_rules = (
            connection.execute(
                select(
                    compiled_rules_table,
                    rule_sets_table.c.node_id.label("node_id"),
                )
                .join(
                    rule_sets_table,
                    compiled_rules_table.c.rule_set_id == rule_sets_table.c.id,
                )
                .order_by(rule_sets_table.c.node_id)
            )
            .mappings()
            .all()
        )
        memberships = (
            connection.execute(select(tables["compiled_access_rule_memberships"]))
            .mappings()
            .all()
        )
        rights = (
            connection.execute(select(tables["compiled_access_rule_rights"]))
            .mappings()
            .all()
        )
        rule_sets = (
            connection.execute(
                select(rule_sets_table).order_by(rule_sets_table.c.node_id)
            )
            .mappings()
            .all()
        )
        nodes = (
            connection.execute(select(tables["nodes"]).order_by(tables["nodes"].c.id))
            .mappings()
            .all()
        )

    assert [(row["node_id"], row["access_type"]) for row in compiled_rules] == [
        ("doc-legacy", "manage"),
        ("folder-legacy", "read"),
    ]
    assert [row["node_id"] for row in rule_sets] == ["doc-legacy", "folder-legacy"]
    assert {
        row["id"]: row["access_rule_set_id"] for row in nodes if row["id"] != "/"
    } == {row["node_id"]: row["id"] for row in rule_sets}
    assert [row["group_name"] for row in memberships] == ["sysop"]
    assert [row["permission"] for row in rights] == ["list_users"]


def test_current_access_rule_backup_manifest_uses_compiled_tables(
    backup_context, tmp_path
):
    from maintenance.backup.export import _stage_backup_payload

    base = backup_context.Base
    source_engine, source_session = _new_database(base, tmp_path / "source.db")
    source_storage = tmp_path / "source-storage"
    staging_dir = tmp_path / "staging"
    source_storage.mkdir()
    staging_dir.mkdir()
    _seed_source(base, source_engine, source_storage)
    tables = base.metadata.tables

    with source_engine.begin() as connection:
        connection.execute(
            insert(tables["nodes"]),
            [
                {
                    "id": "backup-empty-rules",
                    "type": "directory",
                    "name": "Backup Empty Rules",
                    "parent_id": "/",
                    "inherit": True,
                    "status": 0,
                    "status_operation_id": None,
                    "access_rule_set_id": None,
                },
                {
                    "id": "backup-inactive-rules",
                    "type": "directory",
                    "name": "Backup Inactive Rules",
                    "parent_id": "/",
                    "inherit": True,
                    "status": 0,
                    "status_operation_id": None,
                    "access_rule_set_id": None,
                },
            ],
        )
        connection.execute(
            insert(tables["folders"]),
            [
                {
                    "id": "backup-empty-rules",
                    "created_time": 1_700_000_010.0,
                },
                {
                    "id": "backup-inactive-rules",
                    "created_time": 1_700_000_011.0,
                },
            ],
        )
        connection.execute(
            insert(tables["compiled_access_rule_sets"]),
            [
                {
                    "id": "rule-set-empty",
                    "node_id": "backup-empty-rules",
                    "created_at": 1_700_000_010.0,
                },
                {
                    "id": "rule-set-inactive",
                    "node_id": "backup-inactive-rules",
                    "created_at": 1_700_000_011.0,
                },
            ],
        )
        connection.execute(
            update(tables["nodes"])
            .where(tables["nodes"].c.id == "backup-empty-rules")
            .values(access_rule_set_id="rule-set-empty")
        )
        connection.execute(
            insert(tables["compiled_access_rules"]),
            {
                "rule_set_id": "rule-set-inactive",
                "access_type": "read",
                "match_mode": "all",
            },
        )

    manifest = _stage_backup_payload(
        staging_dir,
        session_factory=source_session,
        storage_provider=_RootedStorage(source_storage),
        config=backup_context.source_config,
    )

    assert "compiled_access_rules" in manifest["tables"]
    assert "compiled_access_rule_sets" in manifest["tables"]
    assert "compiled_access_rule_groups" in manifest["tables"]
    assert "compiled_access_rule_memberships" in manifest["tables"]
    assert "compiled_access_rule_rights" in manifest["tables"]
    assert "document_access_rules" not in manifest["tables"]
    assert "folder_access_rules" not in manifest["tables"]

    exported_rule_sets = _read_jsonl(
        staging_dir / "tables" / "compiled_access_rule_sets.jsonl"
    )
    exported_nodes = _read_jsonl(staging_dir / "tables" / "nodes.jsonl")
    assert all("active_name" not in row for row in exported_nodes)
    assert {row["id"] for row in exported_rule_sets} == {
        "rule-set-doc-1",
        "rule-set-folder-1",
    }
    assert {
        row["id"]: row["access_rule_set_id"]
        for row in exported_nodes
        if row["id"] in {"backup-empty-rules", "backup-inactive-rules"}
    } == {
        "backup-empty-rules": None,
        "backup-inactive-rules": None,
    }
