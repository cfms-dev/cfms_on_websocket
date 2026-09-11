import pytest
from sqlalchemy import select

from .support import (
    _new_database,
    _write_jsonl,
)


def test_backup_with_nodes_and_legacy_subtype_names_is_upgraded(
    backup_context, tmp_path
):
    from maintenance.backup.archive import _validate_manifest
    from maintenance.backup.format import BACKUP_FORMAT_VERSION
    from maintenance.backup.restore import _restore_database

    base = backup_context.Base
    target_engine, target_session = _new_database(base, tmp_path / "target.db")
    extract_dir = tmp_path / "legacy-node-payload"
    tables_dir = extract_dir / "tables"
    tables_dir.mkdir(parents=True)

    rows_by_table = {
        "nodes": [
            {"id": "/", "type": "directory", "inherit": True, "status": 0},
            {"id": "folder-old", "type": "directory", "inherit": True, "status": 0},
            {"id": "doc-old", "type": "document", "inherit": True, "status": 0},
        ],
        "folders": [
            {"id": "/", "name": "/", "parent_id": None, "created_time": 1.0},
            {
                "id": "folder-old",
                "name": "Archive",
                "parent_id": "/",
                "created_time": 2.0,
            },
        ],
        "documents": [
            {
                "id": "doc-old",
                "title": "Report",
                "folder_id": "folder-old",
                "created_time": 3.0,
                "current_revision_id": None,
            }
        ],
    }
    for table_name, rows in rows_by_table.items():
        _write_jsonl(tables_dir / f"{table_name}.jsonl", rows)
    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["documents"],
        "tables": {
            table_name: {"columns": list(rows[0]), "rows": len(rows)}
            for table_name, rows in rows_by_table.items()
        },
        "files": [],
        "configuration": {},
    }

    _validate_manifest(manifest)
    _restore_database(extract_dir, manifest, target_session)

    nodes = base.metadata.tables["nodes"]
    with target_engine.connect() as connection:
        restored = {
            row["id"]: (row["name"], row["parent_id"])
            for row in connection.execute(select(nodes)).mappings()
        }
    assert restored == {
        "/": ("/", None),
        "folder-old": ("Archive", "/"),
        "doc-old": ("Report", "folder-old"),
    }


def test_legacy_backup_rejects_active_cross_type_duplicate(backup_context, tmp_path):
    from maintenance.backup.archive import _validate_manifest
    from maintenance.backup.format import BACKUP_FORMAT_VERSION
    from maintenance.backup.restore import _restore_database

    base = backup_context.Base
    _, target_session = _new_database(base, tmp_path / "target.db")
    extract_dir = tmp_path / "duplicate-payload"
    tables_dir = extract_dir / "tables"
    tables_dir.mkdir(parents=True)
    rows_by_table = {
        "folders": [
            {"id": "/", "name": "/", "parent_id": None, "created_time": 1.0},
            {"id": "folder", "name": "Same", "parent_id": "/", "created_time": 2.0},
        ],
        "documents": [
            {
                "id": "document",
                "title": "Same",
                "folder_id": "/",
                "created_time": 3.0,
                "current_revision_id": None,
            }
        ],
    }
    for table_name, rows in rows_by_table.items():
        _write_jsonl(tables_dir / f"{table_name}.jsonl", rows)
    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["documents"],
        "tables": {
            table_name: {"columns": list(rows[0]), "rows": len(rows)}
            for table_name, rows in rows_by_table.items()
        },
        "files": [],
        "configuration": {},
    }

    _validate_manifest(manifest)
    with pytest.raises(
        backup_context.BackupFormatError,
        match="document:document.*parent '/'.*name 'Same'",
    ):
        _restore_database(extract_dir, manifest, target_session)
