from collections.abc import Mapping
from pathlib import Path
from typing import Any

from sqlalchemy import Table, insert
from sqlalchemy.exc import IntegrityError

from include.domains.documents.commands.name_conflicts import is_node_name_conflict
from maintenance.backup.legacy import _load_legacy_node_rows
from maintenance.backup.models import BackupFormatError
from maintenance.backup.rows import _load_table_rows


def _restore_node_tables(
    connection,
    extract_dir: Path,
    manifest: dict[str, Any],
    tables: Mapping[str, Table],
    deferred_updates: dict[str, list[dict[str, Any]]],
    legacy_namespace: dict[str, dict[str, Any]],
) -> set[str]:
    table_names = manifest.get("tables", {})
    node_table_names = {"nodes", "folders", "documents"} & set(table_names)
    if not node_table_names:
        return set()

    if "nodes" in table_names:
        node_rows = {
            str(row["id"]): row
            for row in _load_table_rows(extract_dir, manifest, tables["nodes"])
        }
        for node_id, namespace in legacy_namespace.items():
            row = node_rows.get(node_id)
            if row is None:
                continue
            if row.get("name") is None:
                row["name"] = namespace["name"]
            if node_id != "/" and row.get("parent_id") is None:
                row["parent_id"] = namespace["parent_id"]
    else:
        node_rows = _load_legacy_node_rows(extract_dir, manifest)

    folder_rows = {
        str(row["id"]): row
        for row in (
            _load_table_rows(extract_dir, manifest, tables["folders"])
            if "folders" in table_names
            else []
        )
    }
    document_rows = {
        str(row["id"]): row
        for row in (
            _load_table_rows(extract_dir, manifest, tables["documents"])
            if "documents" in table_names
            else []
        )
    }

    if node_rows and "/" not in node_rows:
        node_rows["/"] = {
            "id": "/",
            "type": "directory",
            "inherit": True,
            "status": 0,
            "status_operation_id": None,
            "access_rule_set_id": None,
            "name": "/",
            "parent_id": None,
        }
    if node_rows and "/" not in folder_rows:
        folder_rows["/"] = {"id": "/", "created_time": 0.0}

    folder_node_ids = {
        node_id for node_id, row in node_rows.items() if row["type"] == "directory"
    }
    document_node_ids = {
        node_id for node_id, row in node_rows.items() if row["type"] == "document"
    }
    if folder_node_ids != set(folder_rows):
        raise BackupFormatError("Backup node and folder rows do not match")
    if document_node_ids != set(document_rows):
        raise BackupFormatError("Backup node and document rows do not match")

    pending_folders = set(folder_node_ids)
    restored_folders: set[str] = set()
    while pending_folders:
        ready = sorted(
            node_id
            for node_id in pending_folders
            if node_id == "/" or node_rows[node_id]["parent_id"] in restored_folders
        )
        if not ready:
            raise BackupFormatError(
                "Backup folder hierarchy contains a cycle or missing parent"
            )
        for node_id in ready:
            _insert_restored_node(
                connection,
                tables["nodes"],
                node_rows[node_id],
                deferred_updates,
            )
            connection.execute(insert(tables["folders"]), folder_rows[node_id])
            restored_folders.add(node_id)
            pending_folders.remove(node_id)

    for node_id in sorted(document_node_ids):
        node_row = node_rows[node_id]
        if node_row["parent_id"] not in restored_folders:
            raise BackupFormatError(
                f"Backup document {node_id!r} references a missing folder"
            )
        _insert_restored_node(
            connection,
            tables["nodes"],
            node_row,
            deferred_updates,
        )
        document_row = document_rows[node_id]
        deferred_updates.setdefault("documents", []).append(document_row.copy())
        insert_row = document_row.copy()
        insert_row["current_revision_id"] = None
        connection.execute(insert(tables["documents"]), insert_row)

    return node_table_names


def _insert_restored_node(
    connection,
    table: Table,
    row: dict[str, Any],
    deferred_updates: dict[str, list[dict[str, Any]]],
) -> None:
    deferred_updates.setdefault("nodes", []).append(row.copy())
    insert_row = row.copy()
    insert_row["access_rule_set_id"] = None
    try:
        connection.execute(insert(table), insert_row)
    except IntegrityError as exc:
        if not is_node_name_conflict(exc):
            raise
        raise BackupFormatError(
            "Backup contains an active sibling name conflict while restoring "
            f"{row['type']}:{row['id']} under parent {row['parent_id']!r} "
            f"with name {row['name']!r}"
        ) from exc
