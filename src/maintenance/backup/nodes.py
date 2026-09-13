import sqlite3
import tempfile
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import orjson
from sqlalchemy import Table, insert
from sqlalchemy.exc import IntegrityError

from include.domains.documents.commands.name_conflicts import is_node_name_conflict
from maintenance.backup.models import BackupFormatError
from maintenance.backup.rows import (
    _decode_row,
    _iter_raw_table_row_batches,
    _iter_table_row_batches,
)


def _restore_node_tables(
    connection,
    extract_dir: Path,
    manifest: dict[str, Any],
    tables: Mapping[str, Table],
) -> set[str]:
    table_names = manifest.get("tables", {})
    node_table_names = {"nodes", "folders", "documents"} & set(table_names)
    if not node_table_names:
        return set()

    with tempfile.TemporaryDirectory(
        prefix="cfms-backup-node-index-",
        dir=extract_dir.parent,
    ) as index_dir:
        index = sqlite3.connect(Path(index_dir) / "nodes.sqlite3")
        try:
            _create_node_index(index)
            _load_node_index(index, extract_dir, manifest, tables)
            _restore_indexed_nodes(connection, index, tables)
        finally:
            index.close()
    return node_table_names


def _create_node_index(index: sqlite3.Connection) -> None:
    index.execute(
        """
        CREATE TABLE staged_nodes (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            parent_id TEXT,
            node BLOB NOT NULL,
            subtype BLOB,
            subtype_kind TEXT
        )
        """
    )
    index.execute("CREATE INDEX ix_staged_nodes_parent ON staged_nodes(parent_id)")


def _load_node_index(
    index: sqlite3.Connection,
    extract_dir: Path,
    manifest: dict[str, Any],
    tables: Mapping[str, Table],
) -> None:
    has_node_rows = "nodes" in manifest["tables"]
    try:
        if has_node_rows:
            for batch in _iter_table_row_batches(
                extract_dir,
                manifest,
                tables["nodes"],
            ):
                index.executemany(
                    "INSERT INTO staged_nodes(id, type, parent_id, node) "
                    "VALUES (?, ?, ?, ?)",
                    (
                        (
                            str(row["id"]),
                            str(row["type"]),
                            row.get("parent_id"),
                            orjson.dumps(row),
                        )
                        for row in batch
                    ),
                )

        for table_name, node_type in (
            ("folders", "directory"),
            ("documents", "document"),
        ):
            if table_name not in manifest["tables"]:
                continue
            for batch in _iter_raw_table_row_batches(
                extract_dir,
                manifest,
                table_name,
            ):
                if has_node_rows:
                    _attach_subtype_rows(index, batch, node_type)
                else:
                    _insert_legacy_subtype_rows(index, batch, node_type)

        node_count = index.execute("SELECT count(*) FROM staged_nodes").fetchone()[0]
        if (
            node_count
            and not index.execute(
                "SELECT 1 FROM staged_nodes WHERE id = '/'"
            ).fetchone()
        ):
            root_node = {
                "id": "/",
                "type": "directory",
                "inherit": True,
                "status": 0,
                "status_operation_id": None,
                "access_rule_set_id": None,
                "name": "/",
                "parent_id": None,
            }
            root_folder = {"id": "/", "created_time": 0.0}
            index.execute(
                "INSERT INTO staged_nodes "
                "(id, type, parent_id, node, subtype, subtype_kind) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (
                    "/",
                    "directory",
                    None,
                    orjson.dumps(root_node),
                    orjson.dumps(root_folder),
                    "directory",
                ),
            )
        elif node_count:
            index.execute(
                "UPDATE staged_nodes SET subtype = ?, subtype_kind = 'directory' "
                "WHERE id = '/' AND type = 'directory' AND subtype IS NULL",
                (orjson.dumps({"id": "/", "created_time": 0.0}),),
            )
    except sqlite3.IntegrityError as exc:
        raise BackupFormatError("Backup contains duplicate node identifiers") from exc

    invalid = index.execute(
        """
        SELECT id
        FROM staged_nodes
        WHERE subtype IS NULL
           OR subtype_kind != type
           OR type NOT IN ('directory', 'document')
        LIMIT 1
        """
    ).fetchone()
    if invalid is not None:
        raise BackupFormatError(
            f"Backup node and subtype rows do not match for {invalid[0]!r}"
        )
    index.commit()


def _attach_subtype_rows(
    index: sqlite3.Connection,
    rows: list[dict[str, Any]],
    node_type: str,
) -> None:
    for row in rows:
        node_id = str(row["id"])
        legacy_parent_id = row.get(
            "parent_id" if node_type == "directory" else "folder_id"
        )
        if node_id != "/" and legacy_parent_id is None:
            legacy_parent_id = "/"
        result = index.execute(
            "UPDATE staged_nodes SET subtype = ?, subtype_kind = ?, "
            "parent_id = CASE WHEN id = '/' THEN parent_id "
            "ELSE coalesce(parent_id, ?) END "
            "WHERE id = ? AND type = ? AND subtype IS NULL",
            (
                orjson.dumps(row),
                node_type,
                legacy_parent_id,
                node_id,
                node_type,
            ),
        )
        if result.rowcount != 1:
            raise BackupFormatError(
                f"Backup node and subtype rows do not match for {row['id']!r}"
            )


def _insert_legacy_subtype_rows(
    index: sqlite3.Connection,
    rows: list[dict[str, Any]],
    node_type: str,
) -> None:
    for row in rows:
        node_id = str(row["id"])
        parent_id = row.get("parent_id" if node_type == "directory" else "folder_id")
        if node_id != "/" and parent_id is None:
            parent_id = "/"
        node = {
            "id": node_id,
            "type": node_type,
            "inherit": row.get("inherit", True),
            "status": row.get("status", 0),
            "status_operation_id": row.get("status_operation_id"),
            "access_rule_set_id": None,
            "name": row.get("name" if node_type == "directory" else "title"),
            "parent_id": parent_id,
        }
        index.execute(
            "INSERT INTO staged_nodes "
            "(id, type, parent_id, node, subtype, subtype_kind) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                node_id,
                node_type,
                parent_id,
                orjson.dumps(node),
                orjson.dumps(row),
                node_type,
            ),
        )


def _restore_indexed_nodes(
    connection,
    index: sqlite3.Connection,
    tables: Mapping[str, Table],
) -> None:
    restored_folders = 0
    folder_rows = index.execute(
        """
        WITH RECURSIVE hierarchy(id, depth) AS (
            SELECT id, 0
            FROM staged_nodes
            WHERE id = '/' AND type = 'directory' AND parent_id IS NULL
            UNION ALL
            SELECT child.id, hierarchy.depth + 1
            FROM staged_nodes AS child
            JOIN hierarchy ON child.parent_id = hierarchy.id
            WHERE child.type = 'directory'
        )
        SELECT staged_nodes.node, staged_nodes.subtype
        FROM hierarchy
        JOIN staged_nodes ON staged_nodes.id = hierarchy.id
        ORDER BY hierarchy.depth, hierarchy.id
        """
    )
    for node_payload, subtype_payload in folder_rows:
        node = _merge_legacy_namespace(
            orjson.loads(node_payload),
            orjson.loads(subtype_payload),
        )
        _insert_restored_node(connection, tables["nodes"], node)
        folder = _decode_row(orjson.loads(subtype_payload), tables["folders"])
        connection.execute(insert(tables["folders"]), folder)
        restored_folders += 1

    expected_folders = index.execute(
        "SELECT count(*) FROM staged_nodes WHERE type = 'directory'"
    ).fetchone()[0]
    if restored_folders != expected_folders:
        raise BackupFormatError(
            "Backup folder hierarchy contains a cycle or missing parent"
        )

    missing_parent = index.execute(
        """
        SELECT document.id
        FROM staged_nodes AS document
        LEFT JOIN staged_nodes AS parent
          ON parent.id = document.parent_id AND parent.type = 'directory'
        WHERE document.type = 'document' AND parent.id IS NULL
        LIMIT 1
        """
    ).fetchone()
    if missing_parent is not None:
        raise BackupFormatError(
            f"Backup document {missing_parent[0]!r} references a missing folder"
        )

    for node_payload, subtype_payload in index.execute(
        "SELECT node, subtype FROM staged_nodes WHERE type = 'document' ORDER BY id"
    ):
        node = _merge_legacy_namespace(
            orjson.loads(node_payload),
            orjson.loads(subtype_payload),
        )
        _insert_restored_node(connection, tables["nodes"], node)
        document = _decode_row(orjson.loads(subtype_payload), tables["documents"])
        document["current_revision_id"] = None
        connection.execute(insert(tables["documents"]), document)


def _merge_legacy_namespace(
    node: dict[str, Any],
    subtype: dict[str, Any],
) -> dict[str, Any]:
    if node.get("name") is None:
        node["name"] = subtype.get("name", subtype.get("title"))
    if node["id"] != "/" and node.get("parent_id") is None:
        node["parent_id"] = subtype.get("parent_id", subtype.get("folder_id", "/"))
    return node


def _insert_restored_node(
    connection,
    table: Table,
    row: dict[str, Any],
) -> None:
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
