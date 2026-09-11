import datetime as dt
import json
import secrets
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import orjson
from sqlalchemy import Table, insert, update

from include.database.models.access import (
    CompiledAccessRule,
    CompiledAccessRuleSet,
)
from include.database.models.documents import (
    Node,
)
from include.domains.access.authorization.compiled_rules import (
    compile_access_rule,
)
from maintenance.backup.archive import _safe_payload_path
from maintenance.backup.models import BackupFormatError
from maintenance.backup.selection import LEGACY_ACCESS_RULE_TABLE_NAMES


def _load_legacy_node_rows(
    extract_dir: Path,
    manifest: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    node_rows: dict[str, dict[str, Any]] = {}
    for table_name, node_type in (("folders", "directory"), ("documents", "document")):
        table_manifest = manifest.get("tables", {}).get(table_name)
        if table_manifest is None:
            continue
        path = _safe_payload_path(extract_dir, f"tables/{table_name}.jsonl")
        with path.open("rb") as f:
            rows = [orjson.loads(line) for line in f if line.strip()]
        if len(rows) != table_manifest["rows"]:
            raise BackupFormatError(
                f"Row count mismatch for table {table_name!r}: "
                f"manifest says {table_manifest['rows']}, payload has {len(rows)}"
            )
        for row in rows:
            node_id = str(row["id"])
            if node_id in node_rows:
                raise BackupFormatError(
                    f"Duplicate document/folder node id in backup: {node_id!r}"
                )
            parent_id = row.get("parent_id", row.get("folder_id"))
            if node_id != "/" and parent_id is None:
                parent_id = "/"
            node_rows[node_id] = {
                "id": node_id,
                "type": node_type,
                "inherit": row.get("inherit", True),
                "status": row.get("status", 0),
                "status_operation_id": row.get("status_operation_id"),
                "access_rule_set_id": None,
                "name": row.get("name", row.get("title")),
                "parent_id": parent_id,
            }
    return node_rows


def _load_legacy_node_namespace(
    extract_dir: Path,
    manifest: dict[str, Any],
) -> dict[str, dict[str, Any]]:
    namespace: dict[str, dict[str, Any]] = {}
    layouts = {
        "folders": ("name", "parent_id"),
        "documents": ("title", "folder_id"),
    }
    for table_name, (name_column, parent_column) in layouts.items():
        table_manifest = manifest.get("tables", {}).get(table_name)
        if table_manifest is None:
            continue
        columns = table_manifest.get("columns")
        if columns is not None and name_column not in columns:
            continue
        path = _safe_payload_path(extract_dir, f"tables/{table_name}.jsonl")
        row_count = 0
        with path.open("rb") as f:
            for line_number, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                try:
                    row = orjson.loads(line)
                except orjson.JSONDecodeError as exc:
                    raise BackupFormatError(
                        f"Invalid JSON row in {path} at line {line_number}"
                    ) from exc
                row_count += 1
                namespace[str(row["id"])] = {
                    "name": row.get(name_column),
                    "parent_id": (
                        row.get(parent_column)
                        if row["id"] == "/" or row.get(parent_column) is not None
                        else "/"
                    ),
                }
        if row_count != table_manifest["rows"]:
            raise BackupFormatError(
                f"Row count mismatch for table {table_name!r}: "
                f"manifest says {table_manifest['rows']}, payload has {row_count}"
            )
    return namespace


def _build_missing_compiled_rule_set_mapping(
    extract_dir: Path,
    manifest: dict[str, Any],
) -> dict[str, str]:
    if "compiled_access_rules" not in manifest.get("tables", {}):
        return {}
    if "compiled_access_rule_sets" in manifest.get("tables", {}):
        return {}

    table_manifest = manifest["tables"]["compiled_access_rules"]
    path = _safe_payload_path(extract_dir, "tables/compiled_access_rules.jsonl")
    node_ids: set[str] = set()
    with path.open("rb") as f:
        row_count = 0
        for line_number, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                row = orjson.loads(line)
            except orjson.JSONDecodeError as exc:
                raise BackupFormatError(
                    f"Invalid JSON row in {path} at line {line_number}"
                ) from exc
            row_count += 1
            node_id = row.get("node_id", row.get("target_id"))
            if node_id:
                node_ids.add(str(node_id))
    if row_count != table_manifest["rows"]:
        raise BackupFormatError(
            "Row count mismatch for table 'compiled_access_rules': "
            f"manifest says {table_manifest['rows']}, payload has {row_count}"
        )
    return {node_id: secrets.token_hex(16) for node_id in sorted(node_ids)}


def _load_compiled_rule_node_ids(
    extract_dir: Path,
    manifest: dict[str, Any],
) -> list[str | None]:
    table_manifest = manifest["tables"]["compiled_access_rules"]
    path = _safe_payload_path(extract_dir, "tables/compiled_access_rules.jsonl")
    node_ids: list[str | None] = []
    with path.open("rb") as f:
        for line_number, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                row = orjson.loads(line)
            except orjson.JSONDecodeError as exc:
                raise BackupFormatError(
                    f"Invalid JSON row in {path} at line {line_number}"
                ) from exc
            node_id = row.get("node_id", row.get("target_id"))
            node_ids.append(str(node_id) if node_id else None)
    if len(node_ids) != table_manifest["rows"]:
        raise BackupFormatError(
            "Row count mismatch for table 'compiled_access_rules': "
            f"manifest says {table_manifest['rows']}, payload has {len(node_ids)}"
        )
    return node_ids


def _restore_missing_compiled_rule_sets(
    connection,
    tables: Mapping[str, Table],
    rule_set_id_by_node: Mapping[str, str],
) -> None:
    if not rule_set_id_by_node:
        return

    created_at = dt.datetime.now(dt.UTC).timestamp()
    connection.execute(
        insert(tables["compiled_access_rule_sets"]),
        [
            {
                "id": rule_set_id,
                "node_id": node_id,
                "created_at": created_at,
            }
            for node_id, rule_set_id in rule_set_id_by_node.items()
        ],
    )
    nodes = tables["nodes"]
    for node_id, rule_set_id in rule_set_id_by_node.items():
        connection.execute(
            update(nodes)
            .where(nodes.c.id == node_id)
            .values(access_rule_set_id=rule_set_id)
        )


def _load_legacy_banned_subnet_reasons(
    extract_dir: Path,
    manifest: dict[str, Any],
) -> dict[str, str | None]:
    table_manifest = manifest.get("tables", {}).get("banned_subnets")
    if table_manifest is None:
        return {}

    path = _safe_payload_path(extract_dir, "tables/banned_subnets.jsonl")
    reasons: dict[str, str | None] = {}
    row_count = 0
    with path.open("rb") as f:
        for line_number, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                row = orjson.loads(line)
            except orjson.JSONDecodeError as exc:
                raise BackupFormatError(
                    f"Invalid JSON row in {path} at line {line_number}"
                ) from exc
            row_count += 1
            if "reason" in row and "reason_comment_id" not in row:
                reasons[str(row["subnet"])] = row["reason"]
    if row_count != table_manifest["rows"]:
        raise BackupFormatError(
            "Row count mismatch for table 'banned_subnets': "
            f"manifest says {table_manifest['rows']}, payload has {row_count}"
        )
    return reasons


def _load_legacy_access_rule_rows(
    extract_dir: Path,
    manifest: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    rows_by_table: dict[str, list[dict[str, Any]]] = {}
    for table_name in LEGACY_ACCESS_RULE_TABLE_NAMES:
        if table_name not in manifest.get("tables", {}):
            continue
        table_manifest = manifest["tables"][table_name]
        path = _safe_payload_path(extract_dir, f"tables/{table_name}.jsonl")
        rows = []
        with path.open("rb") as f:
            for line_number, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                try:
                    rows.append(orjson.loads(line))
                except orjson.JSONDecodeError as exc:
                    raise BackupFormatError(
                        f"Invalid JSON row in {path} at line {line_number}"
                    ) from exc
        if len(rows) != table_manifest["rows"]:
            raise BackupFormatError(
                f"Row count mismatch for table {table_name!r}: "
                f"manifest says {table_manifest['rows']}, payload has {len(rows)}"
            )
        rows_by_table[table_name] = rows
    return rows_by_table


def _restore_legacy_access_rules(
    session,
    rows_by_table: dict[str, list[dict[str, Any]]],
) -> None:
    """Convert pre-compiled backup rows into current compiled access rows."""
    rules_by_node: dict[str, list[CompiledAccessRule]] = {}

    for row in rows_by_table.get("document_access_rules", []):
        compiled_rule = compile_access_rule(
            access_type=str(row["access_type"]),
            rule_data=_coerce_legacy_rule_data(row.get("rule_data")),
        )
        if compiled_rule is not None:
            rules_by_node.setdefault(str(row["document_id"]), []).append(compiled_rule)

    for row in rows_by_table.get("folder_access_rules", []):
        compiled_rule = compile_access_rule(
            access_type=str(row["access_type"]),
            rule_data=_coerce_legacy_rule_data(row.get("rule_data")),
        )
        if compiled_rule is not None:
            rules_by_node.setdefault(str(row["folder_id"]), []).append(compiled_rule)

    for node_id, rules in rules_by_node.items():
        node = session.get(Node, node_id)
        if node is None:
            continue
        rule_set = CompiledAccessRuleSet(node_id=node_id)
        rule_set.rules.extend(rules)
        session.add(rule_set)
        session.flush()
        node.active_access_rule_set = rule_set
        node.access_rule_set_id = rule_set.id


def _coerce_legacy_rule_data(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    return {}
