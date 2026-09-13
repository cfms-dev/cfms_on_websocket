import datetime as dt
import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from sqlalchemy import Table, insert, select, update

from include.database.models.access import (
    CompiledAccessRuleSet,
)
from include.database.models.documents import Node
from include.domains.access.authorization.compiled_rules import compile_access_rule
from maintenance.backup.rows import _iter_raw_table_row_batches
from maintenance.backup.selection import LEGACY_ACCESS_RULE_TABLE_NAMES


def _legacy_rule_set_id(node_id: str) -> str:
    return hashlib.sha256(f"cfms-legacy-rule-set:{node_id}".encode()).hexdigest()[:32]


def _restore_missing_compiled_rule_sets(
    connection,
    tables: Mapping[str, Table],
    node_ids: list[str],
) -> dict[str, str]:
    rule_set_id_by_node = {
        node_id: _legacy_rule_set_id(node_id) for node_id in dict.fromkeys(node_ids)
    }
    if not rule_set_id_by_node:
        return {}

    rule_sets = tables["compiled_access_rule_sets"]
    candidate_ids = tuple(rule_set_id_by_node.values())
    existing_ids = set(
        connection.scalars(
            select(rule_sets.c.id).where(rule_sets.c.id.in_(candidate_ids))
        )
    )
    created_at = dt.datetime.now(dt.UTC).timestamp()
    missing_rows = [
        {
            "id": rule_set_id,
            "node_id": node_id,
            "created_at": created_at,
        }
        for node_id, rule_set_id in rule_set_id_by_node.items()
        if rule_set_id not in existing_ids
    ]
    if missing_rows:
        connection.execute(insert(rule_sets), missing_rows)

    nodes = tables["nodes"]
    for node_id, rule_set_id in rule_set_id_by_node.items():
        connection.execute(
            update(nodes)
            .where(nodes.c.id == node_id)
            .values(access_rule_set_id=rule_set_id)
        )
    return rule_set_id_by_node


def _restore_legacy_access_rules(
    session,
    extract_dir: Path,
    manifest: dict[str, Any],
) -> None:
    for table_name in sorted(LEGACY_ACCESS_RULE_TABLE_NAMES):
        if table_name not in manifest.get("tables", {}):
            continue
        for batch in _iter_raw_table_row_batches(
            extract_dir,
            manifest,
            table_name,
        ):
            for row in batch:
                compiled_rule = compile_access_rule(
                    access_type=str(row["access_type"]),
                    rule_data=_coerce_legacy_rule_data(row.get("rule_data")),
                )
                if compiled_rule is None:
                    continue
                node_id = str(
                    row[
                        "document_id"
                        if table_name == "document_access_rules"
                        else "folder_id"
                    ]
                )
                node = session.get(Node, node_id)
                if node is None:
                    continue
                rule_set_id = _legacy_rule_set_id(node_id)
                rule_set = session.get(CompiledAccessRuleSet, rule_set_id)
                if rule_set is None:
                    rule_set = CompiledAccessRuleSet(id=rule_set_id, node_id=node_id)
                    session.add(rule_set)
                    session.flush()
                    node.access_rule_set_id = rule_set_id
                compiled_rule.rule_set_id = rule_set_id
                session.add(compiled_rule)
            session.flush()
            session.expunge_all()


def _coerce_legacy_rule_data(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    return {}
