import datetime as dt
import hashlib
import json
import uuid
from contextlib import ExitStack, closing
from itertools import chain
from typing import Any
lazy from collections.abc import Mapping
lazy from pathlib import Path

import orjson
from sqlalchemy import Table, insert, select, update

from include.database.models.access import (
    CompiledAccessRuleSet,
)
from include.database.models.auth import (
    UserAuthPolicy,
    UserPasswordCredential,
    UserTotpCredential,
)
from include.database.models.documents import Node
from include.database.models.identity import User
from include.domains.access.authorization.compiled_rules import compile_access_rule
from maintenance.backup.models import BackupFormatError
from maintenance.backup.rows import _iter_raw_table_row_batches, _iter_raw_table_rows
from maintenance.backup.selection import LEGACY_ACCESS_RULE_TABLE_NAMES, _backup_tables

_USERNAME_REFERENCES = {
    "user_passwords": (("username", "user_id"),),
    "user_totp_credentials": (("username", "user_id"),),
    "user_auth_public_keys": (("username", "user_id"),),
    "user_permissions": (("username", "user_id"),),
    "user_memberships": (("username", "user_id"),),
    "keyrings": (("username", "user_id"),),
    "userblock_entries": (("username", "user_id"),),
    "audit_entries": (("username", "user_id"),),
    "document_metadata": (
        ("creator_username", "creator_id"),
        ("last_modified_by_username", "last_modified_by_id"),
    ),
    "schedules": (("created_by", "created_by"), ("updated_by", "updated_by")),
}


def _upgrade_legacy_identity_payload(
    extract_dir: Path, manifest: dict[str, Any]
) -> dict[str, Any]:
    """Translate historical usernames and inline credentials in the extracted copy."""
    if "users" not in manifest["tables"]:
        return manifest
    with closing(_iter_raw_table_rows(extract_dir, manifest, "users")) as users:
        first = next(users, None)
        if (first is not None and "id" in first) or (
            first is None and "id" in manifest["tables"]["users"].get("columns", [])
        ):
            return manifest
        manifest = {**manifest, "tables": dict(manifest["tables"])}
        tables = _backup_tables()
        inline_credentials = (
            "pass_hash" in first
            if first is not None
            else "pass_hash" in manifest["tables"]["users"].get("columns", [])
        )
        if inline_credentials and {"user_passwords", "user_totp_credentials"} & set(
            manifest["tables"]
        ):
            raise BackupFormatError("Backup mixes inline and separate credentials")
        identities = {}
        counts = {"users": 0}
        if inline_credentials:
            counts.update(user_passwords=0, user_totp_credentials=0)
        with ExitStack() as resources:
            outputs = {
                name: resources.enter_context(
                    (extract_dir / "tables" / f"{name}.converted").open("wb")
                )
                for name in counts
            }
            for row in chain(() if first is None else (first,), users):
                username = row.get("username")
                if (
                    not isinstance(username, str)
                    or username in identities
                    or "id" in row
                ):
                    raise BackupFormatError("Invalid legacy account identity")
                user_id = identities[username] = str(uuid.uuid4())
                if inline_credentials:
                    password_hash = row.pop("pass_hash", None)
                    modified = row.pop("passwd_last_modified", None)
                    secret = row.pop("totp_secret", None)
                    enabled = row.pop("totp_enabled", False)
                    backup_codes = row.pop("totp_backup_codes", None)
                    if password_hash is not None:
                        outputs["user_passwords"].write(
                            orjson.dumps(
                                {
                                    "user_id": user_id,
                                    "pass_hash": password_hash,
                                    "passwd_last_modified": modified or 0,
                                }
                            )
                            + b"\n"
                        )
                        counts["user_passwords"] += 1
                    if secret is not None:
                        outputs["user_totp_credentials"].write(
                            orjson.dumps(
                                {
                                    "user_id": user_id,
                                    "secret": secret,
                                    "enabled": enabled,
                                    "backup_codes": backup_codes,
                                    "created_time": row.get("created_time") or 0,
                                }
                            )
                            + b"\n"
                        )
                        counts["user_totp_credentials"] += 1
                outputs["users"].write(orjson.dumps({**row, "id": user_id}) + b"\n")
                counts["users"] += 1
        for name, count in counts.items():
            path = extract_dir / "tables" / f"{name}.jsonl"
            path.with_suffix(".converted").replace(path)
            manifest["tables"][name] = {
                "columns": list(tables[name].c.keys()),
                "rows": count,
            }
    for name in manifest["tables"]:
        if name not in _USERNAME_REFERENCES and name != "object_access_entries":
            continue
        path = extract_dir / "tables" / f"{name}.jsonl"
        count = 0
        with path.with_suffix(".converted").open("wb") as output:
            for row in _iter_raw_table_rows(extract_dir, manifest, name):
                for old_name, new_name in _USERNAME_REFERENCES.get(name, ()):
                    if old_name not in row:
                        continue
                    username = row.pop(old_name)
                    user_id = identities.get(username)
                    if user_id is None and not tables[name].c[new_name].nullable:
                        raise BackupFormatError(
                            f"Orphaned account reference in {name}.{old_name}"
                        )
                    row[new_name] = user_id
                if name == "object_access_entries" and row.get("entity_type") == "user":
                    user_id = identities.get(row.get("entity_identifier"))
                    if user_id is None:
                        continue
                    row["entity_identifier"] = user_id
                output.write(orjson.dumps(row) + b"\n")
                count += 1
        path.with_suffix(".converted").replace(path)
        manifest["tables"][name] = {
            "columns": list(tables[name].c.keys()),
            "rows": count,
        }
    return manifest


def _legacy_rule_set_id(node_id: str) -> str:
    return hashlib.sha256(f"cfms-legacy-rule-set:{node_id}".encode()).hexdigest()[:32]


def _restore_legacy_auth_policies(session) -> None:
    """Preserve pre-policy local authentication only for archives without policies."""
    for user in session.scalars(select(User)):
        password = session.get(UserPasswordCredential, user.id)
        totp = session.get(UserTotpCredential, user.id)
        defaults = {
            "login": [
                [{"method": "password", "credential_ids": [password.credential_id]}]
            ]
            if password
            else [],
            "mfa": [[{"method": "totp", "credential_ids": [totp.credential_id]}]]
            if totp and totp.enabled
            else [],
            "escalation": [],
        }
        session.add_all(
            [
                UserAuthPolicy(
                    user_id=user.id, purpose=purpose, revision=1, chains=chains
                )
                for purpose, chains in defaults.items()
            ]
        )


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
        try:
            parsed = json.loads(value)
        except json.JSONDecodeError as exc:
            raise BackupFormatError(
                "Legacy access rule rule_data is not valid JSON"
            ) from exc
        if isinstance(parsed, dict):
            return parsed
    raise BackupFormatError("Legacy access rule rule_data must be a JSON object")
