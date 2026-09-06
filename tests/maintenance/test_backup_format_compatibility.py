import datetime as dt
import json
import sys
from io import StringIO
from pathlib import Path
from types import SimpleNamespace

import pytest
import tomlkit
from rich.console import Console
from rich.progress import Progress
from sqlalchemy import create_engine, event, insert, select, update
from sqlalchemy.orm import sessionmaker

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SRC_PATH = _PROJECT_ROOT / "src"


class _RootedStorage:
    def __init__(self, root: Path):
        self.root = root

    def _resolve(self, path: str) -> Path:
        return self.root.joinpath(*Path(path).parts)

    def fopen(self, path: str, mode: str = "rb"):
        resolved = self._resolve(path)
        if any(flag in mode for flag in ("w", "a", "+")):
            resolved.parent.mkdir(parents=True, exist_ok=True)
        return open(resolved, mode)

    def exists(self, path: str) -> bool:
        return self._resolve(path).exists()

    def remove(self, path: str) -> bool:
        resolved = self._resolve(path)
        if resolved.exists():
            resolved.unlink()
            return True
        return False

    def mkdir(self, path: str, mode: int = 0o777) -> None:
        self._resolve(path).mkdir(mode=mode)

    def makedirs(self, path: str, mode: int = 0o777, exist_ok: bool = False) -> None:
        self._resolve(path).mkdir(mode=mode, parents=True, exist_ok=exist_ok)

    def getsize(self, path: str) -> int:
        return self._resolve(path).stat().st_size


@pytest.fixture
def backup_context(monkeypatch, tmp_path):
    if str(_SRC_PATH) not in sys.path:
        sys.path.insert(0, str(_SRC_PATH))

    config_dir = tmp_path / "config"
    config_dir.mkdir()
    source_config = _write_config(
        config_dir / "config.toml",
        secret_key="source-secret-key",
        pepper="source-pepper",
    )
    (config_dir / "init").write_text("", encoding="utf-8")
    monkeypatch.chdir(config_dir)

    from include.database.session import Base
    from maintenance.backup import (
        BackupExportSelection,
        BackupFormatError,
        BackupIntegrityError,
        BackupRestoreError,
        BackupWarning,
        decode_backup_key,
        encode_backup_key,
        export_backup,
        import_backup,
        read_backup_header,
    )
    from maintenance.backup import core as backup_core

    return SimpleNamespace(
        Base=Base,
        BackupFormatError=BackupFormatError,
        BackupIntegrityError=BackupIntegrityError,
        BackupRestoreError=BackupRestoreError,
        BackupWarning=BackupWarning,
        BackupExportSelection=BackupExportSelection,
        decode_backup_key=decode_backup_key,
        encode_backup_key=encode_backup_key,
        export_backup=export_backup,
        import_backup=import_backup,
        read_backup_header=read_backup_header,
        backup_core=backup_core,
        source_config=source_config,
    )


def test_legacy_banned_subnet_times_are_upgraded(backup_context):
    table = backup_context.Base.metadata.tables["banned_subnets"]
    decoded = backup_context.backup_core._decode_row(
        {
            "subnet": "192.0.2.0/24",
            "reason": "legacy",
            "created_at": "2024-01-02T03:04:05",
        },
        table,
    )

    expected = dt.datetime(2024, 1, 2, 3, 4, 5, tzinfo=dt.UTC).timestamp()
    assert decoded["created_at"] == expected
    assert decoded["starts_at"] == expected
    assert decoded["expires_at"] is None
    assert decoded["reason_comment_id"] is None


def _write_config(path: Path, *, secret_key: str, pepper: str) -> dict:
    sample = tomlkit.parse((_SRC_PATH / "config.toml.sample").read_text("utf-8"))
    sample["server"]["secret_key"] = secret_key
    sample["security"]["pepper"] = pepper
    sample["database"]["type"] = "sqlite"
    sample["database"]["file"] = str(path.with_suffix(".db"))
    sample["provider"]["storage"] = "local"
    sample["provider"]["caching"] = "memory"
    sample["provider"]["event_bus"] = "local"
    path.write_text(tomlkit.dumps(sample), encoding="utf-8")
    return sample


def _new_database(base, path: Path):
    db_engine = create_engine(f"sqlite:///{path}")

    @event.listens_for(db_engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    base.metadata.create_all(db_engine)
    return db_engine, sessionmaker(bind=db_engine)


def _insert_compiled_rule(
    connection,
    tables,
    *,
    target_id: str,
    access_type: str,
    rule_data: dict,
) -> None:
    rule_set_id = connection.execute(
        select(tables["nodes"].c.access_rule_set_id).where(
            tables["nodes"].c.id == target_id
        )
    ).scalar_one()
    if rule_set_id is None:
        rule_set_id = f"rule-set-{target_id}"[:32]
        connection.execute(
            insert(tables["compiled_access_rule_sets"]),
            {
                "id": rule_set_id,
                "node_id": target_id,
                "created_at": 1_700_000_000.0,
            },
        )
        connection.execute(
            update(tables["nodes"])
            .where(tables["nodes"].c.id == target_id)
            .values(access_rule_set_id=rule_set_id)
        )

    result = connection.execute(
        insert(tables["compiled_access_rules"]),
        {
            "rule_set_id": rule_set_id,
            "access_type": access_type,
            "match_mode": rule_data.get("match", "all"),
        },
    )
    compiled_rule_id = result.inserted_primary_key[0]
    for index, group_data in enumerate(rule_data.get("match_groups", [])):
        rights = group_data.get("rights", {})
        groups = group_data.get("groups", {})
        required_rights = rights.get("require", [])
        required_groups = groups.get("require", [])
        rights_empty = "rights" not in group_data
        groups_empty = "groups" not in group_data
        group_result = connection.execute(
            insert(tables["compiled_access_rule_groups"]),
            {
                "rule_id": compiled_rule_id,
                "group_index": index,
                "match_mode": "all"
                if not required_rights or not required_groups
                else group_data.get("match", "all"),
                "rights_match_mode": rights.get("match", "all"),
                "rights_empty": rights_empty,
                "groups_match_mode": groups.get("match", "all"),
                "groups_empty": groups_empty,
            },
        )
        compiled_group_id = group_result.inserted_primary_key[0]
        for permission in required_rights:
            connection.execute(
                insert(tables["compiled_access_rule_rights"]),
                {"group_id": compiled_group_id, "permission": permission},
            )
        for group_name in required_groups:
            connection.execute(
                insert(tables["compiled_access_rule_memberships"]),
                {"group_id": compiled_group_id, "group_name": group_name},
            )


def test_comment_digest_backup_representation(backup_context) -> None:
    from maintenance.backup.core import _decode_row, _serialize_table_value

    digest = bytes.fromhex("e2" * 32)
    comments = backup_context.Base.metadata.tables["comments"]

    encoded = _serialize_table_value("comments", "content_digest", digest)
    decoded = _decode_row({"content_digest": encoded}, comments)

    assert encoded == digest.hex()
    assert decoded["content_digest"] == digest


def test_comment_digest_backup_rejects_invalid_hex(backup_context) -> None:
    from maintenance.backup.core import _decode_row

    comments = backup_context.Base.metadata.tables["comments"]

    with pytest.raises(backup_context.BackupFormatError):
        _decode_row({"content_digest": "not-a-digest"}, comments)


def _seed_source(base, db_engine, storage_root: Path) -> None:
    storage = _RootedStorage(storage_root)
    with storage.fopen("content/files/doc.bin", "wb") as f:
        f.write(b"document payload")
    with storage.fopen("content/files/avatar.bin", "wb") as f:
        f.write(b"avatar payload")

    tables = base.metadata.tables
    now = 1_700_000_000.0
    created_at = now

    with db_engine.begin() as connection:
        connection.execute(
            insert(tables["comments"]),
            [
                {
                    "comment_id": 1,
                    "digest_version": 1,
                    "content_digest": bytes.fromhex(
                        "e28bca6fb18bcde822a03cfa87a802b94136c6367f1952229382517c9f6d64cc"
                    ),
                    "comment_text": "Repeated policy violations",
                    "comment_data": None,
                },
                {
                    "comment_id": 2,
                    "digest_version": 1,
                    "content_digest": bytes.fromhex(
                        "f2a01247ea2f1c75120f51d5514e9d562002bc363d3b93a15a11ca63912018bd"
                    ),
                    "comment_text": "manual incident",
                    "comment_data": None,
                },
                {
                    "comment_id": 3,
                    "digest_version": 1,
                    "content_digest": bytes.fromhex(
                        "52e5e2272062cc620938aabd097dc450e046b5e1ea7fb9b1da75f0bc51c4e710"
                    ),
                    "comment_text": "Original block reason",
                    "comment_data": None,
                },
            ],
        )
        connection.execute(
            insert(tables["files"]),
            [
                {
                    "id": "file-doc",
                    "sha256": None,
                    "path": "content/files/doc.bin",
                    "size": len(b"document payload"),
                    "created_time": now,
                    "active": True,
                },
                {
                    "id": "file-avatar",
                    "sha256": None,
                    "path": "content/files/avatar.bin",
                    "size": len(b"avatar payload"),
                    "created_time": now,
                    "active": True,
                },
            ],
        )
        connection.execute(
            insert(tables["users"]),
            {
                "username": "alice",
                "pass_hash": "hash",
                "passwd_last_modified": now,
                "nickname": "Alice",
                "avatar_id": "file-avatar",
                "last_login": None,
                "created_time": now,
                "status": 1,
                "status_comment_id": 1,
                "secret_key": "alice-secret",
                "totp_secret": None,
                "totp_enabled": False,
                "totp_backup_codes": None,
                "preference_dek_id": None,
            },
        )
        connection.execute(
            insert(tables["schedules"]),
            {
                "id": "schedule-1",
                "task_name": "test.record",
                "task_contract_version": 1,
                "payload": {"value": 7},
                "trigger_type": "interval",
                "trigger_data": {
                    "seconds": 3600,
                    "start_at": "2023-11-14T22:13:20+00:00",
                },
                "timezone": "UTC",
                "system_managed": False,
                "enabled": True,
                "status": "active",
                "revision": 1,
                "next_run_at": now + 3600,
                "active_execution_id": None,
                "pending_scheduled_for": None,
                "created_by": "alice",
                "created_at": now,
                "updated_by": "alice",
                "updated_at": now,
                "deleted_at": None,
            },
        )
        connection.execute(
            insert(tables["user_groups"]),
            {
                "group_name": "sysop",
                "group_display_name": "Sysop",
            },
        )
        connection.execute(
            insert(tables["group_permissions"]),
            {
                "group_name": "sysop",
                "permission": "manage_system",
                "granted": True,
                "start_time": 0.0,
                "end_time": None,
            },
        )
        connection.execute(
            insert(tables["user_memberships"]),
            {
                "username": "alice",
                "group_name": "sysop",
                "start_time": 0.0,
                "end_time": None,
            },
        )
        connection.execute(
            insert(tables["user_permissions"]),
            {
                "username": "alice",
                "permission": "list_users",
                "granted": True,
                "start_time": 0.0,
                "end_time": None,
            },
        )
        connection.execute(
            insert(tables["keyrings"]),
            {
                "id": "key-1",
                "username": "alice",
                "content": "encrypted-dek",
                "label": "main",
                "created_time": now,
            },
        )
        connection.execute(
            update(tables["users"])
            .where(tables["users"].c.username == "alice")
            .values(preference_dek_id="key-1")
        )
        connection.execute(
            insert(tables["nodes"]),
            {
                "id": "/",
                "type": "directory",
                "name": "/",
                "parent_id": None,
                "inherit": True,
                "status": 0,
                "status_operation_id": None,
            },
        )
        connection.execute(
            insert(tables["folders"]),
            {"id": "/", "created_time": now},
        )
        connection.execute(
            insert(tables["nodes"]),
            {
                "id": "folder-1",
                "type": "directory",
                "name": "Folder",
                "parent_id": "/",
                "inherit": True,
                "status": 0,
                "status_operation_id": None,
            },
        )
        connection.execute(
            insert(tables["folders"]),
            {"id": "folder-1", "created_time": now},
        )
        connection.execute(
            insert(tables["nodes"]),
            {
                "id": "doc-1",
                "type": "document",
                "name": "Document",
                "parent_id": "folder-1",
                "inherit": True,
                "status": 1,
                "status_operation_id": "soft-delete-op",
            },
        )
        _insert_compiled_rule(
            connection,
            tables,
            target_id="folder-1",
            access_type="read",
            rule_data={
                "match": "all",
                "match_groups": [{"groups": {"match": "all", "require": ["sysop"]}}],
            },
        )
        connection.execute(
            insert(tables["documents"]),
            {
                "id": "doc-1",
                "created_time": now,
                "current_revision_id": None,
            },
        )
        connection.execute(
            insert(tables["document_revisions"]),
            {
                "id": "rev-1",
                "document_id": "doc-1",
                "file_id": "file-doc",
                "created_time": now,
                "parent_revision_id": None,
                "status": 0,
            },
        )
        connection.execute(
            update(tables["documents"])
            .where(tables["documents"].c.id == "doc-1")
            .values(current_revision_id="rev-1")
        )
        _insert_compiled_rule(
            connection,
            tables,
            target_id="doc-1",
            access_type="read",
            rule_data={
                "match": "all",
                "match_groups": [{"groups": {"match": "all", "require": ["sysop"]}}],
            },
        )
        connection.execute(
            insert(tables["document_metadata"]),
            {
                "document_id": "doc-1",
                "creator_username": "alice",
                "last_modified_by_username": "alice",
            },
        )
        connection.execute(
            insert(tables["document_metadata_tags"]),
            {
                "document_id": "doc-1",
                "tag": "important",
                "position": 1,
            },
        )
        connection.execute(
            insert(tables["object_access_entries"]),
            {
                "entity_type": "user",
                "entity_identifier": "alice",
                "target_type": "document",
                "target_identifier": "doc-1",
                "access_type": "read",
                "start_time": 0.0,
                "end_time": None,
            },
        )
        connection.execute(
            insert(tables["audit_entries"]),
            {
                "id": "audit-1",
                "action": "create_document",
                "username": "alice",
                "target": "doc-1",
                "data": {"ok": True},
                "result": 200,
                "remote_address": "127.0.0.1",
                "logged_time": now,
            },
        )
        connection.execute(
            insert(tables["userblock_entries"]),
            {
                "block_id": "block-1",
                "username": "alice",
                "timestamp": now,
                "not_before": 0.0,
                "not_after": -1.0,
                "target_type": "document",
                "target_id": "doc-1",
                "reason_comment_id": 3,
            },
        )
        connection.execute(
            insert(tables["userblock_sub_entries"]),
            {
                "parent_id": "block-1",
                "block_type": "read",
            },
        )
        connection.execute(
            insert(tables["banned_subnets"]),
            {
                "subnet": "192.0.2.0/24",
                "reason_comment_id": 2,
                "created_at": created_at,
                "starts_at": created_at,
                "expires_at": None,
            },
        )
        connection.execute(
            insert(tables["file_tasks"]),
            {
                "id": "task-1",
                "file_id": "file-doc",
                "status": 0,
                "mode": 0,
                "start_time": now,
                "end_time": now + 60,
                "encryption_key": "transient",
            },
        )
        connection.execute(
            insert(tables["login_throttles"]),
            {
                "username": "alice",
                "ip_address": "198.51.100.10",
                "failed_attempts": 3,
                "window_started_at": created_at,
                "last_attempt": created_at,
                "locked_until": created_at,
            },
        )
        connection.execute(
            insert(tables["traffic_throttles"]),
            {
                "ip_address": "198.51.100.11",
                "failed_attempts": 4,
                "window_started_at": created_at,
                "last_attempt": created_at,
                "locked_until": created_at,
            },
        )
        connection.execute(
            insert(tables["system_states"]),
            {
                "owner": "core",
                "state_key": "lockdown",
                "schema_version": 1,
                "revision": 1,
                "payload": {
                    "enabled": True,
                    "reason": "Maintenance",
                    "last_disabled_at": 0.0,
                },
                "updated_at": created_at,
            },
        )


def _dump_backup_tables(base, db_engine) -> dict[str, list[dict]]:
    dumped = {}
    with db_engine.connect() as connection:
        for table_name in base.metadata.tables:
            if table_name not in _backup_table_names(base):
                continue
            table = base.metadata.tables[table_name]
            order_by = [column for column in table.primary_key.columns]
            statement = select(table)
            if order_by:
                statement = statement.order_by(*order_by)
            rows = []
            for row in connection.execute(statement).mappings():
                rows.append({key: _normalize(value) for key, value in row.items()})
            dumped[table_name] = rows
    return dumped


def _backup_table_names(base) -> set[str]:
    excluded = {
        "account_throttles",
        "file_tasks",
        "login_throttles",
        "rate_limit_buckets",
        "risk_ip_accounts",
        "schedule_executions",
        "scheduling_runtime_state",
        "system_states",
        "traffic_throttles",
    }
    return set(base.metadata.tables) - excluded


def _normalize(value):
    if isinstance(value, dt.datetime):
        return value.isoformat()
    return value


def _write_jsonl(path: Path, rows: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        "".join(f"{json.dumps(row, separators=(',', ':'))}\n" for row in rows),
        encoding="utf-8",
    )


def _read_jsonl(path: Path) -> list[dict]:
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _test_progress() -> Progress:
    return Progress(
        console=Console(file=StringIO(), force_terminal=False, width=120),
    )


def test_backup_key_uses_human_readable_format(backup_context):
    key = bytes(range(32))
    encoded = backup_context.encode_backup_key(key)
    data = encoded.replace("-", "")

    assert len(data) == 52
    assert not set(data) & set("01OILl")
    assert backup_context.decode_backup_key(encoded) == key


def test_backup_key_decoder_rejects_invalid_human_keys(backup_context):
    key = bytes(range(32))
    encoded = backup_context.encode_backup_key(key)

    with pytest.raises(ValueError, match="invalid character"):
        backup_context.decode_backup_key(f"{encoded[:-1]}0")

    with pytest.raises(ValueError, match="data characters"):
        backup_context.decode_backup_key(encoded[:-1])

    with pytest.raises(ValueError, match="out of range"):
        backup_context.decode_backup_key("Z" * 52)


def test_backup_key_decoder_keeps_legacy_base64url_compatibility(backup_context):
    legacy_key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

    assert backup_context.decode_backup_key(legacy_key) == bytes(range(32))


def test_runtime_state_tables_are_excluded(backup_context):
    excluded = backup_context.backup_core.EXCLUDED_TABLE_NAMES

    assert "rate_limit_buckets" in excluded
    assert "risk_ip_accounts" in excluded
    assert "schedule_executions" in excluded
    assert "scheduling_runtime_state" in excluded
    assert "system_states" in excluded
