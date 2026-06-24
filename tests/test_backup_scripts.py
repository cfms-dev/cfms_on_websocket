import datetime as dt
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import tomlkit
from sqlalchemy import create_engine, event, insert, select, update
from sqlalchemy.orm import sessionmaker

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
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

    from include.database.handler import Base
    from maintenance.backup import (
        BackupFormatError,
        BackupIntegrityError,
        BackupRestoreError,
        BackupWarning,
        decode_backup_key,
        export_backup,
        import_backup,
        read_backup_header,
    )

    return SimpleNamespace(
        Base=Base,
        BackupFormatError=BackupFormatError,
        BackupIntegrityError=BackupIntegrityError,
        BackupRestoreError=BackupRestoreError,
        BackupWarning=BackupWarning,
        decode_backup_key=decode_backup_key,
        export_backup=export_backup,
        import_backup=import_backup,
        read_backup_header=read_backup_header,
        source_config=source_config,
    )


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


def _seed_source(base, db_engine, storage_root: Path) -> None:
    storage = _RootedStorage(storage_root)
    with storage.fopen("content/files/doc.bin", "wb") as f:
        f.write(b"document payload")
    with storage.fopen("content/files/avatar.bin", "wb") as f:
        f.write(b"avatar payload")

    tables = base.metadata.tables
    now = 1_700_000_000.0
    created_at = dt.datetime(2024, 1, 2, 3, 4, 5)

    with db_engine.begin() as connection:
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
                "status": 0,
                "secret_key": "alice-secret",
                "totp_secret": None,
                "totp_enabled": False,
                "totp_backup_codes": None,
                "preference_dek_id": None,
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
            insert(tables["folders"]),
            [
                {
                    "id": "/",
                    "name": "/",
                    "created_time": now,
                    "parent_id": None,
                    "status": 0,
                    "status_operation_id": None,
                    "inherit": True,
                },
                {
                    "id": "folder-1",
                    "name": "Folder",
                    "created_time": now,
                    "parent_id": "/",
                    "status": 0,
                    "status_operation_id": None,
                    "inherit": True,
                },
            ],
        )
        connection.execute(
            insert(tables["folder_access_rules"]),
            {
                "access_type": "read",
                "folder_id": "folder-1",
                "rule_data": {"match": "all", "match_groups": []},
            },
        )
        connection.execute(
            insert(tables["documents"]),
            {
                "id": "doc-1",
                "title": "Document",
                "created_time": now,
                "folder_id": "folder-1",
                "current_revision_id": None,
                "status": 1,
                "status_operation_id": "soft-delete-op",
                "inherit": True,
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
        connection.execute(
            insert(tables["document_access_rules"]),
            {
                "access_type": "read",
                "document_id": "doc-1",
                "rule_data": {"match": "all", "match_groups": []},
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
                "reason": "manual",
                "created_at": created_at,
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
                "last_attempt": created_at,
                "locked_until": created_at,
            },
        )
        connection.execute(
            insert(tables["traffic_throttles"]),
            {
                "ip_address": "198.51.100.11",
                "failed_attempts": 4,
                "last_attempt": created_at,
                "locked_until": created_at,
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
    excluded = {"file_tasks", "login_throttles", "traffic_throttles"}
    return set(base.metadata.tables) - excluded


def _normalize(value):
    if isinstance(value, dt.datetime):
        return value.isoformat()
    return value


def test_backup_header_and_roundtrip_restore(backup_context, tmp_path):
    base = backup_context.Base
    source_engine, source_session = _new_database(base, tmp_path / "source.db")
    target_engine, target_session = _new_database(base, tmp_path / "target.db")
    source_storage = tmp_path / "source-storage"
    target_storage = tmp_path / "target-storage"
    source_storage.mkdir()
    target_storage.mkdir()
    _seed_source(base, source_engine, source_storage)

    backup_path = tmp_path / "backup.conf"
    key_text = backup_context.export_backup(
        backup_path,
        session_factory=source_session,
        storage_provider=_RootedStorage(source_storage),
        config=backup_context.source_config,
    )

    assert backup_path.read_bytes().startswith(b"CONF")
    header = backup_context.read_backup_header(backup_path)
    assert header.created_at
    assert header.encryption == "AES-256-GCM"

    target_config = tmp_path / "target-config.toml"
    _write_config(target_config, secret_key="target-secret", pepper="target-pepper")
    init_path = tmp_path / "target-init"
    result = backup_context.import_backup(
        backup_path,
        key_text,
        session_factory=target_session,
        db_engine=target_engine,
        storage_provider=_RootedStorage(target_storage),
        config_path=target_config,
        init_path=init_path,
    )

    assert result["created_at"] == header.created_at
    assert init_path.exists()
    assert _dump_backup_tables(base, source_engine) == _dump_backup_tables(
        base, target_engine
    )
    assert (target_storage / "content" / "files" / "doc.bin").read_bytes() == (
        source_storage / "content" / "files" / "doc.bin"
    ).read_bytes()
    assert (target_storage / "content" / "files" / "avatar.bin").read_bytes() == (
        source_storage / "content" / "files" / "avatar.bin"
    ).read_bytes()

    restored_config = tomlkit.parse(target_config.read_text(encoding="utf-8"))
    assert restored_config["security"]["pepper"] == "source-pepper"
    assert restored_config["server"]["secret_key"] == "source-secret-key"

    with target_engine.connect() as connection:
        file_tasks = connection.execute(
            select(base.metadata.tables["file_tasks"])
        ).all()
        login_throttles = connection.execute(
            select(base.metadata.tables["login_throttles"])
        ).all()
        traffic_throttles = connection.execute(
            select(base.metadata.tables["traffic_throttles"])
        ).all()
        assert file_tasks == []
        assert login_throttles == []
        assert traffic_throttles == []


def test_wrong_magic_and_wrong_key_fail(backup_context, tmp_path):
    bad_backup = tmp_path / "bad.conf"
    bad_backup.write_bytes(b"NOPE")
    with pytest.raises(backup_context.BackupFormatError):
        backup_context.read_backup_header(bad_backup)

    base = backup_context.Base
    source_engine, source_session = _new_database(base, tmp_path / "source.db")
    target_engine, target_session = _new_database(base, tmp_path / "target.db")
    source_storage = tmp_path / "source-storage"
    target_storage = tmp_path / "target-storage"
    source_storage.mkdir()
    target_storage.mkdir()
    _seed_source(base, source_engine, source_storage)

    backup_path = tmp_path / "backup.conf"
    backup_context.export_backup(
        backup_path,
        session_factory=source_session,
        storage_provider=_RootedStorage(source_storage),
        config=backup_context.source_config,
    )
    wrong_key = backup_context.decode_backup_key(
        backup_context.export_backup(
            tmp_path / "other.conf",
            session_factory=source_session,
            storage_provider=_RootedStorage(source_storage),
            config=backup_context.source_config,
        )
    )

    target_config = tmp_path / "target-config.toml"
    _write_config(target_config, secret_key="target-secret", pepper="target-pepper")
    with pytest.raises(backup_context.BackupIntegrityError):
        backup_context.import_backup(
            backup_path,
            wrong_key,
            session_factory=target_session,
            db_engine=target_engine,
            storage_provider=_RootedStorage(target_storage),
            config_path=target_config,
            init_path=tmp_path / "init",
        )


def test_export_fails_when_physical_file_is_missing(backup_context, tmp_path):
    base = backup_context.Base
    source_engine, source_session = _new_database(base, tmp_path / "source.db")
    source_storage = tmp_path / "source-storage"
    source_storage.mkdir()
    _seed_source(base, source_engine, source_storage)
    (source_storage / "content" / "files" / "doc.bin").unlink()

    with pytest.raises(backup_context.BackupIntegrityError):
        backup_context.export_backup(
            tmp_path / "backup.conf",
            session_factory=source_session,
            storage_provider=_RootedStorage(source_storage),
            config=backup_context.source_config,
        )


def test_export_skips_missing_inactive_physical_file(backup_context, tmp_path):
    base = backup_context.Base
    source_engine, source_session = _new_database(base, tmp_path / "source.db")
    target_engine, target_session = _new_database(base, tmp_path / "target.db")
    source_storage = tmp_path / "source-storage"
    target_storage = tmp_path / "target-storage"
    source_storage.mkdir()
    target_storage.mkdir()
    _seed_source(base, source_engine, source_storage)

    missing_storage_path = "content/files/inactive-missing.bin"
    with source_engine.begin() as connection:
        connection.execute(
            insert(base.metadata.tables["files"]),
            {
                "id": "file-inactive-missing",
                "sha256": None,
                "path": missing_storage_path,
                "size": 123,
                "created_time": 1_700_000_001.0,
                "active": False,
            },
        )

    backup_path = tmp_path / "backup.conf"
    with pytest.warns(backup_context.BackupWarning, match="Skipping inactive"):
        key_text = backup_context.export_backup(
            backup_path,
            session_factory=source_session,
            storage_provider=_RootedStorage(source_storage),
            config=backup_context.source_config,
        )

    target_config = tmp_path / "target-config.toml"
    _write_config(target_config, secret_key="target-secret", pepper="target-pepper")
    result = backup_context.import_backup(
        backup_path,
        key_text,
        session_factory=target_session,
        db_engine=target_engine,
        storage_provider=_RootedStorage(target_storage),
        config_path=target_config,
        init_path=tmp_path / "target-init",
    )

    assert "file-inactive-missing" not in {
        entry["file_id"] for entry in result["files"]
    }
    assert not (target_storage / Path(missing_storage_path)).exists()


def test_import_rejects_non_empty_target(backup_context, tmp_path):
    base = backup_context.Base
    source_engine, source_session = _new_database(base, tmp_path / "source.db")
    target_engine, target_session = _new_database(base, tmp_path / "target.db")
    source_storage = tmp_path / "source-storage"
    target_storage = tmp_path / "target-storage"
    source_storage.mkdir()
    target_storage.mkdir()
    _seed_source(base, source_engine, source_storage)

    backup_path = tmp_path / "backup.conf"
    key_text = backup_context.export_backup(
        backup_path,
        session_factory=source_session,
        storage_provider=_RootedStorage(source_storage),
        config=backup_context.source_config,
    )

    with target_engine.begin() as connection:
        connection.execute(
            insert(base.metadata.tables["files"]),
            {
                "id": "existing",
                "sha256": None,
                "path": "content/files/existing.bin",
                "size": 1,
                "created_time": 0.0,
                "active": True,
            },
        )

    target_config = tmp_path / "target-config.toml"
    _write_config(target_config, secret_key="target-secret", pepper="target-pepper")
    with pytest.raises(backup_context.BackupRestoreError):
        backup_context.import_backup(
            backup_path,
            key_text,
            session_factory=target_session,
            db_engine=target_engine,
            storage_provider=_RootedStorage(target_storage),
            config_path=target_config,
            init_path=tmp_path / "init",
        )
