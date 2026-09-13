import hashlib
import tarfile
from pathlib import Path

import orjson
import pytest
import tomlkit
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from sqlalchemy import event, func, insert, select, update

from .roundtrip_support import _seed_source
from .support import (
    _dump_backup_tables,
    _new_database,
    _read_jsonl,
    _RootedStorage,
    _test_progress,
    _write_config,
    _write_jsonl,
)


def _write_audit_rows(extract_dir: Path, row_count: int) -> None:
    rows = [
        {
            "id": f"audit-{index:04d}",
            "action": "batch-test",
            "username": None,
            "target": None,
            "data": {"sequence": index},
            "result": 200,
            "remote_address": "192.0.2.1",
            "logged_time": float(index),
        }
        for index in range(row_count)
    ]
    _write_jsonl(extract_dir / "tables" / "audit_entries.jsonl", rows)


def test_partial_document_export_restores_dependency_closure(backup_context, tmp_path):
    base = backup_context.Base
    source_engine, source_session = _new_database(base, tmp_path / "source.db")
    target_engine, target_session = _new_database(base, tmp_path / "target.db")
    source_storage = tmp_path / "source-storage"
    target_storage = tmp_path / "target-storage"
    source_storage.mkdir()
    target_storage.mkdir()
    _seed_source(base, source_engine, source_storage)

    backup_path = tmp_path / "documents.conf"
    selection = backup_context.BackupExportSelection.from_component_values(
        ["documents"]
    )
    key_text = backup_context.export_backup(
        backup_path,
        session_factory=source_session,
        storage_provider=_RootedStorage(source_storage),
        config=backup_context.source_config,
        selection=selection,
    )

    target_config = tmp_path / "target-config.toml"
    _write_config(target_config, secret_key="target-secret", pepper="target-pepper")
    backup_context.import_backup(
        backup_path,
        key_text,
        session_factory=target_session,
        db_engine=target_engine,
        storage_provider=_RootedStorage(target_storage),
        config_path=target_config,
        init_path=tmp_path / "target-init",
    )

    restored = _dump_backup_tables(base, target_engine)
    assert [row["id"] for row in restored["documents"]] == ["doc-1"]
    assert [row["id"] for row in restored["folders"]] == ["/", "folder-1"]
    assert {row["node_id"] for row in restored["compiled_access_rule_sets"]} == {
        "folder-1",
        "doc-1",
    }
    rule_set_node_by_id = {
        row["id"]: row["node_id"] for row in restored["compiled_access_rule_sets"]
    }
    assert {
        rule_set_node_by_id[row["rule_set_id"]]
        for row in restored["compiled_access_rules"]
    } == {"folder-1", "doc-1"}
    assert [row["target_identifier"] for row in restored["object_access_entries"]] == [
        "doc-1"
    ]
    assert [row["username"] for row in restored["users"]] == ["alice"]
    assert restored["users"][0]["status_comment_id"] == 1
    assert [row["comment_text"] for row in restored["comments"]] == [
        "Repeated policy violations",
        "Original block reason",
    ]
    assert restored["comments"][0]["content_digest"] == bytes.fromhex(
        "e28bca6fb18bcde822a03cfa87a802b94136c6367f1952229382517c9f6d64cc"
    )
    assert restored["userblock_entries"][0]["reason_comment_id"] == 3
    assert {row["id"] for row in restored["files"]} == {"file-avatar", "file-doc"}
    assert restored["audit_entries"] == []
    assert restored["banned_subnets"] == []
    assert (target_storage / "content" / "files" / "doc.bin").read_bytes() == (
        source_storage / "content" / "files" / "doc.bin"
    ).read_bytes()
    assert (target_storage / "content" / "files" / "avatar.bin").read_bytes() == (
        source_storage / "content" / "files" / "avatar.bin"
    ).read_bytes()

    restored_config = tomlkit.parse(target_config.read_text(encoding="utf-8"))
    assert restored_config["security"]["pepper"] == "target-pepper"
    assert restored_config["server"]["secret_key"] == "target-secret"


def test_file_export_uses_the_exported_database_snapshot(
    backup_context,
    tmp_path,
) -> None:
    from maintenance.backup.export import _stage_backup_payload

    base = backup_context.Base
    source_engine, source_session = _new_database(base, tmp_path / "source.db")
    source_storage = tmp_path / "source-storage"
    source_storage.mkdir()
    _seed_source(base, source_engine, source_storage)
    moved_path = source_storage / "content" / "files" / "moved.bin"
    moved_path.write_bytes(b"moved payload")
    session_count = 0

    def changing_session_factory():
        nonlocal session_count
        session_count += 1
        if session_count == 2:
            with source_engine.begin() as connection:
                connection.execute(
                    update(base.metadata.tables["files"])
                    .where(base.metadata.tables["files"].c.id == "file-doc")
                    .values(path="content/files/moved.bin")
                )
        return source_session()

    staging_dir = tmp_path / "staging"
    staging_dir.mkdir()
    manifest = _stage_backup_payload(
        staging_dir,
        session_factory=changing_session_factory,
        storage_provider=_RootedStorage(source_storage),
        config=backup_context.source_config,
    )

    exported_paths = {
        row["id"]: row["path"]
        for row in _read_jsonl(staging_dir / "tables" / "files.jsonl")
    }
    assert {
        entry["file_id"]: entry["storage_path"] for entry in manifest["files"]
    } == exported_paths


def test_banned_subnet_export_includes_only_referenced_comments(
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
    selection = backup_context.BackupExportSelection.from_component_values(
        ["banned_subnets"]
    )

    manifest = _stage_backup_payload(
        staging_dir,
        session_factory=source_session,
        storage_provider=_RootedStorage(source_storage),
        config=backup_context.source_config,
        selection=selection,
    )

    assert set(manifest["tables"]) == {"comments", "banned_subnets"}
    assert _read_jsonl(staging_dir / "tables" / "comments.jsonl") == [
        {
            "comment_data": None,
            "comment_id": 2,
            "comment_text": "manual incident",
            "content_digest": (
                "f2a01247ea2f1c75120f51d5514e9d562002bc363d3b93a15a11ca63912018bd"
            ),
            "digest_version": 1,
        }
    ]
    assert (
        _read_jsonl(staging_dir / "tables" / "banned_subnets.jsonl")[0][
            "reason_comment_id"
        ]
        == 2
    )


def test_legacy_banned_subnet_reason_restores_as_comment(backup_context, tmp_path):
    from maintenance.backup.format import BACKUP_FORMAT_VERSION
    from maintenance.backup.restore import _restore_database

    base = backup_context.Base
    target_engine, target_session = _new_database(base, tmp_path / "target.db")
    extract_dir = tmp_path / "legacy-payload"
    tables_dir = extract_dir / "tables"
    rows = [
        {
            "subnet": "192.0.2.0/24",
            "reason": "legacy incident",
            "created_at": "2024-01-02T03:04:05Z",
        }
    ]
    _write_jsonl(tables_dir / "banned_subnets.jsonl", rows)
    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["banned_subnets"],
        "tables": {"banned_subnets": {"rows": 1}},
        "files": [],
        "configuration": {},
    }

    _restore_database(extract_dir, manifest, target_session)

    restored = _dump_backup_tables(base, target_engine)
    assert restored["comments"][0]["comment_text"] == "legacy incident"
    assert (
        restored["banned_subnets"][0]["reason_comment_id"]
        == restored["comments"][0]["comment_id"]
    )


def test_database_restore_bounds_batches_and_reports_row_progress(
    backup_context,
    tmp_path,
):
    from maintenance.backup.format import BACKUP_FORMAT_VERSION
    from maintenance.backup.progress import _BackupProgressReporter
    from maintenance.backup.restore import _restore_database

    base = backup_context.Base
    target_engine, target_session = _new_database(base, tmp_path / "target.db")
    extract_dir = tmp_path / "payload"
    row_count = 1001
    _write_audit_rows(extract_dir, row_count)
    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["audit"],
        "tables": {"audit_entries": {"rows": row_count}},
        "files": [],
        "configuration": {},
    }
    insert_batch_sizes = []

    @event.listens_for(target_engine, "before_cursor_execute")
    def _record_audit_insert_batch(
        _connection,
        _cursor,
        statement,
        parameters,
        _context,
        executemany,
    ) -> None:
        if statement.startswith("INSERT INTO audit_entries"):
            insert_batch_sizes.append(len(parameters) if executemany else 1)

    with _test_progress() as progress:
        _restore_database(
            extract_dir,
            manifest,
            target_session,
            progress_reporter=_BackupProgressReporter(
                progress,
                show_details=False,
            ),
        )

    assert sum(insert_batch_sizes) == row_count
    assert len(insert_batch_sizes) > 1
    assert max(insert_batch_sizes) <= 1000
    row_progress = next(
        task for task in progress.tasks if task.description == "Restoring database rows"
    )
    assert row_progress.completed == row_count
    assert row_progress.total == row_count
    with target_engine.connect() as connection:
        restored_count = connection.scalar(
            select(func.count()).select_from(base.metadata.tables["audit_entries"])
        )
    assert restored_count == row_count


def test_database_restore_rolls_back_batches_on_row_count_mismatch(
    backup_context,
    tmp_path,
):
    from maintenance.backup.format import BACKUP_FORMAT_VERSION
    from maintenance.backup.restore import _restore_database

    base = backup_context.Base
    target_engine, target_session = _new_database(base, tmp_path / "target.db")
    extract_dir = tmp_path / "payload"
    _write_audit_rows(extract_dir, 1001)
    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["audit"],
        "tables": {"audit_entries": {"rows": 1000}},
        "files": [],
        "configuration": {},
    }

    with pytest.raises(backup_context.BackupFormatError, match="Row count mismatch"):
        _restore_database(extract_dir, manifest, target_session)

    with target_engine.connect() as connection:
        restored_count = connection.scalar(
            select(func.count()).select_from(base.metadata.tables["audit_entries"])
        )
    assert restored_count == 0


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


def test_export_refuses_to_replace_backup_or_key_output(backup_context, tmp_path):
    base = backup_context.Base
    source_engine, source_session = _new_database(base, tmp_path / "source.db")
    source_storage = tmp_path / "source-storage"
    source_storage.mkdir()
    _seed_source(base, source_engine, source_storage)
    backup_path = tmp_path / "backup.conf"
    key_path = tmp_path / "backup.key"
    backup_path.write_bytes(b"existing backup")

    with pytest.raises(backup_context.BackupError, match="already exists"):
        backup_context.export_backup(
            backup_path,
            session_factory=source_session,
            storage_provider=_RootedStorage(source_storage),
            config=backup_context.source_config,
        )
    assert backup_path.read_bytes() == b"existing backup"

    backup_path.unlink()
    key_path.write_text("existing key\n", encoding="utf-8")
    with pytest.raises(backup_context.BackupError, match="already exists"):
        backup_context.export_backup(
            backup_path,
            key_output_path=key_path,
            session_factory=source_session,
            storage_provider=_RootedStorage(source_storage),
            config=backup_context.source_config,
        )
    assert not backup_path.exists()
    assert key_path.read_text(encoding="utf-8") == "existing key\n"


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


def test_import_removes_partially_written_storage_file(
    backup_context,
    tmp_path,
):
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

    class FailingWriter:
        def __init__(self, file):
            self.file = file

        def __enter__(self):
            self.file.__enter__()
            return self

        def __exit__(self, *args):
            return self.file.__exit__(*args)

        def write(self, data):
            self.file.write(bytes(data)[:1])
            raise OSError("simulated storage write failure")

    class FailingStorage(_RootedStorage):
        def fopen(self, path: str, mode: str = "rb"):
            opened = super().fopen(path, mode)
            return FailingWriter(opened) if "w" in mode else opened

    target_config = tmp_path / "target-config.toml"
    _write_config(target_config, secret_key="target-secret", pepper="target-pepper")
    original_config = target_config.read_bytes()

    with pytest.raises(OSError, match="simulated storage write failure"):
        backup_context.import_backup(
            backup_path,
            key_text,
            session_factory=target_session,
            db_engine=target_engine,
            storage_provider=FailingStorage(target_storage),
            config_path=target_config,
            init_path=tmp_path / "init",
        )

    assert not any(path.is_file() for path in target_storage.rglob("*"))
    assert target_config.read_bytes() == original_config


def test_import_rolls_back_database_files_and_config_when_finalization_fails(
    backup_context,
    tmp_path,
    monkeypatch,
):
    from maintenance.backup import restore as backup_restore

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
    target_config = tmp_path / "target-config.toml"
    _write_config(target_config, secret_key="target-secret", pepper="target-pepper")
    original_config = target_config.read_bytes()
    init_path = tmp_path / "init"
    real_atomic_write = backup_restore._write_file_atomically

    def fail_init_write(path: Path, contents: bytes) -> None:
        if path == init_path and contents.startswith(b"This file indicates"):
            raise OSError("simulated init write failure")
        real_atomic_write(path, contents)

    monkeypatch.setattr(backup_restore, "_write_file_atomically", fail_init_write)

    with pytest.raises(OSError, match="simulated init write failure"):
        backup_context.import_backup(
            backup_path,
            key_text,
            session_factory=target_session,
            db_engine=target_engine,
            storage_provider=_RootedStorage(target_storage),
            config_path=target_config,
            init_path=init_path,
        )

    with target_engine.connect() as connection:
        assert all(
            connection.scalar(select(func.count()).select_from(table)) == 0
            for table in base.metadata.tables.values()
        )
    assert not any(path.is_file() for path in target_storage.rglob("*"))
    assert target_config.read_bytes() == original_config
    assert not init_path.exists()


def test_import_attempts_init_rollback_when_config_rollback_fails(
    backup_context,
    tmp_path,
    monkeypatch,
):
    from maintenance.backup import restore as backup_restore

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
    target_config = tmp_path / "target-config.toml"
    _write_config(target_config, secret_key="target-secret", pepper="target-pepper")
    init_path = tmp_path / "init"
    init_path.write_bytes(b"original init\n")

    def fail_after_finalization(*args, finalize=None, **kwargs):
        assert finalize is not None
        finalize()
        raise RuntimeError("simulated post-finalization failure")

    real_restore_snapshot = backup_restore._restore_file_snapshot

    def fail_config_rollback(path: Path, snapshot) -> None:
        if path == target_config:
            raise OSError("simulated config rollback failure")
        real_restore_snapshot(path, snapshot)

    monkeypatch.setattr(backup_restore, "_restore_database", fail_after_finalization)
    monkeypatch.setattr(
        backup_restore,
        "_restore_file_snapshot",
        fail_config_rollback,
    )

    with pytest.raises(RuntimeError, match="post-finalization failure"):
        backup_context.import_backup(
            backup_path,
            key_text,
            session_factory=target_session,
            db_engine=target_engine,
            storage_provider=_RootedStorage(target_storage),
            config_path=target_config,
            init_path=init_path,
        )

    assert init_path.read_bytes() == b"original init\n"


def test_manifest_rejects_duplicate_file_ids(backup_context) -> None:
    from maintenance.backup.archive import _validate_manifest
    from maintenance.backup.format import BACKUP_FORMAT_VERSION

    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["accounts"],
        "tables": {"files": {"rows": 1}},
        "files": [
            {
                "file_id": "duplicate",
                "storage_path": "content/files/first.bin",
                "archive_path": "files/00000000.bin",
                "size": 1,
                "sha256": "0" * 64,
            },
            {
                "file_id": "duplicate",
                "storage_path": "content/files/second.bin",
                "archive_path": "files/00000001.bin",
                "size": 1,
                "sha256": "1" * 64,
            },
        ],
        "configuration": {},
    }

    with pytest.raises(backup_context.BackupFormatError, match="duplicate file IDs"):
        _validate_manifest(manifest)


@pytest.mark.parametrize(
    "configuration",
    [
        [],
        {"security": []},
        {"server": []},
        {"security": {"pepper": 1}},
        {"server": {"secret_key": False}},
    ],
)
def test_manifest_rejects_invalid_configuration_shape(
    backup_context,
    configuration,
) -> None:
    from maintenance.backup.archive import _validate_manifest
    from maintenance.backup.format import BACKUP_FORMAT_VERSION

    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["audit"],
        "tables": {"audit_entries": {"rows": 0}},
        "files": [],
        "configuration": configuration,
    }

    with pytest.raises(
        backup_context.BackupFormatError,
        match="invalid configuration",
    ):
        _validate_manifest(manifest)


def test_manifest_rejects_tables_outside_component_selection(backup_context) -> None:
    from maintenance.backup.archive import _validate_manifest
    from maintenance.backup.format import BACKUP_FORMAT_VERSION

    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["configuration"],
        "tables": {"audit_entries": {"rows": 0}},
        "files": [],
        "configuration": {"security": {"pepper": "restored"}},
    }

    with pytest.raises(
        backup_context.BackupFormatError,
        match="outside the selected components",
    ):
        _validate_manifest(manifest)


def test_manifest_rejects_missing_tables_for_selected_components(
    backup_context,
) -> None:
    from maintenance.backup.archive import _validate_manifest
    from maintenance.backup.format import BACKUP_FORMAT_VERSION

    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["accounts"],
        "tables": {},
        "files": [],
        "configuration": {},
    }

    with pytest.raises(
        backup_context.BackupFormatError,
        match="does not match the selected components",
    ):
        _validate_manifest(manifest)


def test_restore_files_rejects_manifest_entry_without_matching_database_row(
    backup_context,
    tmp_path,
) -> None:
    from maintenance.backup.format import BACKUP_FORMAT_VERSION
    from maintenance.backup.restore import _restore_files

    extract_dir = tmp_path / "payload"
    payload = extract_dir / "files" / "00000000.bin"
    payload.parent.mkdir(parents=True)
    payload.write_bytes(b"payload")
    _write_jsonl(
        extract_dir / "tables" / "files.jsonl",
        [
            {
                "id": "database-file",
                "path": "content/files/database.bin",
                "active": True,
            }
        ],
    )
    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["accounts"],
        "tables": {"files": {"rows": 1}},
        "files": [
            {
                "file_id": "manifest-file",
                "storage_path": "content/files/manifest.bin",
                "archive_path": "files/00000000.bin",
                "size": len(b"payload"),
                "sha256": hashlib.sha256(b"payload").hexdigest(),
            }
        ],
        "configuration": {},
    }
    storage_root = tmp_path / "storage"
    storage_root.mkdir()

    with pytest.raises(
        backup_context.BackupFormatError,
        match="does not match the files table",
    ):
        _restore_files(extract_dir, manifest, _RootedStorage(storage_root))

    assert not (storage_root / "content" / "files" / "manifest.bin").exists()


def test_restore_files_rejects_active_database_row_without_payload(
    backup_context,
    tmp_path,
) -> None:
    from maintenance.backup.format import BACKUP_FORMAT_VERSION
    from maintenance.backup.restore import _restore_files

    extract_dir = tmp_path / "payload"
    _write_jsonl(
        extract_dir / "tables" / "files.jsonl",
        [
            {
                "id": "active-file",
                "path": "content/files/active.bin",
                "active": True,
            }
        ],
    )
    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["accounts"],
        "tables": {"files": {"rows": 1}},
        "files": [],
        "configuration": {},
    }
    storage_root = tmp_path / "storage"
    storage_root.mkdir()

    with pytest.raises(
        backup_context.BackupFormatError,
        match="active files table row has no payload",
    ):
        _restore_files(extract_dir, manifest, _RootedStorage(storage_root))


def test_import_rejects_payload_members_absent_from_manifest(
    backup_context,
    tmp_path,
) -> None:
    from maintenance.backup.format import _encode_header, _header_prefix
    from maintenance.backup.models import BackupHeader

    key = bytes(range(32))
    nonce = bytes(range(12))
    manifest = {
        "format_version": backup_context.backup_core.BACKUP_FORMAT_VERSION,
        "components": ["configuration"],
        "tables": {},
        "files": [],
        "configuration": {
            "security": {"pepper": "restored-pepper"},
            "server": {"secret_key": "restored-secret"},
        },
    }
    payload_root = tmp_path / "archive-source"
    payload_root.mkdir()
    (payload_root / "manifest.json").write_bytes(orjson.dumps(manifest))
    (payload_root / "unexpected.bin").write_bytes(b"not declared")
    compressed_payload = tmp_path / "payload.tar.xz"
    with tarfile.open(compressed_payload, "w:xz") as archive:
        archive.add(payload_root / "manifest.json", arcname="manifest.json")
        archive.add(payload_root / "unexpected.bin", arcname="unexpected.bin")

    header_bytes = _encode_header(
        BackupHeader(
            format_version=backup_context.backup_core.BACKUP_FORMAT_VERSION,
            created_at="2026-09-13T00:00:00+00:00",
            core_version="0.10.1",
            compression="xz",
            encryption="AES-256-GCM",
            nonce="AAECAwQFBgcICQoL",
        )
    )
    prefix = _header_prefix(header_bytes)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(prefix)
    ciphertext = encryptor.update(compressed_payload.read_bytes())
    ciphertext += encryptor.finalize()
    backup_path = tmp_path / "unexpected-member.conf"
    backup_path.write_bytes(prefix + ciphertext + encryptor.tag)

    target_engine, target_session = _new_database(
        backup_context.Base,
        tmp_path / "target.db",
    )
    target_config = tmp_path / "target-config.toml"
    _write_config(target_config, secret_key="target-secret", pepper="target-pepper")

    with pytest.raises(
        backup_context.BackupFormatError,
        match="contents do not match its manifest",
    ):
        backup_context.import_backup(
            backup_path,
            key,
            session_factory=target_session,
            db_engine=target_engine,
            storage_provider=_RootedStorage(tmp_path / "storage"),
            config_path=target_config,
            init_path=tmp_path / "target-init",
        )


def test_restore_rejects_oversized_json_row_before_parsing(
    backup_context,
    tmp_path,
    monkeypatch,
):
    from maintenance.backup import rows as backup_rows
    from maintenance.backup.format import BACKUP_FORMAT_VERSION
    from maintenance.backup.restore import _restore_database

    base = backup_context.Base
    target_engine, target_session = _new_database(base, tmp_path / "target.db")
    extract_dir = tmp_path / "payload"
    _write_audit_rows(extract_dir, 1)
    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["audit"],
        "tables": {"audit_entries": {"rows": 1}},
        "files": [],
        "configuration": {},
    }
    monkeypatch.setattr(backup_rows, "MAX_JSONL_ROW_BYTES", 16)

    with pytest.raises(backup_context.BackupFormatError, match="exceeds"):
        _restore_database(extract_dir, manifest, target_session)

    with target_engine.connect() as connection:
        assert (
            connection.scalar(
                select(func.count()).select_from(base.metadata.tables["audit_entries"])
            )
            == 0
        )


def test_export_rejects_json_row_larger_than_restore_limit(
    backup_context,
    tmp_path,
    monkeypatch,
) -> None:
    from maintenance.backup import export as backup_export

    base = backup_context.Base
    source_engine, source_session = _new_database(base, tmp_path / "source.db")
    with source_engine.begin() as connection:
        connection.execute(
            insert(base.metadata.tables["audit_entries"]),
            {
                "id": "oversized-audit",
                "action": "export-limit",
                "username": None,
                "target": None,
                "data": {"payload": "too large"},
                "result": 200,
                "remote_address": None,
                "logged_time": 0.0,
            },
        )
    staging_dir = tmp_path / "staging"
    staging_dir.mkdir()
    monkeypatch.setattr(backup_export, "MAX_JSONL_ROW_BYTES", 16)
    selection = backup_context.BackupExportSelection.from_component_values(["audit"])

    with pytest.raises(backup_context.BackupIntegrityError, match="backup limit"):
        backup_export._export_tables(
            staging_dir,
            source_session,
            selection=selection,
        )


def test_restore_accepts_json_row_at_export_limit(tmp_path, monkeypatch) -> None:
    from maintenance.backup import rows as backup_rows

    extract_dir = tmp_path / "payload"
    table_path = extract_dir / "tables" / "audit_entries.jsonl"
    table_path.parent.mkdir(parents=True)
    encoded_row = orjson.dumps({"id": "boundary"})
    table_path.write_bytes(encoded_row + b"\n")
    monkeypatch.setattr(backup_rows, "MAX_JSONL_ROW_BYTES", len(encoded_row))
    manifest = {"tables": {"audit_entries": {"rows": 1}}}

    assert list(
        backup_rows._iter_raw_table_rows(extract_dir, manifest, "audit_entries")
    ) == [{"id": "boundary"}]
