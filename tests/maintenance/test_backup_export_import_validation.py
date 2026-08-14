from pathlib import Path

import pytest
import tomlkit
from sqlalchemy import insert

from tests.maintenance.test_backup_format_compatibility import (
    _dump_backup_tables,
    _new_database,
    _read_jsonl,
    _RootedStorage,
    _seed_source,
    _write_config,
    _write_jsonl,
)


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


def test_banned_subnet_export_includes_only_referenced_comments(
    backup_context, tmp_path
):
    from maintenance.backup.core import _stage_backup_payload

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
    from maintenance.backup.core import BACKUP_FORMAT_VERSION, _restore_database

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
