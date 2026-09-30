from pathlib import Path

import orjson
import pytest
import tomlkit
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import insert, select

from .support import (
    _new_database,
    _read_jsonl,
    _RootedStorage,
    _write_config,
    _write_jsonl,
)


def _option_row(**changes) -> dict:
    return {
        "owner": "retired_extension",
        "option_key": "policy",
        "schema_version": 73,
        "revision": 12,
        "payload": {"unknown_setting": ["preserve", {"nested": True}]},
        "updated_at": 1_700_000_000.125,
        **changes,
    }


def _configuration_manifest(*, version: int = 2, rows: int | None = 0) -> dict:
    return {
        "format_version": version,
        "components": ["configuration"],
        "tables": {} if rows is None else {"options": {"rows": rows}},
        "files": [],
        "configuration": {
            "security": {"pepper": "restored-pepper"},
            "server": {"secret_key": "restored-secret"},
        },
    }


def _write_archive(path: Path, manifest: dict, *, header_version: int) -> bytes:
    from maintenance.backup.format import _encode_header, _write_encrypted_archive
    from maintenance.backup.models import BackupHeader

    staging = path.parent / f"{path.stem}-payload"
    staging.mkdir()
    (staging / "files").mkdir()
    for table_name in manifest["tables"]:
        _write_jsonl(staging / "tables" / f"{table_name}.jsonl", [])
    (staging / "manifest.json").write_bytes(orjson.dumps(manifest))
    key = bytes(range(32))
    header = BackupHeader(
        format_version=header_version,
        created_at="2026-09-30T00:00:00+00:00",
        core_version="0.10.1",
        compression="xz",
        encryption="AES-256-GCM",
        nonce="AAECAwQFBgcICQoL",
    )
    _write_encrypted_archive(
        path, staging, _encode_header(header), key, bytes(range(12))
    )
    return key


@pytest.mark.parametrize("version", [1, 2])
def test_configuration_manifest_accepts_supported_versions(backup_context, version):
    from maintenance.backup.archive import _validate_manifest

    _validate_manifest(_configuration_manifest(version=version))


def test_v1_configuration_manifest_can_omit_options(backup_context):
    from maintenance.backup.archive import _validate_manifest

    _validate_manifest(_configuration_manifest(version=1, rows=None))


def test_v2_configuration_manifest_requires_options(backup_context):
    from maintenance.backup.archive import _validate_manifest

    with pytest.raises(backup_context.BackupFormatError, match="selected components"):
        _validate_manifest(_configuration_manifest(rows=None))


@pytest.mark.parametrize("version", [1, 2])
def test_options_cannot_be_restored_outside_configuration(backup_context, version):
    from maintenance.backup.archive import _validate_manifest

    manifest = _configuration_manifest(version=version)
    manifest["components"] = ["audit"]
    manifest["configuration"] = {}
    manifest["tables"]["audit_entries"] = {"rows": 0}

    with pytest.raises(backup_context.BackupFormatError, match="outside the selected"):
        _validate_manifest(manifest)


@pytest.mark.parametrize("version", [1, 2])
def test_backup_header_accepts_supported_versions(backup_context, version):
    from maintenance.backup.format import _validate_header
    from maintenance.backup.models import BackupHeader

    _validate_header(
        BackupHeader(
            format_version=version,
            created_at="2026-09-30T00:00:00+00:00",
            core_version="0.10.1",
            compression="xz",
            encryption="AES-256-GCM",
            nonce="AAECAwQFBgcICQoL",
        )
    )


@pytest.mark.parametrize("version", [True, 1.0, 0, 3])
def test_backup_header_rejects_unsupported_versions(backup_context, version):
    from maintenance.backup.format import _validate_header
    from maintenance.backup.models import BackupHeader

    with pytest.raises(backup_context.BackupFormatError, match="format version"):
        _validate_header(
            BackupHeader(
                format_version=version,
                created_at="2026-09-30T00:00:00+00:00",
                core_version="0.10.1",
                compression="xz",
                encryption="AES-256-GCM",
                nonce="AAECAwQFBgcICQoL",
            )
        )


@pytest.mark.parametrize(
    ("field", "invalid"),
    [
        ("owner", "Bad owner"),
        ("option_key", "Bad key"),
        ("schema_version", 0),
        ("schema_version", True),
        ("revision", -1),
        ("revision", "12"),
        ("payload", [1, 2]),
        ("updated_at", float("inf")),
        ("updated_at", float("nan")),
    ],
)
def test_option_restore_validates_generic_row_shape(backup_context, field, invalid):
    from maintenance.backup.rows import _decode_row

    with pytest.raises(backup_context.BackupFormatError, match="invalid option row"):
        _decode_row(
            _option_row(**{field: invalid}),
            backup_context.Base.metadata.tables["options"],
        )


def test_unknown_option_owner_and_schema_are_preserved(backup_context):
    from maintenance.backup.rows import _decode_row

    row = _option_row()
    assert _decode_row(row, backup_context.Base.metadata.tables["options"]) == row


@pytest.mark.parametrize("include_configuration", [False, True])
def test_options_export_follows_configuration_selection(
    backup_context, tmp_path, include_configuration
):
    from maintenance.backup.export import _stage_backup_payload

    source_engine, source_session = _new_database(
        backup_context.Base, tmp_path / "source.db"
    )
    options = backup_context.Base.metadata.tables["options"]
    row = _option_row()
    with source_engine.begin() as connection:
        connection.execute(insert(options), row)
    staging = tmp_path / "staging"
    staging.mkdir()
    selected = "configuration" if include_configuration else "audit"
    selection = backup_context.BackupExportSelection.from_component_values([selected])

    manifest = _stage_backup_payload(
        staging,
        session_factory=source_session,
        storage_provider=_RootedStorage(tmp_path / "storage"),
        config=backup_context.source_config,
        selection=selection,
    )

    assert ("options" in manifest["tables"]) is include_configuration
    if include_configuration:
        assert _read_jsonl(staging / "tables" / "options.jsonl") == [row]
    else:
        assert not (staging / "tables" / "options.jsonl").exists()


def test_configuration_restore_keeps_unknown_extensions_without_loading_them(
    backup_context, tmp_path
):
    from maintenance.backup.restore import _restore_database

    target_engine, target_session = _new_database(
        backup_context.Base, tmp_path / "target.db"
    )
    payload = tmp_path / "payload"
    row = _option_row()
    _write_jsonl(payload / "tables" / "options.jsonl", [row])
    _restore_database(payload, _configuration_manifest(rows=1), target_session)

    with target_engine.connect() as connection:
        restored = (
            connection.execute(
                select(backup_context.Base.metadata.tables["options"]).where(
                    backup_context.Base.metadata.tables["options"].c.owner
                    == row["owner"]
                )
            )
            .mappings()
            .one()
        )
    assert dict(restored) == row


@pytest.mark.parametrize("version", [1, 2])
def test_options_restore_uses_defaults_and_stamps_current_schema(
    backup_context, tmp_path, version
):
    from include.config.paths import EXECUTABLE_ABSPATH
    from include.database.options import read_option

    manifest = _configuration_manifest(
        version=version, rows=None if version == 1 else 0
    )
    archive_path = tmp_path / "default-options.conf"
    key = _write_archive(archive_path, manifest, header_version=version)
    target_engine, target_session = _new_database(
        backup_context.Base, tmp_path / "target.db"
    )
    target_config = tmp_path / "target-config.toml"
    _write_config(target_config, secret_key="target-secret", pepper="target-pepper")
    document = tomlkit.parse(target_config.read_text("utf-8"))
    document["server"]["name"] = "Old target TOML name"
    document["extensions"]["brute_force_lockdown"] = {"window_seconds": 42}
    target_config.write_text(tomlkit.dumps(document), "utf-8")

    backup_context.import_backup(
        archive_path,
        key,
        session_factory=target_session,
        db_engine=target_engine,
        storage_provider=_RootedStorage(tmp_path / "storage"),
        config_path=target_config,
        init_path=tmp_path / "init",
    )

    with target_session() as session:
        option = read_option(session, "core", "server")
        assert option is not None
        assert option.payload == {"name": "CFMS WebSocket Server"}
        options = backup_context.Base.metadata.tables["options"]
        assert (
            session.execute(
                select(options).where(options.c.owner == "brute_force_lockdown")
            ).all()
            == []
        )
    scripts = ScriptDirectory.from_config(Config(EXECUTABLE_ABSPATH / "alembic.ini"))
    with target_engine.connect() as connection:
        assert MigrationContext.configure(connection).get_current_heads() == (
            scripts.get_current_head(),
        )
    preserved = tomlkit.parse(target_config.read_text("utf-8"))
    assert preserved["server"]["name"] == "Old target TOML name"
    assert preserved["extensions"]["brute_force_lockdown"]["window_seconds"] == 42


def test_restore_does_not_parse_existing_core_option_schema(backup_context, tmp_path):
    from maintenance.backup.restore import _restore_database

    target_engine, target_session = _new_database(
        backup_context.Base, tmp_path / "target.db"
    )
    payload = tmp_path / "payload"
    row = _option_row(owner="core", option_key="server")
    _write_jsonl(payload / "tables" / "options.jsonl", [row])

    _restore_database(payload, _configuration_manifest(rows=1), target_session)

    with target_engine.connect() as connection:
        restored = (
            connection.execute(select(backup_context.Base.metadata.tables["options"]))
            .mappings()
            .all()
        )
    assert [dict(option) for option in restored] == [row]


def test_restore_rolls_back_options_defaults_and_schema_stamp(backup_context, tmp_path):
    from maintenance.backup.restore import _restore_database

    target_engine, target_session = _new_database(
        backup_context.Base, tmp_path / "target.db"
    )
    payload = tmp_path / "payload"
    _write_jsonl(payload / "tables" / "options.jsonl", [_option_row()])

    def fail_finalization():
        raise OSError("simulated finalization failure")

    with pytest.raises(OSError, match="finalization failure"):
        _restore_database(
            payload,
            _configuration_manifest(rows=1),
            target_session,
            finalize=fail_finalization,
        )

    with target_engine.connect() as connection:
        assert (
            connection.execute(
                select(backup_context.Base.metadata.tables["options"])
            ).all()
            == []
        )
        assert MigrationContext.configure(connection).get_current_heads() == ()


@pytest.mark.parametrize(("header_version", "payload_version"), [(1, 2), (2, 1)])
def test_import_rejects_header_payload_version_mismatch(
    backup_context, tmp_path, header_version, payload_version
):
    manifest = _configuration_manifest(version=payload_version)
    archive_path = tmp_path / "mismatched.conf"
    key = _write_archive(archive_path, manifest, header_version=header_version)
    target_engine, target_session = _new_database(
        backup_context.Base, tmp_path / "target.db"
    )

    with pytest.raises(
        backup_context.BackupFormatError, match="format versions differ"
    ):
        backup_context.import_backup(
            archive_path,
            key,
            session_factory=target_session,
            db_engine=target_engine,
            storage_provider=_RootedStorage(tmp_path / "storage"),
            config_path=tmp_path / "config.toml",
            init_path=tmp_path / "init",
        )

    with target_engine.connect() as connection:
        assert (
            connection.execute(
                select(backup_context.Base.metadata.tables["options"])
            ).all()
            == []
        )
        assert MigrationContext.configure(connection).get_current_heads() == ()
