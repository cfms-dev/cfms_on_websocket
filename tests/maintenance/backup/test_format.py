import datetime as dt
import hashlib
import io
import tarfile

import pytest


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


def test_comment_digest_backup_representation(backup_context) -> None:
    from maintenance.backup.format import _serialize_table_value
    from maintenance.backup.rows import _decode_row

    digest = bytes.fromhex("e2" * 32)
    comments = backup_context.Base.metadata.tables["comments"]

    encoded = _serialize_table_value("comments", "content_digest", digest)
    decoded = _decode_row({"content_digest": encoded}, comments)

    assert encoded == digest.hex()
    assert decoded["content_digest"] == digest


def test_comment_digest_backup_rejects_invalid_hex(backup_context) -> None:
    from maintenance.backup.rows import _decode_row

    comments = backup_context.Base.metadata.tables["comments"]

    with pytest.raises(backup_context.BackupFormatError):
        _decode_row({"content_digest": "not-a-digest"}, comments)


def test_file_digest_verification_accepts_valid_uppercase_hex(
    backup_context,
    tmp_path,
) -> None:
    from maintenance.backup.archive import _verify_file_digest

    contents = b"backup payload"
    payload = tmp_path / "payload.bin"
    payload.write_bytes(contents)
    entry = {
        "file_id": "file-1",
        "storage_path": "content/files/file-1.bin",
        "archive_path": "files/00000000.bin",
        "size": len(contents),
        "sha256": hashlib.sha256(contents).hexdigest().upper(),
    }
    manifest = {
        "format_version": backup_context.backup_core.BACKUP_FORMAT_VERSION,
        "tables": {
            table_name: {"rows": 0}
            for table_name in backup_context.backup_core.BACKUP_TABLE_NAMES
        },
        "files": [entry],
        "configuration": {},
    }

    backup_context.backup_core._validate_manifest(manifest)
    _verify_file_digest(payload, entry)


@pytest.mark.parametrize(
    "unsafe_path",
    ("C:escape.bin", "content/file.bin:stream", r"content\escape.bin"),
)
def test_storage_paths_reject_windows_drive_ads_and_separators(
    backup_context,
    unsafe_path,
) -> None:
    from maintenance.backup.archive import _validate_storage_path

    with pytest.raises(backup_context.BackupFormatError, match="Unsafe storage path"):
        _validate_storage_path(unsafe_path)


@pytest.mark.parametrize(
    "unsafe_path",
    ("files/C:escape.bin", "files/data.bin:stream", r"files\escape.bin"),
)
def test_archive_paths_reject_windows_drive_ads_and_separators(
    backup_context,
    tmp_path,
    unsafe_path,
) -> None:
    from maintenance.backup.archive import _safe_payload_path

    with pytest.raises(backup_context.BackupFormatError, match="Unsafe archive path"):
        _safe_payload_path(tmp_path, unsafe_path)


def test_backup_extraction_rejects_uncompressed_size_limit(
    backup_context,
    tmp_path,
    monkeypatch,
) -> None:
    from maintenance.backup import archive as backup_archive

    source = tmp_path / "payload.tar.xz"
    directory = tarfile.TarInfo("tables/")
    directory.type = tarfile.DIRTYPE
    member = tarfile.TarInfo("tables/audit_entries.jsonl")
    member.size = 5
    with tarfile.open(source, "w:xz") as archive:
        archive.addfile(directory)
        archive.addfile(member, io.BytesIO(b"12345"))
    target = tmp_path / "extracted"
    target.mkdir()
    monkeypatch.setattr(backup_archive, "MAX_BACKUP_UNCOMPRESSED_BYTES", 4)

    with pytest.raises(backup_context.BackupFormatError, match="uncompressed size"):
        backup_archive._safe_extract_tar_xz(source, target)

    assert not (target / "tables" / "audit_entries.jsonl").exists()


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


def test_backup_key_decoder_rejects_invalid_legacy_base64url(backup_context):
    legacy_key = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8"

    with pytest.raises(ValueError, match="valid base64url"):
        backup_context.decode_backup_key(f"{legacy_key}!!!!")


def test_backup_header_rejects_coercible_field_types(backup_context) -> None:
    from maintenance.backup.models import BackupHeader

    with pytest.raises(backup_context.BackupFormatError, match="field types"):
        BackupHeader.from_mapping(
            {
                "format_version": True,
                "created_at": "2026-09-13T00:00:00+00:00",
                "core_version": "0.10.1",
                "compression": "xz",
                "encryption": "AES-256-GCM",
                "nonce": "AAECAwQFBgcICQoL",
            }
        )


def test_backup_row_rejects_invalid_datetime_as_format_error(
    backup_context,
) -> None:
    from sqlalchemy import Column, DateTime, MetaData, Table

    from maintenance.backup.rows import _decode_row

    table = Table("example", MetaData(), Column("created_at", DateTime()))

    with pytest.raises(backup_context.BackupFormatError, match="datetime"):
        _decode_row({"created_at": "not-a-datetime"}, table)


@pytest.mark.parametrize("nonce", ("a", "AAAAAAAAAAAAAAAA!"))
def test_backup_header_rejects_malformed_base64_nonce(
    backup_context,
    nonce,
) -> None:
    from maintenance.backup.format import _validate_header
    from maintenance.backup.models import BackupHeader

    header = BackupHeader(
        format_version=backup_context.backup_core.BACKUP_FORMAT_VERSION,
        created_at="2026-09-13T00:00:00+00:00",
        core_version="0.10.1",
        compression="xz",
        encryption="AES-256-GCM",
        nonce=nonce,
    )

    with pytest.raises(backup_context.BackupFormatError, match="nonce"):
        _validate_header(header)


@pytest.mark.parametrize(
    "created_at",
    ("not-a-time", "2026-09-13T00:00:00"),
)
def test_backup_header_rejects_invalid_created_at(
    backup_context,
    created_at,
) -> None:
    from maintenance.backup.format import _validate_header
    from maintenance.backup.models import BackupHeader

    header = BackupHeader(
        format_version=backup_context.backup_core.BACKUP_FORMAT_VERSION,
        created_at=created_at,
        core_version="0.10.1",
        compression="xz",
        encryption="AES-256-GCM",
        nonce="AAECAwQFBgcICQoL",
    )

    with pytest.raises(backup_context.BackupFormatError, match="created_at"):
        _validate_header(header)


def test_backup_header_rejects_invalid_core_version(backup_context) -> None:
    from maintenance.backup.format import _validate_header
    from maintenance.backup.models import BackupHeader

    header = BackupHeader(
        format_version=backup_context.backup_core.BACKUP_FORMAT_VERSION,
        created_at="2026-09-13T00:00:00+00:00",
        core_version="not-a-version",
        compression="xz",
        encryption="AES-256-GCM",
        nonce="AAECAwQFBgcICQoL",
    )

    with pytest.raises(backup_context.BackupFormatError, match="core_version"):
        _validate_header(header)


@pytest.mark.parametrize(
    "layout",
    ("current", "previous_compiled", "legacy_access_rules"),
)
def test_pre_scheduling_full_backup_manifest_is_accepted(
    backup_context, layout
) -> None:
    core = backup_context.backup_core
    current_tables = set(core.BACKUP_TABLE_NAMES)
    layouts = {
        "current": current_tables,
        "previous_compiled": current_tables - {"compiled_access_rule_sets"},
        "legacy_access_rules": (
            current_tables - set(core.COMPILED_ACCESS_RULE_TABLE_NAMES)
        )
        | set(core.LEGACY_ACCESS_RULE_TABLE_NAMES),
    }
    historical_tables = layouts[layout] - {"schedules"}
    manifest = {
        "format_version": core.BACKUP_FORMAT_VERSION,
        "tables": {table_name: {"rows": 0} for table_name in historical_tables},
        "files": [],
        "configuration": {},
    }

    assert core._validate_manifest(manifest) is None


def test_runtime_state_tables_are_excluded(backup_context):
    excluded = backup_context.backup_core.EXCLUDED_TABLE_NAMES

    assert "rate_limit_buckets" in excluded
    assert "risk_ip_accounts" in excluded
    assert "schedule_executions" in excluded
    assert "scheduling_runtime_state" in excluded
    assert "system_states" in excluded
