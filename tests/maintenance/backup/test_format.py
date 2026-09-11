import datetime as dt

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
