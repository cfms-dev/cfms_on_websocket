import sys
from types import SimpleNamespace

import pytest

from tests.maintenance.backup.support import _SRC_PATH, _write_config


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
    from maintenance.backup.archive import _validate_manifest
    from maintenance.backup.constants import BACKUP_FORMAT_VERSION
    from maintenance.backup.rows import _decode_row
    from maintenance.backup.selection import (
        BACKUP_TABLE_NAMES,
        COMPILED_ACCESS_RULE_TABLE_NAMES,
        EXCLUDED_TABLE_NAMES,
        LEGACY_ACCESS_RULE_TABLE_NAMES,
    )

    backup_internals = SimpleNamespace(
        BACKUP_FORMAT_VERSION=BACKUP_FORMAT_VERSION,
        BACKUP_TABLE_NAMES=BACKUP_TABLE_NAMES,
        COMPILED_ACCESS_RULE_TABLE_NAMES=COMPILED_ACCESS_RULE_TABLE_NAMES,
        EXCLUDED_TABLE_NAMES=EXCLUDED_TABLE_NAMES,
        LEGACY_ACCESS_RULE_TABLE_NAMES=LEGACY_ACCESS_RULE_TABLE_NAMES,
        _decode_row=_decode_row,
        _validate_manifest=_validate_manifest,
    )

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
        backup_core=backup_internals,
        source_config=source_config,
    )
