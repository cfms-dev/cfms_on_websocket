from __future__ import annotations

import importlib
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.runtime import ensure_src_workdir, initialize_providers

if TYPE_CHECKING:
    from maintenance.backup import BackupHeader, BackupProgressHandler


LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class BackupExportResult:
    output_path: Path
    key_output_path: Path | None
    key: str
    warnings: tuple[str, ...] = ()


@dataclass(frozen=True)
class BackupImportResult:
    created_at: str
    core_version: str
    table_count: int
    file_count: int


def _load_backup_module():
    return importlib.import_module("maintenance.backup")


def export_backup(
    output_path: str | Path,
    *,
    key_output_path: str | Path | None = None,
    progress_handler: BackupProgressHandler | None = None,
) -> BackupExportResult:
    ensure_src_workdir()
    backup_module = _load_backup_module()
    warnings: list[str] = []

    try:
        LOGGER.debug("Initializing providers for backup export")
        initialize_providers()
        key = backup_module.export_backup(
            output_path,
            key_output_path=key_output_path,
            warning_handler=warnings.append,
            progress_handler=progress_handler,
        )
    except (backup_module.BackupError, OSError, ValueError) as exc:
        raise MaintenanceOperationError(str(exc)) from exc

    return BackupExportResult(
        output_path=Path(output_path),
        key_output_path=None if key_output_path is None else Path(key_output_path),
        key=key,
        warnings=tuple(warnings),
    )


def read_backup_info(backup_path: str | Path) -> BackupHeader:
    ensure_src_workdir()
    backup_module = _load_backup_module()

    try:
        LOGGER.debug("Reading backup info from %s", backup_path)
        return backup_module.read_backup_header(backup_path)
    except backup_module.BackupError as exc:
        raise MaintenanceOperationError(str(exc)) from exc


def import_backup(
    backup_path: str | Path,
    *,
    key: str | None = None,
    key_file: str | Path | None = None,
    progress_handler: BackupProgressHandler | None = None,
) -> BackupImportResult:
    ensure_src_workdir()
    if (key is None) == (key_file is None):
        raise MaintenanceOperationError("Specify exactly one key source.")
    backup_module = _load_backup_module()

    try:
        LOGGER.debug("Initializing providers for backup import")
        initialize_providers()
        if key_file is None:
            key_text = key
        else:
            key_text = Path(key_file).read_text(encoding="utf-8").strip()
        if key_text is None:
            raise MaintenanceOperationError("Specify exactly one key source.")
        result: dict[str, Any] = backup_module.import_backup(
            backup_path,
            key_text,
            init_path=Path("init"),
            progress_handler=progress_handler,
        )
    except (backup_module.BackupError, OSError, ValueError) as exc:
        raise MaintenanceOperationError(str(exc)) from exc

    return BackupImportResult(
        created_at=str(result["created_at"]),
        core_version=str(result["core_version"]),
        table_count=len(result["tables"]),
        file_count=len(result["files"]),
    )
