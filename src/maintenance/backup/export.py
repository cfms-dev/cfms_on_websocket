import datetime as dt
import hashlib
import json
import logging
import os
import secrets
import tempfile
import warnings
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import orjson
from rich.progress import Progress
from sqlalchemy import case, select
from sqlalchemy.orm import sessionmaker

from include.config.constants import CORE_VERSION
from include.config.settings import global_config
from include.database.session import Session
from include.providers.base import StorageProvider
from include.providers.manager import ProviderManager
from maintenance.backup.archive import _write_json
from maintenance.backup.constants import (
    BACKUP_FORMAT_VERSION,
    GCM_NONCE_BYTES,
    MAX_BACKUP_FILES,
    MAX_JSONL_ROW_BYTES,
)
from maintenance.backup.format import (
    _encode_bytes,
    _encode_header,
    _serialize_table_value,
    _write_encrypted_archive,
    encode_backup_key,
)
from maintenance.backup.models import (
    BackupError,
    BackupHeader,
    BackupIntegrityError,
    BackupWarning,
    BackupWarningHandler,
)
from maintenance.backup.progress import (
    EXPORT_PROGRESS_STEPS,
    _BackupProgressReporter,
    _emit_progress,
)
from maintenance.backup.rows import _iter_raw_table_rows
from maintenance.backup.selection import (
    BACKUP_TABLE_NAMES,
    EXCLUDED_TABLE_NAMES,
    BackupComponent,
    BackupExportSelection,
    _active_compiled_rule_set_id_query,
    _apply_compiled_access_rule_export_filter,
    _apply_export_table_filter,
    _backup_tables,
    _selected_table_names,
    _selection_components,
)

LOGGER = logging.getLogger(__name__)


@dataclass(frozen=True)
class _TableExportResult:
    manifest: dict[str, Any]


def export_backup(
    output_path: str | os.PathLike[str],
    *,
    key: bytes | None = None,
    key_output_path: str | os.PathLike[str] | None = None,
    selection: BackupExportSelection | None = None,
    session_factory: sessionmaker = Session,
    storage_provider: StorageProvider | None = None,
    config=global_config,
    warning_handler: BackupWarningHandler | None = None,
    progress: Progress | None = None,
    show_progress_details: bool = False,
) -> str:
    storage = storage_provider or ProviderManager().storage
    progress_reporter = _BackupProgressReporter(progress, show_progress_details)
    key_bytes = secrets.token_bytes(32) if key is None else key
    if len(key_bytes) != 32:
        raise ValueError("Backup key must be exactly 32 bytes")

    output = Path(output_path)
    key_output = None if key_output_path is None else Path(key_output_path)
    if output.exists():
        raise BackupError(f"Backup output already exists: {output}")
    if key_output is not None:
        if key_output.resolve() == output.resolve():
            raise BackupError("Backup output and key output must be different files")
        if key_output.exists():
            raise BackupError(f"Backup key output already exists: {key_output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    LOGGER.debug("Starting backup export to %s", output)
    _emit_progress(
        progress_reporter,
        phase="prepare_export",
        message="Preparing backup export",
        current_step=1,
        total_steps=EXPORT_PROGRESS_STEPS,
        detail=str(output),
    )
    created_at = dt.datetime.now(dt.UTC).isoformat()
    nonce = secrets.token_bytes(GCM_NONCE_BYTES)
    header = BackupHeader(
        format_version=BACKUP_FORMAT_VERSION,
        created_at=created_at,
        core_version=str(CORE_VERSION),
        compression="xz",
        encryption="AES-256-GCM",
        nonce=_encode_bytes(nonce),
    )
    header_bytes = _encode_header(header)

    with tempfile.TemporaryDirectory(prefix="cfms-backup-export-") as tmp_dir:
        staging_dir = Path(tmp_dir)
        LOGGER.debug("Created backup staging directory: %s", staging_dir)
        manifest = _stage_backup_payload(
            staging_dir,
            session_factory=session_factory,
            storage_provider=storage,
            config=config,
            selection=selection,
            warning_handler=warning_handler,
            progress_reporter=progress_reporter,
        )
        _emit_progress(
            progress_reporter,
            phase="write_manifest",
            message="Writing backup manifest",
            current_step=4,
            total_steps=EXPORT_PROGRESS_STEPS,
        )
        _write_json(staging_dir / "manifest.json", manifest)
        _emit_progress(
            progress_reporter,
            phase="encrypt_archive",
            message="Compressing and encrypting backup payload",
            current_step=5,
            total_steps=EXPORT_PROGRESS_STEPS,
        )
        _write_encrypted_archive(
            output,
            staging_dir,
            header_bytes,
            key_bytes,
            nonce,
            progress_reporter=progress_reporter,
        )

    encoded_key = encode_backup_key(key_bytes)
    if key_output is not None:
        LOGGER.debug("Writing backup key to %s", key_output)
        try:
            _write_key_file(key_output, encoded_key)
        except Exception:
            output.unlink(missing_ok=True)
            raise
    _emit_progress(
        progress_reporter,
        phase="complete_export",
        message="Backup export completed",
        current_step=6,
        total_steps=EXPORT_PROGRESS_STEPS,
        detail=str(output),
    )
    LOGGER.debug("Backup export completed: %s", output)
    return encoded_key


def _write_key_file(path: Path, encoded_key: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="") as output:
            output.write(f"{encoded_key}\n")
            output.flush()
            os.fsync(output.fileno())
        try:
            os.link(temporary_path, path)
        except FileExistsError as exc:
            raise BackupError(f"Backup key output already exists: {path}") from exc
    finally:
        temporary_path.unlink(missing_ok=True)


def _stage_backup_payload(
    staging_dir: Path,
    *,
    session_factory: sessionmaker,
    storage_provider: StorageProvider,
    config,
    selection: BackupExportSelection | None = None,
    warning_handler: BackupWarningHandler | None = None,
    progress_reporter: _BackupProgressReporter | None = None,
) -> dict[str, Any]:
    tables_dir = staging_dir / "tables"
    files_dir = staging_dir / "files"
    tables_dir.mkdir()
    files_dir.mkdir()

    _emit_progress(
        progress_reporter,
        phase="export_tables",
        message="Exporting database tables",
        current_step=2,
        total_steps=EXPORT_PROGRESS_STEPS,
    )
    table_export = _export_tables(
        tables_dir,
        session_factory,
        selection=selection,
        progress_reporter=progress_reporter,
    )
    _emit_progress(
        progress_reporter,
        phase="export_files",
        message="Copying storage files",
        current_step=3,
        total_steps=EXPORT_PROGRESS_STEPS,
    )
    file_manifest = _export_files(
        staging_dir,
        table_export.manifest,
        storage_provider,
        warning_handler=warning_handler,
        progress_reporter=progress_reporter,
    )
    components = _selection_components(selection)
    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "core_version": str(CORE_VERSION),
        "exported_at": dt.datetime.now(dt.UTC).isoformat(),
        "components": sorted(component.value for component in components),
        "tables": table_export.manifest,
        "excluded_tables": sorted(EXCLUDED_TABLE_NAMES),
        "files": file_manifest,
    }
    if BackupComponent.CONFIGURATION in components:
        manifest["configuration"] = {
            "security": {"pepper": _config_get(config, ("security", "pepper"), "")},
            "server": {"secret_key": _config_get(config, ("server", "secret_key"), "")},
        }
    else:
        manifest["configuration"] = {}
    return manifest


def _export_tables(
    tables_dir: Path,
    session_factory: sessionmaker,
    *,
    selection: BackupExportSelection | None = None,
    progress_reporter: _BackupProgressReporter | None = None,
) -> _TableExportResult:
    metadata_tables = _backup_tables()
    manifest: dict[str, Any] = {}
    components = _selection_components(selection)
    full_export = selection is None

    with session_factory() as session:
        connection = session.connection()
        active_compiled_rule_set_ids = _active_compiled_rule_set_id_query(
            metadata_tables,
        )
        table_names = BACKUP_TABLE_NAMES
        if not full_export:
            table_names = _selected_table_names(
                components,
                include_files=bool(
                    BackupComponent.ACCOUNTS in components
                    or BackupComponent.DOCUMENT_LIBRARY in components
                ),
            )

        for table_index, table_name in enumerate(table_names, start=1):
            LOGGER.debug(
                "Exporting table %s (%d/%d)",
                table_name,
                table_index,
                len(table_names),
            )
            _emit_progress(
                progress_reporter,
                phase="export_table",
                message="Exporting table",
                current_step=2,
                total_steps=EXPORT_PROGRESS_STEPS,
                detail=table_name,
                completed_units=table_index,
                total_units=len(table_names),
                detail_task=True,
            )
            table = metadata_tables[table_name]
            stored_columns = [
                column for column in table.columns if column.computed is None
            ]
            columns = [column.name for column in stored_columns]
            rows_path = tables_dir / f"{table_name}.jsonl"
            row_count = 0
            order_by = [column for column in table.primary_key.columns]
            selected_columns = [
                (
                    case(
                        (
                            column.in_(active_compiled_rule_set_ids),
                            column,
                        ),
                        else_=None,
                    ).label(column.name)
                    if table_name == "nodes" and column.name == "access_rule_set_id"
                    else column
                )
                for column in stored_columns
            ]
            statement = select(*selected_columns)
            if order_by:
                statement = statement.order_by(*order_by)
            if not full_export:
                statement = _apply_export_table_filter(
                    statement,
                    table,
                    table_name,
                    metadata_tables,
                    components,
                )
            statement = _apply_compiled_access_rule_export_filter(
                statement,
                table,
                table_name,
                metadata_tables,
                active_compiled_rule_set_ids,
            )

            with rows_path.open("wb") as f:
                for row in connection.execute(statement).mappings():
                    encoded = {}
                    for column in stored_columns:
                        value = row[column.name]
                        encoded[str(column.name)] = _serialize_table_value(
                            table_name,
                            column.name,
                            value,
                        )
                    encoded_row = orjson.dumps(encoded, option=orjson.OPT_SORT_KEYS)
                    if len(encoded_row) > MAX_JSONL_ROW_BYTES:
                        raise BackupIntegrityError(
                            f"Database row in table {table_name!r} exceeds the "
                            f"{MAX_JSONL_ROW_BYTES}-byte backup limit"
                        )
                    f.write(encoded_row)
                    f.write(b"\n")
                    row_count += 1

            manifest[table_name] = {"columns": columns, "rows": row_count}
            LOGGER.debug("Exported table %s with %d row(s)", table_name, row_count)

    return _TableExportResult(manifest=manifest)


def _export_files(
    staging_dir: Path,
    table_manifest: dict[str, Any],
    storage_provider: StorageProvider,
    *,
    warning_handler: BackupWarningHandler | None = None,
    progress_reporter: _BackupProgressReporter | None = None,
) -> list[dict[str, Any]]:
    files_dir = staging_dir / "files"
    if "files" not in table_manifest:
        return []
    total_files = table_manifest["files"]["rows"]
    if total_files > MAX_BACKUP_FILES:
        raise BackupIntegrityError(
            f"Backup selection contains more than {MAX_BACKUP_FILES} files"
        )
    file_manifest = []
    LOGGER.debug("Found %d database file record(s) to inspect", total_files)
    manifest = {"tables": table_manifest}
    for file_index, row in enumerate(
        _iter_raw_table_rows(staging_dir, manifest, "files"),
        start=1,
    ):
        file_id = str(row["id"])
        storage_path = str(row["path"])
        active = bool(row["active"])
        index = len(file_manifest)
        archive_path = f"files/{index:08d}.bin"
        staged_file = files_dir / f"{index:08d}.bin"
        LOGGER.debug(
            "Copying storage file %s from %s (%d/%d)",
            file_id,
            storage_path,
            file_index,
            total_files,
        )
        _emit_progress(
            progress_reporter,
            phase="export_file",
            message="Copying storage file",
            current_step=3,
            total_steps=EXPORT_PROGRESS_STEPS,
            detail=f"{file_id}: {storage_path}",
            completed_units=file_index,
            total_units=total_files,
            detail_task=True,
        )

        if not storage_provider.exists(storage_path):
            if not active:
                _warn_backup_skip(
                    "Skipping inactive database file record "
                    f"{file_id!r} because its physical file is missing: "
                    f"{storage_path}",
                    warning_handler,
                )
                continue
            raise BackupIntegrityError(
                f"Physical file for database file record {file_id!r} is missing: "
                f"{storage_path}"
            )

        sha256 = hashlib.sha256()
        size = 0
        with (
            storage_provider.fopen(storage_path, "rb") as source,
            staged_file.open("wb") as target,
        ):
            while chunk := source.read(1024 * 1024):
                sha256.update(chunk)
                size += len(chunk)
                target.write(chunk)

        file_manifest.append(
            {
                "file_id": file_id,
                "storage_path": storage_path,
                "archive_path": archive_path,
                "size": size,
                "sha256": sha256.hexdigest(),
            }
        )
        LOGGER.debug(
            "Copied storage file %s (%d byte(s), sha256=%s)",
            file_id,
            size,
            sha256.hexdigest(),
        )

    return file_manifest


def _warn_backup_skip(
    message: str,
    warning_handler: BackupWarningHandler | None,
) -> None:
    LOGGER.debug("Backup warning: %s", message)
    if warning_handler is not None:
        warning_handler(message)
        return
    warnings.warn(message, BackupWarning, stacklevel=2)


def _config_get(config, keys: tuple[str, ...], default: Any = None) -> Any:
    value = config
    for key in keys:
        try:
            value = value[key]
        except KeyError, TypeError:
            return default
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return json.loads(json.dumps(value))
