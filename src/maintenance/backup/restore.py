import logging
import os
import shutil
import tempfile
from pathlib import Path
from typing import Any

import tomlkit
from rich.progress import Progress
from sqlalchemy import func, insert, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from include.config.paths import EXECUTABLE_ABSPATH
from include.database.session import Base, Session, engine
from include.domains.documents.commands.name_conflicts import is_node_name_conflict
from include.domains.operations.comments import CommentStore
from include.providers.base import StorageProvider
from include.providers.manager import ProviderManager
from maintenance.backup.archive import (
    _cleanup_restored_files,
    _load_manifest,
    _manifest_includes_configuration,
    _manifest_table_names,
    _safe_extract_tar_xz,
    _safe_payload_path,
    _validate_manifest,
    _validate_storage_path,
    _verify_file_digest,
)
from maintenance.backup.format import (
    _decrypt_payload,
    _read_header_bytes,
    _validate_header,
    decode_backup_key,
)
from maintenance.backup.legacy import (
    _build_missing_compiled_rule_set_mapping,
    _load_compiled_rule_node_ids,
    _load_legacy_access_rule_rows,
    _load_legacy_banned_subnet_reasons,
    _load_legacy_node_namespace,
    _restore_legacy_access_rules,
    _restore_missing_compiled_rule_sets,
)
from maintenance.backup.models import (
    BackupFormatError,
    BackupRestoreError,
)
from maintenance.backup.nodes import _restore_node_tables
from maintenance.backup.progress import (
    IMPORT_PROGRESS_STEPS,
    _BackupProgressReporter,
    _emit_progress,
)
from maintenance.backup.rows import _load_table_rows
from maintenance.backup.selection import (
    _backup_tables,
)
from maintenance.operations.database.tables import (
    DEFERRED_COLUMNS,
    DEFERRED_UPDATE_ORDER,
)

LOGGER = logging.getLogger(__name__)


def import_backup(
    backup_path: str | os.PathLike[str],
    key: bytes | str,
    *,
    session_factory: sessionmaker = Session,
    db_engine: Engine = engine,
    storage_provider: StorageProvider | None = None,
    config_path: str | os.PathLike[str] = "config.toml",
    init_path: str | os.PathLike[str] = EXECUTABLE_ABSPATH / "init",
    progress: Progress | None = None,
    show_progress_details: bool = False,
) -> dict[str, Any]:
    key_bytes = decode_backup_key(key) if isinstance(key, str) else key
    if len(key_bytes) != 32:
        raise ValueError("Backup key must be exactly 32 bytes")

    storage = storage_provider or ProviderManager().storage
    progress_reporter = _BackupProgressReporter(progress, show_progress_details)
    LOGGER.debug("Starting backup import from %s", backup_path)
    _emit_progress(
        progress_reporter,
        phase="read_header",
        message="Reading backup header",
        current_step=1,
        total_steps=IMPORT_PROGRESS_STEPS,
        detail=str(backup_path),
    )
    header, header_bytes, ciphertext_offset = _read_header_bytes(backup_path)
    _validate_header(header)

    _emit_progress(
        progress_reporter,
        phase="prepare_target",
        message="Preparing target database",
        current_step=2,
        total_steps=IMPORT_PROGRESS_STEPS,
    )
    Base.metadata.create_all(db_engine)
    _ensure_target_is_empty(db_engine)

    written_paths: list[str] = []
    with tempfile.TemporaryDirectory(prefix="cfms-backup-import-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        compressed_payload = tmp_path / "payload.tar.xz"
        LOGGER.debug("Created backup import workspace: %s", tmp_path)
        _emit_progress(
            progress_reporter,
            phase="decrypt_payload",
            message="Decrypting backup payload",
            current_step=3,
            total_steps=IMPORT_PROGRESS_STEPS,
        )
        _decrypt_payload(
            backup_path,
            compressed_payload,
            key_bytes,
            header,
            header_bytes,
            ciphertext_offset,
        )

        extract_dir = tmp_path / "payload"
        extract_dir.mkdir()
        _emit_progress(
            progress_reporter,
            phase="extract_payload",
            message="Extracting backup payload",
            current_step=4,
            total_steps=IMPORT_PROGRESS_STEPS,
        )
        _safe_extract_tar_xz(compressed_payload, extract_dir)
        _emit_progress(
            progress_reporter,
            phase="validate_manifest",
            message="Validating backup manifest",
            current_step=5,
            total_steps=IMPORT_PROGRESS_STEPS,
        )
        manifest = _load_manifest(extract_dir / "manifest.json")
        _validate_manifest(manifest)

        try:
            _emit_progress(
                progress_reporter,
                phase="restore_files",
                message="Restoring storage files",
                current_step=6,
                total_steps=IMPORT_PROGRESS_STEPS,
            )
            written_paths = _restore_files(
                extract_dir,
                manifest,
                storage,
                progress_reporter=progress_reporter,
            )
            _emit_progress(
                progress_reporter,
                phase="restore_database",
                message="Restoring database rows",
                current_step=7,
                total_steps=IMPORT_PROGRESS_STEPS,
            )
            _restore_database(
                extract_dir,
                manifest,
                session_factory,
                progress_reporter=progress_reporter,
            )
            _emit_progress(
                progress_reporter,
                phase="restore_config",
                message=(
                    "Restoring configuration keys"
                    if _manifest_includes_configuration(manifest)
                    else "Skipping configuration keys"
                ),
                current_step=8,
                total_steps=IMPORT_PROGRESS_STEPS,
            )
            if _manifest_includes_configuration(manifest):
                _restore_config_keys(config_path, manifest)
            LOGGER.debug("Writing init marker to %s", init_path)
            Path(init_path).write_text(
                "This file indicates that the database has been initialized.\n",
                encoding="utf-8",
            )
        except Exception:
            LOGGER.debug(
                "Import failed; cleaning up %d restored file(s)",
                len(written_paths),
            )
            _cleanup_restored_files(storage, written_paths)
            raise

    _emit_progress(
        progress_reporter,
        phase="complete_import",
        message="Backup import completed",
        current_step=9,
        total_steps=IMPORT_PROGRESS_STEPS,
        detail=str(backup_path),
    )
    LOGGER.debug("Backup import completed: %s", backup_path)
    return {
        "created_at": header.created_at,
        "core_version": header.core_version,
        "tables": manifest["tables"],
        "files": manifest["files"],
    }


def _restore_files(
    extract_dir: Path,
    manifest: dict[str, Any],
    storage_provider: StorageProvider,
    *,
    progress_reporter: _BackupProgressReporter | None = None,
) -> list[str]:
    written_paths = []
    file_entries = manifest["files"]
    for file_index, entry in enumerate(file_entries, start=1):
        storage_path = str(entry["storage_path"])
        _validate_storage_path(storage_path)
        LOGGER.debug(
            "Restoring storage file %s (%d/%d)",
            storage_path,
            file_index,
            len(file_entries),
        )
        _emit_progress(
            progress_reporter,
            phase="restore_file",
            message="Restoring storage file",
            current_step=6,
            total_steps=IMPORT_PROGRESS_STEPS,
            detail=storage_path,
            completed_units=file_index,
            total_units=len(file_entries),
            verbose_only=True,
        )
        source_path = _safe_payload_path(extract_dir, str(entry["archive_path"]))
        if not source_path.is_file():
            raise BackupFormatError(
                f"Backup payload is missing {entry['archive_path']}"
            )
        _verify_file_digest(source_path, entry)

        if storage_provider.exists(storage_path):
            raise BackupRestoreError(
                f"Refusing to overwrite existing storage file: {storage_path}"
            )

        parent = os.path.dirname(storage_path)
        if parent:
            storage_provider.makedirs(parent, exist_ok=True)
        with (
            source_path.open("rb") as source,
            storage_provider.fopen(storage_path, "wb") as target,
        ):
            shutil.copyfileobj(source, target, length=1024 * 1024)
        written_paths.append(storage_path)
        LOGGER.debug("Restored storage file %s", storage_path)

    return written_paths


def _restore_database(
    extract_dir: Path,
    manifest: dict[str, Any],
    session_factory: sessionmaker,
    *,
    progress_reporter: _BackupProgressReporter | None = None,
) -> None:
    tables = _backup_tables()
    table_names = _manifest_table_names(manifest)
    legacy_access_rule_rows = _load_legacy_access_rule_rows(extract_dir, manifest)
    compiled_rule_set_id_by_node = _build_missing_compiled_rule_set_mapping(
        extract_dir, manifest
    )
    legacy_banned_subnet_reasons = _load_legacy_banned_subnet_reasons(
        extract_dir, manifest
    )
    legacy_node_namespace = _load_legacy_node_namespace(extract_dir, manifest)
    deferred_updates: dict[str, list[dict[str, Any]]] = {
        table_name: [] for table_name in DEFERRED_COLUMNS if table_name in table_names
    }

    with session_factory.begin() as session:
        connection = session.connection()
        restored_node_tables = _restore_node_tables(
            connection,
            extract_dir,
            manifest,
            tables,
            deferred_updates,
            legacy_node_namespace,
        )
        for table_index, table_name in enumerate(table_names, start=1):
            if table_name in restored_node_tables:
                continue
            LOGGER.debug(
                "Restoring table %s (%d/%d)",
                table_name,
                table_index,
                len(table_names),
            )
            _emit_progress(
                progress_reporter,
                phase="restore_table",
                message="Restoring table",
                current_step=7,
                total_steps=IMPORT_PROGRESS_STEPS,
                detail=table_name,
                completed_units=table_index,
                total_units=len(table_names),
                verbose_only=True,
            )
            table = tables[table_name]
            rows = _load_table_rows(extract_dir, manifest, table)
            if table_name == "banned_subnets" and legacy_banned_subnet_reasons:
                for row in rows:
                    reason = legacy_banned_subnet_reasons.get(row["subnet"])
                    if reason is not None:
                        row["reason_comment_id"] = CommentStore.get_or_create_id(
                            session, reason
                        )
            if table_name == "compiled_access_rules" and compiled_rule_set_id_by_node:
                _restore_missing_compiled_rule_sets(
                    connection,
                    tables,
                    compiled_rule_set_id_by_node,
                )
                legacy_node_ids = _load_compiled_rule_node_ids(extract_dir, manifest)
                for row, node_id in zip(rows, legacy_node_ids, strict=True):
                    if node_id in compiled_rule_set_id_by_node:
                        row["rule_set_id"] = compiled_rule_set_id_by_node[node_id]
                    elif row.get("rule_set_id") is None:
                        raise BackupFormatError(
                            "Compiled access rule row is missing a restorable "
                            "rule_set_id"
                        )
            deferred_columns = set(DEFERRED_COLUMNS.get(table_name, ()))
            insert_rows = []
            for row in rows:
                if deferred_columns:
                    deferred_updates[table_name].append(row.copy())
                    row = row.copy()
                    for column_name in deferred_columns:
                        row[column_name] = None
                insert_rows.append(row)
            if insert_rows:
                try:
                    connection.execute(insert(table), insert_rows)
                except IntegrityError as exc:
                    if table_name != "nodes" or not is_node_name_conflict(exc):
                        raise
                    raise BackupFormatError(
                        "Backup contains active sibling nodes with duplicate names"
                    ) from exc
            LOGGER.debug("Restored table %s with %d row(s)", table_name, len(rows))

        for table_name, pk_name, column_names in DEFERRED_UPDATE_ORDER:
            if table_name not in table_names:
                continue
            table = tables[table_name]
            for row in deferred_updates.get(table_name, []):
                values = {
                    column_name: row[column_name]
                    for column_name in column_names
                    if row.get(column_name) is not None
                }
                if values:
                    connection.execute(
                        update(table)
                        .where(table.c[pk_name] == row[pk_name])
                        .values(**values)
                    )
            LOGGER.debug("Applied deferred updates for table %s", table_name)

        if legacy_access_rule_rows and "compiled_access_rules" not in manifest.get(
            "tables", {}
        ):
            _restore_legacy_access_rules(session, legacy_access_rule_rows)
            LOGGER.debug("Converted legacy JSON access rules during database restore")


def _restore_config_keys(
    config_path: str | os.PathLike[str],
    manifest: dict[str, Any],
) -> None:
    configuration = manifest.get("configuration", {})
    security = configuration.get("security", {})
    server = configuration.get("server", {})
    path = Path(config_path)
    if not path.exists():
        raise BackupRestoreError(f"Configuration file not found: {path}")

    LOGGER.debug("Restoring configuration keys in %s", path)
    doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    if "security" not in doc:
        doc["security"] = tomlkit.table()
    if "server" not in doc:
        doc["server"] = tomlkit.table()

    doc["security"]["pepper"] = security.get("pepper", "")
    doc["server"]["secret_key"] = server.get("secret_key", "")
    path.write_text(tomlkit.dumps(doc), encoding="utf-8")
    LOGGER.debug("Configuration keys restored in %s", path)


def _ensure_target_is_empty(db_engine: Engine) -> None:
    with db_engine.connect() as connection:
        for table_name, table in _backup_tables().items():
            count = connection.execute(
                select(func.count()).select_from(table)
            ).scalar_one()
            LOGGER.debug("Target table %s contains %d row(s)", table_name, count)
            if count:
                raise BackupRestoreError(
                    f"Target database is not empty; table {table_name!r} has "
                    f"{count} row(s)"
                )
