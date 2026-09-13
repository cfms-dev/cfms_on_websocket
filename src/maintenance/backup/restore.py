import logging
import os
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import Any

import tomlkit
from rich.progress import Progress
from sqlalchemy import bindparam, func, insert, select
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
    _validate_payload_tree,
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
from maintenance.backup.rows import (
    _decode_row,
    _iter_raw_table_row_batches,
    _iter_raw_table_rows,
    _iter_table_row_batches,
)
from maintenance.backup.selection import (
    LEGACY_ACCESS_RULE_TABLE_NAMES,
    _backup_tables,
)
from maintenance.operations.config.sync import MAX_CONFIG_BYTES, read_config_text
from maintenance.operations.database.tables import (
    DEFERRED_COLUMNS,
    DEFERRED_UPDATE_ORDER,
)

LOGGER = logging.getLogger(__name__)
MAX_INIT_MARKER_BYTES = 64 * 1024


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
        _validate_payload_tree(extract_dir, manifest)

        config_file = Path(config_path)
        init_file = Path(init_path)
        config_snapshot = (
            _read_file_snapshot(config_file, maximum=MAX_CONFIG_BYTES)
            if _manifest_includes_configuration(manifest)
            else None
        )
        init_snapshot = _read_file_snapshot(
            init_file,
            maximum=MAX_INIT_MARKER_BYTES,
        )
        finalization_started = False

        def finalize_target_files() -> None:
            nonlocal finalization_started
            finalization_started = True
            if _manifest_includes_configuration(manifest):
                _restore_config_keys(config_file, manifest)
            LOGGER.debug("Writing init marker to %s", init_file)
            _write_file_atomically(
                init_file,
                b"This file indicates that the database has been initialized.\n",
            )

        try:
            _emit_progress(
                progress_reporter,
                phase="restore_files",
                message="Restoring storage files",
                current_step=6,
                total_steps=IMPORT_PROGRESS_STEPS,
            )
            _restore_files(
                extract_dir,
                manifest,
                storage,
                written_paths=written_paths,
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
                finalize=finalize_target_files,
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
        except Exception:
            LOGGER.debug(
                "Import failed; cleaning up %d restored file(s)",
                len(written_paths),
            )
            _cleanup_restored_files(storage, written_paths)
            if finalization_started:
                snapshots = []
                if config_snapshot is not None:
                    snapshots.append((config_file, config_snapshot))
                snapshots.append((init_file, init_snapshot))
                for path, snapshot in snapshots:
                    try:
                        _restore_file_snapshot(path, snapshot)
                    except OSError:
                        LOGGER.exception(
                            "Unable to roll back backup import target %s",
                            path,
                        )
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
    written_paths: list[str] | None = None,
    progress_reporter: _BackupProgressReporter | None = None,
) -> list[str]:
    if written_paths is None:
        written_paths = []
    file_entries = manifest["files"]
    _validate_file_manifest_table(extract_dir, manifest)
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
            detail_task=True,
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
            written_paths.append(storage_path)
            shutil.copyfileobj(source, target, length=1024 * 1024)
        LOGGER.debug("Restored storage file %s", storage_path)

    return written_paths


def _validate_file_manifest_table(
    extract_dir: Path,
    manifest: dict[str, Any],
) -> None:
    expected_paths = {
        entry["file_id"]: entry["storage_path"] for entry in manifest["files"]
    }
    if "files" not in manifest["tables"]:
        if not expected_paths:
            return
        raise BackupFormatError("Backup file manifest does not match the files table")
    unmatched_ids = set(expected_paths)
    missing_active_payload = False
    for row in _iter_raw_table_rows(extract_dir, manifest, "files"):
        file_id = row.get("id")
        if file_id not in expected_paths:
            if row.get("active") is not False:
                missing_active_payload = True
            continue
        if row.get("path") != expected_paths[file_id]:
            raise BackupFormatError(
                "Backup file manifest does not match the files table"
            )
        unmatched_ids.discard(file_id)
    if unmatched_ids:
        raise BackupFormatError("Backup file manifest does not match the files table")
    if missing_active_payload:
        raise BackupFormatError("Backup active files table row has no payload")


def _restore_database(
    extract_dir: Path,
    manifest: dict[str, Any],
    session_factory: sessionmaker,
    *,
    progress_reporter: _BackupProgressReporter | None = None,
    finalize: Callable[[], None] | None = None,
) -> None:
    tables = _backup_tables()
    table_names = _manifest_table_names(manifest)
    total_row_count = sum(
        table_manifest["rows"] for table_manifest in manifest["tables"].values()
    )
    restored_row_count = 0
    _emit_progress(
        progress_reporter,
        phase="restore_database_rows",
        message="Restoring database rows",
        current_step=7,
        total_steps=IMPORT_PROGRESS_STEPS,
        completed_units=restored_row_count,
        total_units=total_row_count,
        detail_task=True,
        details_only=False,
    )
    legacy_access_rule_tables = LEGACY_ACCESS_RULE_TABLE_NAMES & set(manifest["tables"])
    missing_compiled_rule_sets = (
        "compiled_access_rules" in manifest["tables"]
        and "compiled_access_rule_sets" not in manifest["tables"]
    )

    with session_factory.begin() as session:
        connection = session.connection()
        restored_node_tables = _restore_node_tables(
            connection,
            extract_dir,
            manifest,
            tables,
        )
        restored_row_count += sum(
            manifest["tables"][table_name]["rows"]
            for table_name in restored_node_tables
        )
        _emit_progress(
            progress_reporter,
            phase="restore_database_rows",
            message="Restoring database rows",
            current_step=7,
            total_steps=IMPORT_PROGRESS_STEPS,
            completed_units=restored_row_count,
            total_units=total_row_count,
            detail_task=True,
            details_only=False,
            refresh=False,
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
                detail_task=True,
            )
            table = tables[table_name]
            if table_name == "compiled_access_rules" and missing_compiled_rule_sets:
                row_batches = _iter_legacy_compiled_rule_batches(
                    connection,
                    extract_dir,
                    manifest,
                    tables,
                    table,
                )
            elif table_name == "banned_subnets":
                row_batches = _iter_banned_subnet_batches(
                    session,
                    extract_dir,
                    manifest,
                    table,
                )
            else:
                row_batches = _iter_table_row_batches(extract_dir, manifest, table)

            restored_table_row_count = 0
            deferred_columns = set(DEFERRED_COLUMNS.get(table_name, ()))
            for rows in row_batches:
                if deferred_columns:
                    insert_rows = []
                    for row in rows:
                        insert_row = row.copy()
                        for column_name in deferred_columns:
                            insert_row[column_name] = None
                        insert_rows.append(insert_row)
                else:
                    insert_rows = rows
                if insert_rows:
                    try:
                        connection.execute(insert(table), insert_rows)
                    except IntegrityError as exc:
                        if table_name != "nodes" or not is_node_name_conflict(exc):
                            raise
                        raise BackupFormatError(
                            "Backup contains active sibling nodes with duplicate names"
                        ) from exc
                restored_table_row_count += len(rows)
                restored_row_count += len(rows)
                _emit_progress(
                    progress_reporter,
                    phase="restore_database_rows",
                    message="Restoring database rows",
                    current_step=7,
                    total_steps=IMPORT_PROGRESS_STEPS,
                    detail=table_name,
                    completed_units=restored_row_count,
                    total_units=total_row_count,
                    detail_task=True,
                    details_only=False,
                    refresh=False,
                )
            LOGGER.debug(
                "Restored table %s with %d row(s)",
                table_name,
                restored_table_row_count,
            )

        _restore_deferred_updates(
            connection,
            extract_dir,
            manifest,
            tables,
            table_names,
        )

        if (
            legacy_access_rule_tables
            and "compiled_access_rules" not in manifest["tables"]
        ):
            _restore_legacy_access_rules(session, extract_dir, manifest)
            restored_row_count += sum(
                manifest["tables"][table_name]["rows"]
                for table_name in legacy_access_rule_tables
            )
            LOGGER.debug("Converted legacy JSON access rules during database restore")

        _emit_progress(
            progress_reporter,
            phase="restore_database_rows",
            message="Restoring database rows",
            current_step=7,
            total_steps=IMPORT_PROGRESS_STEPS,
            completed_units=restored_row_count,
            total_units=total_row_count,
            detail_task=True,
            details_only=False,
        )
        if finalize is not None:
            finalize()


def _iter_legacy_compiled_rule_batches(
    connection,
    extract_dir: Path,
    manifest: dict[str, Any],
    tables: dict[str, Any],
    table,
):
    for raw_rows in _iter_raw_table_row_batches(
        extract_dir,
        manifest,
        "compiled_access_rules",
    ):
        rows = [_decode_row(raw_row, table) for raw_row in raw_rows]
        node_ids = []
        for raw_row, row in zip(raw_rows, rows, strict=True):
            node_id = raw_row.get("node_id", raw_row.get("target_id"))
            if node_id is None:
                if row.get("rule_set_id") is None:
                    raise BackupFormatError(
                        "Compiled access rule row is missing a restorable rule_set_id"
                    )
                continue
            node_ids.append(str(node_id))
        rule_set_id_by_node = _restore_missing_compiled_rule_sets(
            connection,
            tables,
            node_ids,
        )
        for raw_row, row in zip(raw_rows, rows, strict=True):
            node_id = raw_row.get("node_id", raw_row.get("target_id"))
            if node_id is not None:
                row["rule_set_id"] = rule_set_id_by_node[str(node_id)]
        yield rows


def _iter_banned_subnet_batches(
    session,
    extract_dir: Path,
    manifest: dict[str, Any],
    table,
):
    for raw_rows in _iter_raw_table_row_batches(
        extract_dir,
        manifest,
        "banned_subnets",
    ):
        rows = []
        for raw_row in raw_rows:
            row = _decode_row(raw_row, table)
            if "reason" in raw_row and "reason_comment_id" not in raw_row:
                row["reason_comment_id"] = CommentStore.get_or_create_id(
                    session,
                    raw_row["reason"],
                )
            rows.append(row)
        yield rows


def _restore_deferred_updates(
    connection,
    extract_dir: Path,
    manifest: dict[str, Any],
    tables: dict[str, Any],
    table_names: tuple[str, ...],
) -> None:
    for table_name, pk_name, column_names in DEFERRED_UPDATE_ORDER:
        if table_name not in table_names:
            continue
        table = tables[table_name]
        update_statement = (
            table.update()
            .where(table.c[pk_name] == bindparam("restore_primary_key"))
            .values(
                {
                    column_name: bindparam(f"restore_value_{column_name}")
                    for column_name in column_names
                }
            )
        )
        for rows in _iter_table_row_batches(extract_dir, manifest, table):
            parameters = [
                {
                    "restore_primary_key": row[pk_name],
                    **{
                        f"restore_value_{column_name}": row[column_name]
                        for column_name in column_names
                    },
                }
                for row in rows
                if any(row.get(column_name) is not None for column_name in column_names)
            ]
            if parameters:
                connection.execute(update_statement, parameters)
        LOGGER.debug("Applied deferred updates for table %s", table_name)


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
    doc = tomlkit.parse(read_config_text(path))
    if "security" not in doc:
        doc["security"] = tomlkit.table()
    if "server" not in doc:
        doc["server"] = tomlkit.table()

    doc["security"]["pepper"] = security["pepper"]
    doc["server"]["secret_key"] = server["secret_key"]
    _write_file_atomically(path, tomlkit.dumps(doc).encode())
    LOGGER.debug("Configuration keys restored in %s", path)


def _read_file_snapshot(path: Path, *, maximum: int) -> tuple[bool, bytes]:
    try:
        with path.open("rb") as snapshot_file:
            contents = snapshot_file.read(maximum + 1)
    except FileNotFoundError:
        return False, b""
    if len(contents) > maximum:
        raise BackupRestoreError(
            f"Backup restore target exceeds the {maximum}-byte rollback limit: {path}"
        )
    return True, contents


def _restore_file_snapshot(path: Path, snapshot: tuple[bool, bytes]) -> None:
    existed, contents = snapshot
    if existed:
        _write_file_atomically(path, contents)
    else:
        path.unlink(missing_ok=True)


def _write_file_atomically(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    file_descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{path.name}.",
        suffix=".tmp",
        dir=path.parent,
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(file_descriptor, "wb") as temporary:
            temporary.write(contents)
            temporary.flush()
            os.fsync(temporary.fileno())
        if path.exists():
            shutil.copymode(path, temporary_path)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


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
