from __future__ import annotations

import base64
import contextlib
import datetime as dt
import enum
import hashlib
import json
import logging
import lzma
import os
import secrets
import shutil
import tarfile
import tempfile
import warnings
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any

import orjson
import tomlkit
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from sqlalchemy import DateTime, Table, func, insert, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from include.conf_loader import global_config
from include.constants import CORE_VERSION, ROOT_ABSPATH
from include.database.handler import Base, Session, engine
from include.database.models.blocking import UserBlockEntry, UserBlockSubEntry
from include.database.models.classic import (
    AuditEntry,
    ObjectAccessEntry,
    User,
    UserGroup,
    UserGroupPermission,
    UserMembership,
    UserPermission,
)
from include.database.models.entity import (
    Document,
    DocumentAccessRule,
    DocumentMetadata,
    DocumentMetadataTag,
    DocumentRevision,
    Folder,
    FolderAccessRule,
)
from include.database.models.file import File
from include.database.models.keyring import UserKey
from include.database.models.security import BannedSubnet
from include.providers.base import StorageProvider
from include.providers.manager import ProviderManager

_MODEL_IMPORTS = (
    UserBlockEntry,
    UserBlockSubEntry,
    AuditEntry,
    ObjectAccessEntry,
    User,
    UserGroup,
    UserGroupPermission,
    UserMembership,
    UserPermission,
    Document,
    DocumentAccessRule,
    DocumentMetadata,
    DocumentMetadataTag,
    DocumentRevision,
    Folder,
    FolderAccessRule,
    File,
    UserKey,
    BannedSubnet,
)

LOGGER = logging.getLogger(__name__)

BACKUP_MAGIC = b"CONF"
BACKUP_FORMAT_VERSION = 1
HEADER_LENGTH_BYTES = 4
GCM_NONCE_BYTES = 12
GCM_TAG_BYTES = 16
MAX_HEADER_BYTES = 64 * 1024
EXPORT_PROGRESS_STEPS = 6
IMPORT_PROGRESS_STEPS = 9

BACKUP_TABLE_NAMES = (
    "files",
    "users",
    "user_groups",
    "group_permissions",
    "user_memberships",
    "user_permissions",
    "keyrings",
    "folders",
    "folder_access_rules",
    "documents",
    "document_revisions",
    "document_access_rules",
    "document_metadata",
    "document_metadata_tags",
    "object_access_entries",
    "audit_entries",
    "userblock_entries",
    "userblock_sub_entries",
    "banned_subnets",
)

EXCLUDED_TABLE_NAMES = frozenset(
    {
        "file_tasks",
        "login_throttles",
        "traffic_throttles",
    }
)

INSERT_ORDER = (
    "files",
    "users",
    "user_groups",
    "group_permissions",
    "user_memberships",
    "user_permissions",
    "keyrings",
    "folders",
    "folder_access_rules",
    "documents",
    "document_revisions",
    "document_access_rules",
    "document_metadata",
    "document_metadata_tags",
    "object_access_entries",
    "audit_entries",
    "userblock_entries",
    "userblock_sub_entries",
    "banned_subnets",
)

DEFERRED_COLUMNS = {
    "users": ("preference_dek_id",),
    "folders": ("parent_id",),
    "documents": ("current_revision_id",),
    "document_revisions": ("parent_revision_id",),
}

DEFERRED_UPDATE_ORDER = (
    ("users", "username", ("preference_dek_id",)),
    ("folders", "id", ("parent_id",)),
    ("document_revisions", "id", ("parent_revision_id",)),
    ("documents", "id", ("current_revision_id",)),
)


class BackupError(RuntimeError):
    pass


class BackupFormatError(BackupError):
    pass


class BackupIntegrityError(BackupError):
    pass


class BackupRestoreError(BackupError):
    pass


class BackupWarning(UserWarning):
    pass


@dataclass(frozen=True)
class BackupProgressEvent:
    phase: str
    message: str
    current_step: int
    total_steps: int
    detail: str | None = None
    completed_units: int | None = None
    total_units: int | None = None
    verbose_only: bool = False


BackupProgressHandler = Callable[[BackupProgressEvent], None]
BackupWarningHandler = Callable[[str], None]


@dataclass(frozen=True)
class BackupHeader:
    format_version: int
    created_at: str
    core_version: str
    compression: str
    encryption: str
    nonce: str

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> "BackupHeader":
        try:
            return cls(
                format_version=int(data["format_version"]),
                created_at=str(data["created_at"]),
                core_version=str(data["core_version"]),
                compression=str(data["compression"]),
                encryption=str(data["encryption"]),
                nonce=str(data["nonce"]),
            )
        except (KeyError, TypeError, ValueError) as exc:
            raise BackupFormatError("Backup header is missing required fields") from exc

    def as_dict(self) -> dict[str, Any]:
        return {
            "format_version": self.format_version,
            "created_at": self.created_at,
            "core_version": self.core_version,
            "compression": self.compression,
            "encryption": self.encryption,
            "nonce": self.nonce,
        }


def export_backup(
    output_path: str | os.PathLike[str],
    *,
    key: bytes | None = None,
    key_output_path: str | os.PathLike[str] | None = None,
    session_factory: sessionmaker = Session,
    storage_provider: StorageProvider | None = None,
    config=global_config,
    warning_handler: BackupWarningHandler | None = None,
    progress_handler: BackupProgressHandler | None = None,
) -> str:
    storage = storage_provider or ProviderManager().storage
    key_bytes = key or secrets.token_bytes(32)
    if len(key_bytes) != 32:
        raise ValueError("Backup key must be exactly 32 bytes")

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    LOGGER.debug("Starting backup export to %s", output)
    _emit_progress(
        progress_handler,
        phase="prepare_export",
        message="Preparing backup export",
        current_step=1,
        total_steps=EXPORT_PROGRESS_STEPS,
        detail=str(output),
    )
    created_at = dt.datetime.now(dt.timezone.utc).isoformat()
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
            warning_handler=warning_handler,
            progress_handler=progress_handler,
        )
        _emit_progress(
            progress_handler,
            phase="write_manifest",
            message="Writing backup manifest",
            current_step=4,
            total_steps=EXPORT_PROGRESS_STEPS,
        )
        _write_json(staging_dir / "manifest.json", manifest)
        _emit_progress(
            progress_handler,
            phase="encrypt_archive",
            message="Compressing and encrypting backup payload",
            current_step=5,
            total_steps=EXPORT_PROGRESS_STEPS,
        )
        _write_encrypted_archive(output, staging_dir, header_bytes, key_bytes, nonce)

    encoded_key = encode_backup_key(key_bytes)
    if key_output_path is not None:
        LOGGER.debug("Writing backup key to %s", key_output_path)
        Path(key_output_path).write_text(f"{encoded_key}\n", encoding="utf-8")
    _emit_progress(
        progress_handler,
        phase="complete_export",
        message="Backup export completed",
        current_step=6,
        total_steps=EXPORT_PROGRESS_STEPS,
        detail=str(output),
    )
    LOGGER.debug("Backup export completed: %s", output)
    return encoded_key


def import_backup(
    backup_path: str | os.PathLike[str],
    key: bytes | str,
    *,
    session_factory: sessionmaker = Session,
    db_engine: Engine = engine,
    storage_provider: StorageProvider | None = None,
    config_path: str | os.PathLike[str] = "config.toml",
    init_path: str | os.PathLike[str] = ROOT_ABSPATH / "init",
    progress_handler: BackupProgressHandler | None = None,
) -> dict[str, Any]:
    key_bytes = decode_backup_key(key) if isinstance(key, str) else key
    if len(key_bytes) != 32:
        raise ValueError("Backup key must be exactly 32 bytes")

    storage = storage_provider or ProviderManager().storage
    LOGGER.debug("Starting backup import from %s", backup_path)
    _emit_progress(
        progress_handler,
        phase="read_header",
        message="Reading backup header",
        current_step=1,
        total_steps=IMPORT_PROGRESS_STEPS,
        detail=str(backup_path),
    )
    header, header_bytes, ciphertext_offset = _read_header_bytes(backup_path)
    _validate_header(header)

    _emit_progress(
        progress_handler,
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
            progress_handler,
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
            progress_handler,
            phase="extract_payload",
            message="Extracting backup payload",
            current_step=4,
            total_steps=IMPORT_PROGRESS_STEPS,
        )
        _safe_extract_tar_xz(compressed_payload, extract_dir)
        _emit_progress(
            progress_handler,
            phase="validate_manifest",
            message="Validating backup manifest",
            current_step=5,
            total_steps=IMPORT_PROGRESS_STEPS,
        )
        manifest = _load_manifest(extract_dir / "manifest.json")
        _validate_manifest(manifest)

        try:
            _emit_progress(
                progress_handler,
                phase="restore_files",
                message="Restoring storage files",
                current_step=6,
                total_steps=IMPORT_PROGRESS_STEPS,
            )
            written_paths = _restore_files(
                extract_dir,
                manifest,
                storage,
                progress_handler=progress_handler,
            )
            _emit_progress(
                progress_handler,
                phase="restore_database",
                message="Restoring database rows",
                current_step=7,
                total_steps=IMPORT_PROGRESS_STEPS,
            )
            _restore_database(
                extract_dir,
                manifest,
                session_factory,
                progress_handler=progress_handler,
            )
            _emit_progress(
                progress_handler,
                phase="restore_config",
                message="Restoring configuration keys",
                current_step=8,
                total_steps=IMPORT_PROGRESS_STEPS,
            )
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
        progress_handler,
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


def read_backup_header(
    backup_path: str | os.PathLike[str],
) -> BackupHeader:
    header, _header_bytes, _ciphertext_offset = _read_header_bytes(backup_path)
    _validate_header(header)
    return header


def encode_backup_key(key: bytes) -> str:
    if len(key) != 32:
        raise ValueError("Backup key must be exactly 32 bytes")
    return base64.urlsafe_b64encode(key).decode("ascii").rstrip("=")


def decode_backup_key(value: str) -> bytes:
    normalized = value.strip()
    if not normalized:
        raise ValueError("Backup key cannot be empty")
    padding = "=" * (-len(normalized) % 4)
    try:
        decoded = base64.urlsafe_b64decode(normalized + padding)
    except ValueError as exc:
        raise ValueError("Backup key is not valid base64url") from exc
    if len(decoded) != 32:
        raise ValueError("Backup key must decode to exactly 32 bytes")
    return decoded


def _stage_backup_payload(
    staging_dir: Path,
    *,
    session_factory: sessionmaker,
    storage_provider: StorageProvider,
    config,
    warning_handler: BackupWarningHandler | None = None,
    progress_handler: BackupProgressHandler | None = None,
) -> dict[str, Any]:
    tables_dir = staging_dir / "tables"
    files_dir = staging_dir / "files"
    tables_dir.mkdir()
    files_dir.mkdir()

    _emit_progress(
        progress_handler,
        phase="export_tables",
        message="Exporting database tables",
        current_step=2,
        total_steps=EXPORT_PROGRESS_STEPS,
    )
    table_manifest = _export_tables(
        tables_dir,
        session_factory,
        progress_handler=progress_handler,
    )
    _emit_progress(
        progress_handler,
        phase="export_files",
        message="Copying storage files",
        current_step=3,
        total_steps=EXPORT_PROGRESS_STEPS,
    )
    file_manifest = _export_files(
        files_dir,
        session_factory,
        storage_provider,
        warning_handler=warning_handler,
        progress_handler=progress_handler,
    )
    return {
        "format_version": BACKUP_FORMAT_VERSION,
        "core_version": str(CORE_VERSION),
        "exported_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "tables": table_manifest,
        "excluded_tables": sorted(EXCLUDED_TABLE_NAMES),
        "files": file_manifest,
        "configuration": {
            "security": {"pepper": _config_get(config, ("security", "pepper"), "")},
            "server": {"secret_key": _config_get(config, ("server", "secret_key"), "")},
        },
    }


def _export_tables(
    tables_dir: Path,
    session_factory: sessionmaker,
    *,
    progress_handler: BackupProgressHandler | None = None,
) -> dict[str, Any]:
    metadata_tables = _backup_tables()
    manifest: dict[str, Any] = {}

    with session_factory() as session:
        connection = session.connection()
        for table_index, table_name in enumerate(BACKUP_TABLE_NAMES, start=1):
            LOGGER.debug(
                "Exporting table %s (%d/%d)",
                table_name,
                table_index,
                len(BACKUP_TABLE_NAMES),
            )
            _emit_progress(
                progress_handler,
                phase="export_table",
                message="Exporting table",
                current_step=2,
                total_steps=EXPORT_PROGRESS_STEPS,
                detail=table_name,
                completed_units=table_index,
                total_units=len(BACKUP_TABLE_NAMES),
                verbose_only=True,
            )
            table = metadata_tables[table_name]
            columns = [column.name for column in table.columns]
            rows_path = tables_dir / f"{table_name}.jsonl"
            row_count = 0
            order_by = [column for column in table.primary_key.columns]
            statement = select(table)
            if order_by:
                statement = statement.order_by(*order_by)

            with rows_path.open("wb") as f:
                for row in connection.execute(statement).mappings():
                    encoded = {
                        str(column.name): _serialize_value(row[column.name])
                        for column in table.columns
                    }
                    f.write(orjson.dumps(encoded, option=orjson.OPT_SORT_KEYS))
                    f.write(b"\n")
                    row_count += 1

            manifest[table_name] = {"columns": columns, "rows": row_count}
            LOGGER.debug("Exported table %s with %d row(s)", table_name, row_count)

    return manifest


def _export_files(
    files_dir: Path,
    session_factory: sessionmaker,
    storage_provider: StorageProvider,
    *,
    warning_handler: BackupWarningHandler | None = None,
    progress_handler: BackupProgressHandler | None = None,
) -> list[dict[str, Any]]:
    file_rows: list[dict[str, Any]] = []
    files_table = _backup_tables()["files"]

    with session_factory() as session:
        connection = session.connection()
        statement = select(files_table).order_by(files_table.c.id)
        for row in connection.execute(statement).mappings():
            file_rows.append(dict(row))

    file_manifest = []
    LOGGER.debug("Found %d database file record(s) to inspect", len(file_rows))
    for file_index, row in enumerate(file_rows, start=1):
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
            len(file_rows),
        )
        _emit_progress(
            progress_handler,
            phase="export_file",
            message="Copying storage file",
            current_step=3,
            total_steps=EXPORT_PROGRESS_STEPS,
            detail=f"{file_id}: {storage_path}",
            completed_units=file_index,
            total_units=len(file_rows),
            verbose_only=True,
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
        with storage_provider.fopen(storage_path, "rb") as source:
            with staged_file.open("wb") as target:
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


def _write_encrypted_archive(
    output_path: Path,
    staging_dir: Path,
    header_bytes: bytes,
    key: bytes,
    nonce: bytes,
) -> None:
    prefix = _header_prefix(header_bytes)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(prefix)

    compressed_payload = staging_dir / "payload.tar.xz"
    temp_output = output_path.with_name(f".{output_path.name}.{os.getpid()}.tmp")
    LOGGER.debug("Writing encrypted archive via temporary file %s", temp_output)
    try:
        _write_compressed_payload(compressed_payload, staging_dir)
        with temp_output.open("wb") as raw_output:
            raw_output.write(prefix)
            with compressed_payload.open("rb") as source:
                while chunk := source.read(1024 * 1024):
                    raw_output.write(encryptor.update(chunk))
            raw_output.write(encryptor.finalize())
            raw_output.write(encryptor.tag)
        os.replace(temp_output, output_path)
        LOGGER.debug("Encrypted archive written to %s", output_path)
    except Exception:
        with contextlib.suppress(FileNotFoundError):
            temp_output.unlink()
        raise


def _write_compressed_payload(output_path: Path, staging_dir: Path) -> None:
    LOGGER.debug("Creating compressed payload at %s", output_path)
    with lzma.open(output_path, "wb", preset=6) as compressed:
        with tarfile.open(fileobj=compressed, mode="w|") as tar:
            _add_staged_file(tar, staging_dir / "manifest.json", "manifest.json")
            for table_name in BACKUP_TABLE_NAMES:
                _add_staged_file(
                    tar,
                    staging_dir / "tables" / f"{table_name}.jsonl",
                    f"tables/{table_name}.jsonl",
                )
            for staged_file in sorted((staging_dir / "files").iterdir()):
                _add_staged_file(tar, staged_file, f"files/{staged_file.name}")
    LOGGER.debug("Compressed payload created at %s", output_path)


def _decrypt_payload(
    backup_path: str | os.PathLike[str],
    output_path: Path,
    key: bytes,
    header: BackupHeader,
    header_bytes: bytes,
    ciphertext_offset: int,
) -> None:
    nonce = _decode_bytes(header.nonce)
    backup = Path(backup_path)
    size = backup.stat().st_size
    ciphertext_length = size - ciphertext_offset - GCM_TAG_BYTES
    if ciphertext_length < 0:
        raise BackupFormatError("Backup file is truncated")
    LOGGER.debug(
        "Decrypting backup payload: ciphertext_bytes=%d output=%s",
        ciphertext_length,
        output_path,
    )

    with backup.open("rb") as source:
        source.seek(size - GCM_TAG_BYTES)
        tag = source.read(GCM_TAG_BYTES)
        source.seek(ciphertext_offset)

        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag))
        decryptor = cipher.decryptor()
        decryptor.authenticate_additional_data(_header_prefix(header_bytes))

        remaining = ciphertext_length
        try:
            with output_path.open("wb") as target:
                while remaining:
                    chunk = source.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise BackupFormatError("Backup file ended unexpectedly")
                    remaining -= len(chunk)
                    target.write(decryptor.update(chunk))
                target.write(decryptor.finalize())
        except InvalidTag as exc:
            with contextlib.suppress(FileNotFoundError):
                output_path.unlink()
            raise BackupIntegrityError(
                "Backup decryption failed; the key may be wrong or the file was "
                "modified"
            ) from exc
    LOGGER.debug("Decrypted payload written to %s", output_path)


def _restore_files(
    extract_dir: Path,
    manifest: dict[str, Any],
    storage_provider: StorageProvider,
    *,
    progress_handler: BackupProgressHandler | None = None,
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
            progress_handler,
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
        with source_path.open("rb") as source:
            with storage_provider.fopen(storage_path, "wb") as target:
                shutil.copyfileobj(source, target, length=1024 * 1024)
        written_paths.append(storage_path)
        LOGGER.debug("Restored storage file %s", storage_path)

    return written_paths


def _restore_database(
    extract_dir: Path,
    manifest: dict[str, Any],
    session_factory: sessionmaker,
    *,
    progress_handler: BackupProgressHandler | None = None,
) -> None:
    tables = _backup_tables()
    deferred_updates: dict[str, list[dict[str, Any]]] = {
        table_name: [] for table_name in DEFERRED_COLUMNS
    }

    with session_factory.begin() as session:
        connection = session.connection()
        for table_index, table_name in enumerate(INSERT_ORDER, start=1):
            LOGGER.debug(
                "Restoring table %s (%d/%d)",
                table_name,
                table_index,
                len(INSERT_ORDER),
            )
            _emit_progress(
                progress_handler,
                phase="restore_table",
                message="Restoring table",
                current_step=7,
                total_steps=IMPORT_PROGRESS_STEPS,
                detail=table_name,
                completed_units=table_index,
                total_units=len(INSERT_ORDER),
                verbose_only=True,
            )
            table = tables[table_name]
            rows = _load_table_rows(extract_dir, manifest, table)
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
                connection.execute(insert(table), insert_rows)
            LOGGER.debug("Restored table %s with %d row(s)", table_name, len(rows))

        for table_name, pk_name, column_names in DEFERRED_UPDATE_ORDER:
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


def _load_table_rows(
    extract_dir: Path,
    manifest: dict[str, Any],
    table: Table,
) -> list[dict[str, Any]]:
    table_name = table.name
    table_manifest = manifest["tables"][table_name]
    path = _safe_payload_path(extract_dir, f"tables/{table_name}.jsonl")
    rows = []
    with path.open("rb") as f:
        for line_number, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                row = orjson.loads(line)
            except orjson.JSONDecodeError as exc:
                raise BackupFormatError(
                    f"Invalid JSON row in {path} at line {line_number}"
                ) from exc
            rows.append(_decode_row(row, table))
    if len(rows) != table_manifest["rows"]:
        raise BackupFormatError(
            f"Row count mismatch for table {table_name!r}: "
            f"manifest says {table_manifest['rows']}, payload has {len(rows)}"
        )
    LOGGER.debug("Loaded %d row(s) for table %s", len(rows), table_name)
    return rows


def _decode_row(row: dict[str, Any], table: Table) -> dict[str, Any]:
    decoded = {}
    for column in table.columns:
        if column.name not in row:
            decoded[column.name] = None
            continue
        value = row[column.name]
        if value is not None and isinstance(column.type, DateTime):
            value = dt.datetime.fromisoformat(value)
        decoded[column.name] = value
    return decoded


def _validate_manifest(manifest: dict[str, Any]) -> None:
    LOGGER.debug("Validating backup manifest")
    if manifest.get("format_version") != BACKUP_FORMAT_VERSION:
        raise BackupFormatError(
            f"Unsupported payload format version: {manifest.get('format_version')}"
        )
    table_names = set(manifest.get("tables", {}).keys())
    expected = set(BACKUP_TABLE_NAMES)
    if table_names != expected:
        raise BackupFormatError(
            "Backup table set does not match this server version: "
            f"expected {sorted(expected)}, got {sorted(table_names)}"
        )
    for excluded in EXCLUDED_TABLE_NAMES:
        if excluded in table_names:
            raise BackupFormatError(f"Excluded table {excluded!r} is present")
    for entry in manifest.get("files", []):
        _validate_storage_path(str(entry.get("storage_path", "")))
    LOGGER.debug(
        "Backup manifest validated: tables=%d files=%d",
        len(table_names),
        len(manifest.get("files", [])),
    )


def _load_manifest(path: Path) -> dict[str, Any]:
    LOGGER.debug("Loading backup manifest from %s", path)
    try:
        manifest = orjson.loads(path.read_bytes())
    except (FileNotFoundError, orjson.JSONDecodeError) as exc:
        raise BackupFormatError("Backup manifest is missing or invalid") from exc
    if not isinstance(manifest, dict):
        raise BackupFormatError("Backup manifest must be a JSON object")
    return manifest


def _safe_extract_tar_xz(source_path: Path, target_dir: Path) -> None:
    LOGGER.debug("Extracting compressed payload %s to %s", source_path, target_dir)
    with lzma.open(source_path, "rb") as compressed:
        with tarfile.open(fileobj=compressed, mode="r|") as tar:
            for member in tar:
                LOGGER.debug("Extracting archive member %s", member.name)
                target_path = _safe_payload_path(target_dir, member.name)
                if member.isdir():
                    target_path.mkdir(parents=True, exist_ok=True)
                    continue
                if not member.isfile():
                    raise BackupFormatError(
                        f"Unsupported archive member type: {member.name}"
                    )
                target_path.parent.mkdir(parents=True, exist_ok=True)
                extracted = tar.extractfile(member)
                if extracted is None:
                    raise BackupFormatError(
                        f"Unable to read archive member: {member.name}"
                    )
                with extracted:
                    with target_path.open("wb") as target:
                        shutil.copyfileobj(extracted, target, length=1024 * 1024)
    LOGGER.debug("Compressed payload extracted to %s", target_dir)


def _safe_payload_path(root: Path, archive_path: str) -> Path:
    pure_path = PurePosixPath(archive_path)
    if pure_path.is_absolute() or any(
        part in ("", ".", "..") for part in pure_path.parts
    ):
        raise BackupFormatError(f"Unsafe archive path: {archive_path}")
    target = root.joinpath(*pure_path.parts)
    resolved_root = root.resolve()
    resolved_target = target.resolve(strict=False)
    if not resolved_target.is_relative_to(resolved_root):
        raise BackupFormatError(f"Unsafe archive path: {archive_path}")
    return target


def _validate_storage_path(path: str) -> None:
    if not path or os.path.isabs(path):
        raise BackupFormatError(f"Unsafe storage path in backup: {path!r}")
    parts = Path(path).parts
    if any(part in ("..", "") for part in parts):
        raise BackupFormatError(f"Unsafe storage path in backup: {path!r}")


def _verify_file_digest(path: Path, entry: dict[str, Any]) -> None:
    expected_size = int(entry["size"])
    expected_sha256 = str(entry["sha256"])
    sha256 = hashlib.sha256()
    size = 0
    with path.open("rb") as f:
        while chunk := f.read(1024 * 1024):
            sha256.update(chunk)
            size += len(chunk)
    if size != expected_size or sha256.hexdigest() != expected_sha256:
        raise BackupIntegrityError(
            f"File payload failed verification for {entry['storage_path']}"
        )
    LOGGER.debug("Verified file payload for %s", entry["storage_path"])


def _cleanup_restored_files(
    storage_provider: StorageProvider,
    paths: Iterable[str],
) -> None:
    for path in reversed(list(paths)):
        with contextlib.suppress(Exception):
            LOGGER.debug("Removing restored file after failed import: %s", path)
            storage_provider.remove(path)


def _read_header_bytes(
    backup_path: str | os.PathLike[str],
) -> tuple[BackupHeader, bytes, int]:
    LOGGER.debug("Reading backup header from %s", backup_path)
    with Path(backup_path).open("rb") as f:
        magic = f.read(len(BACKUP_MAGIC))
        if magic != BACKUP_MAGIC:
            raise BackupFormatError("File is not a CFMS backup")
        raw_length = f.read(HEADER_LENGTH_BYTES)
        if len(raw_length) != HEADER_LENGTH_BYTES:
            raise BackupFormatError("Backup header length is missing")
        header_length = int.from_bytes(raw_length, "big")
        if header_length <= 0 or header_length > MAX_HEADER_BYTES:
            raise BackupFormatError("Backup header length is invalid")
        header_bytes = f.read(header_length)
        if len(header_bytes) != header_length:
            raise BackupFormatError("Backup header is truncated")
        try:
            data = orjson.loads(header_bytes)
        except orjson.JSONDecodeError as exc:
            raise BackupFormatError("Backup header is not valid JSON") from exc
    return (
        BackupHeader.from_mapping(data),
        header_bytes,
        len(BACKUP_MAGIC) + HEADER_LENGTH_BYTES + header_length,
    )


def _validate_header(header: BackupHeader) -> None:
    if header.format_version != BACKUP_FORMAT_VERSION:
        raise BackupFormatError(
            f"Unsupported backup format version: {header.format_version}"
        )
    if header.compression != "xz":
        raise BackupFormatError(f"Unsupported compression: {header.compression}")
    if header.encryption != "AES-256-GCM":
        raise BackupFormatError(f"Unsupported encryption: {header.encryption}")
    if len(_decode_bytes(header.nonce)) != GCM_NONCE_BYTES:
        raise BackupFormatError("Backup header nonce length is invalid")


def _encode_header(header: BackupHeader) -> bytes:
    return orjson.dumps(header.as_dict(), option=orjson.OPT_SORT_KEYS)


def _header_prefix(header_bytes: bytes) -> bytes:
    return (
        BACKUP_MAGIC
        + len(header_bytes).to_bytes(HEADER_LENGTH_BYTES, "big")
        + header_bytes
    )


def _add_staged_file(
    tar: tarfile.TarFile, source_path: Path, archive_path: str
) -> None:
    stat_result = source_path.stat()
    info = tarfile.TarInfo(archive_path)
    info.size = stat_result.st_size
    info.mtime = int(stat_result.st_mtime)
    with source_path.open("rb") as f:
        tar.addfile(info, f)


def _write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_bytes(
        orjson.dumps(data, option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS)
    )


def _serialize_value(value: Any) -> Any:
    if isinstance(value, dt.datetime):
        return value.isoformat()
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, dict):
        return {str(key): _serialize_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_serialize_value(item) for item in value]
    if isinstance(value, tuple):
        return [_serialize_value(item) for item in value]
    return value


def _encode_bytes(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def _decode_bytes(value: str) -> bytes:
    padding = "=" * (-len(value) % 4)
    return base64.urlsafe_b64decode(value + padding)


def _backup_tables() -> dict[str, Table]:
    missing = [name for name in BACKUP_TABLE_NAMES if name not in Base.metadata.tables]
    if missing:
        raise BackupFormatError(f"Backup table metadata is missing: {missing}")
    return {name: Base.metadata.tables[name] for name in BACKUP_TABLE_NAMES}


def _emit_progress(
    progress_handler: BackupProgressHandler | None,
    *,
    phase: str,
    message: str,
    current_step: int,
    total_steps: int,
    detail: str | None = None,
    completed_units: int | None = None,
    total_units: int | None = None,
    verbose_only: bool = False,
) -> None:
    if progress_handler is None:
        return
    progress_handler(
        BackupProgressEvent(
            phase=phase,
            message=message,
            current_step=current_step,
            total_steps=total_steps,
            detail=detail,
            completed_units=completed_units,
            total_units=total_units,
            verbose_only=verbose_only,
        )
    )


def _config_get(config, keys: tuple[str, ...], default: Any = None) -> Any:
    value = config
    for key in keys:
        try:
            value = value[key]
        except (KeyError, TypeError):
            return default
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return json.loads(json.dumps(value))
