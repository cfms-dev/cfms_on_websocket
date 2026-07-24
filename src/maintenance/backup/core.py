import base64
import binascii
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
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

import orjson
import tomlkit
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from rich.progress import Progress, TaskID
from sqlalchemy import DateTime, Table, exists, func, insert, or_, select, update
from sqlalchemy.engine import Engine
from sqlalchemy.orm import sessionmaker

from include.config.constants import CORE_VERSION, ROOT_ABSPATH
from include.config.settings import global_config
from include.database.models.access import (
    CompiledAccessRule,
    CompiledAccessRuleGroup,
    CompiledAccessRuleMembership,
    CompiledAccessRuleRight,
    CompiledAccessRuleSet,
    ObjectAccessEntry,
    UserBlockEntry,
    UserBlockSubEntry,
)
from include.database.models.documents import (
    Document,
    DocumentMetadata,
    DocumentMetadataTag,
    DocumentRevision,
    Folder,
    Node,
)
from include.database.models.files import File
from include.database.models.identity import (
    User,
    UserGroup,
    UserGroupPermission,
    UserMembership,
    UserPermission,
)
from include.database.models.keyrings import UserKey
from include.database.models.operations import AuditEntry
from include.database.models.security import BannedSubnet
from include.database.session import Base, Session, engine
from include.domains.access.authorization.compiled_rules import (
    compile_access_rule,
)
from include.domains.operations.comments import CommentStore
from include.providers.base import StorageProvider
from include.providers.manager import ProviderManager

_MODEL_IMPORTS = (
    UserBlockEntry,
    UserBlockSubEntry,
    AuditEntry,
    ObjectAccessEntry,
    CompiledAccessRule,
    CompiledAccessRuleGroup,
    CompiledAccessRuleMembership,
    CompiledAccessRuleRight,
    CompiledAccessRuleSet,
    User,
    UserGroup,
    UserGroupPermission,
    UserMembership,
    UserPermission,
    Document,
    DocumentMetadata,
    DocumentMetadataTag,
    DocumentRevision,
    Folder,
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
HUMAN_KEY_ALPHABET = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"
HUMAN_KEY_DATA_LENGTH = 52
HUMAN_KEY_GROUP_SIZE = 4
HUMAN_KEY_MAX_VALUE = 1 << 256
HUMAN_KEY_SEPARATOR = "-"

BACKUP_TABLE_NAMES = (
    "files",
    "comments",
    "users",
    "user_groups",
    "group_permissions",
    "user_memberships",
    "user_permissions",
    "keyrings",
    "nodes",
    "folders",
    "documents",
    "document_revisions",
    "document_metadata",
    "document_metadata_tags",
    "object_access_entries",
    "compiled_access_rule_sets",
    "compiled_access_rules",
    "compiled_access_rule_groups",
    "compiled_access_rule_memberships",
    "compiled_access_rule_rights",
    "audit_entries",
    "userblock_entries",
    "userblock_sub_entries",
    "banned_subnets",
)

EXCLUDED_TABLE_NAMES = frozenset(
    {
        "account_throttles",
        "file_tasks",
        "login_throttles",
        "traffic_throttles",
    }
)

INSERT_ORDER = (
    "files",
    "comments",
    "users",
    "user_groups",
    "group_permissions",
    "user_memberships",
    "user_permissions",
    "keyrings",
    "nodes",
    "folders",
    "documents",
    "document_revisions",
    "document_metadata",
    "document_metadata_tags",
    "object_access_entries",
    "compiled_access_rule_sets",
    "compiled_access_rules",
    "compiled_access_rule_groups",
    "compiled_access_rule_memberships",
    "compiled_access_rule_rights",
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
    "nodes": ("access_rule_set_id",),
}

DEFERRED_UPDATE_ORDER = (
    ("users", "username", ("preference_dek_id",)),
    ("folders", "id", ("parent_id",)),
    ("document_revisions", "id", ("parent_revision_id",)),
    ("documents", "id", ("current_revision_id",)),
    ("nodes", "id", ("access_rule_set_id",)),
)


class BackupComponent(enum.StrEnum):
    ACCOUNTS = "accounts"
    DOCUMENT_LIBRARY = "documents"
    AUDIT_LOG = "audit"
    BANNED_SUBNETS = "banned_subnets"
    CONFIGURATION = "configuration"


BACKUP_COMPONENT_TABLES: dict[BackupComponent, tuple[str, ...]] = {
    BackupComponent.ACCOUNTS: (
        "comments",
        "users",
        "user_groups",
        "group_permissions",
        "user_memberships",
        "user_permissions",
        "keyrings",
        "userblock_entries",
        "userblock_sub_entries",
    ),
    BackupComponent.DOCUMENT_LIBRARY: (
        "nodes",
        "folders",
        "documents",
        "document_revisions",
        "document_metadata",
        "document_metadata_tags",
        "object_access_entries",
        "compiled_access_rule_sets",
        "compiled_access_rules",
        "compiled_access_rule_groups",
        "compiled_access_rule_memberships",
        "compiled_access_rule_rights",
    ),
    BackupComponent.AUDIT_LOG: ("audit_entries",),
    BackupComponent.BANNED_SUBNETS: ("comments", "banned_subnets"),
    BackupComponent.CONFIGURATION: (),
}
BACKUP_COMPONENT_DEPENDENCIES: dict[BackupComponent, tuple[BackupComponent, ...]] = {
    BackupComponent.DOCUMENT_LIBRARY: (BackupComponent.ACCOUNTS,),
    BackupComponent.AUDIT_LOG: (BackupComponent.ACCOUNTS,),
}
DOCUMENT_ACCESS_TARGET_TYPES = frozenset({"document", "directory"})
COMPILED_ACCESS_RULE_TABLE_NAMES = frozenset(
    {
        "compiled_access_rules",
        "compiled_access_rule_sets",
        "compiled_access_rule_groups",
        "compiled_access_rule_memberships",
        "compiled_access_rule_rights",
    }
)
# These table names are accepted only when restoring backups produced before
# compiled access rules became authoritative. They are not part of the current
# schema or export format.
LEGACY_ACCESS_RULE_TABLE_NAMES = frozenset(
    {
        "document_access_rules",
        "folder_access_rules",
    }
)


@dataclass(frozen=True)
class BackupExportSelection:
    components: frozenset[BackupComponent]

    def __post_init__(self) -> None:
        normalized = frozenset(
            _coerce_backup_component(item) for item in self.components
        )
        if not normalized:
            raise ValueError("Choose at least one backup component")
        object.__setattr__(self, "components", normalized)

    @classmethod
    def from_component_values(
        cls,
        values: Iterable[BackupComponent | str],
    ) -> BackupExportSelection:
        return cls(frozenset(_coerce_backup_component(value) for value in values))

    @classmethod
    def full(cls) -> BackupExportSelection:
        return cls(frozenset(BackupComponent))

    def resolved_components(self) -> frozenset[BackupComponent]:
        return _resolve_component_dependencies(self.components)


@dataclass(frozen=True)
class _TableExportResult:
    manifest: dict[str, Any]
    file_ids: frozenset[str] | None


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


BackupWarningHandler = Callable[[str], None]


@dataclass
class _BackupProgressReporter:
    progress: Progress | None
    show_details: bool = False
    overall_task_id: TaskID | None = None
    detail_task_ids: dict[str, TaskID] = field(default_factory=dict)

    def update_overall(
        self,
        *,
        message: str,
        current_step: int,
        total_steps: int,
        detail: str | None = None,
    ) -> None:
        if self.progress is None:
            return

        description = _format_progress_description(message, detail)
        if self.overall_task_id is None:
            self.overall_task_id = self.progress.add_task(
                description,
                total=total_steps,
                completed=0,
            )
        self.progress.update(
            self.overall_task_id,
            total=total_steps,
            completed=current_step,
            description=description,
            refresh=True,
        )

    def update_detail(
        self,
        *,
        phase: str,
        message: str,
        detail: str | None = None,
        completed_units: int | None = None,
        total_units: int | None = None,
    ) -> None:
        if self.progress is None or not self.show_details:
            return

        description = _format_progress_description(message, detail)
        task_id = self.detail_task_ids.get(phase)
        if task_id is None:
            task_id = self.progress.add_task(
                description,
                total=total_units,
                completed=0,
            )
            self.detail_task_ids[phase] = task_id

        self.progress.update(
            task_id,
            total=total_units,
            completed=completed_units,
            description=description,
            refresh=True,
        )


@dataclass(frozen=True)
class BackupHeader:
    format_version: int
    created_at: str
    core_version: str
    compression: str
    encryption: str
    nonce: str

    @classmethod
    def from_mapping(cls, data: dict[str, Any]) -> BackupHeader:
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
    key_bytes = key or secrets.token_bytes(32)
    if len(key_bytes) != 32:
        raise ValueError("Backup key must be exactly 32 bytes")

    output = Path(output_path)
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
    if key_output_path is not None:
        LOGGER.debug("Writing backup key to %s", key_output_path)
        Path(key_output_path).write_text(f"{encoded_key}\n", encoding="utf-8")
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


def import_backup(
    backup_path: str | os.PathLike[str],
    key: bytes | str,
    *,
    session_factory: sessionmaker = Session,
    db_engine: Engine = engine,
    storage_provider: StorageProvider | None = None,
    config_path: str | os.PathLike[str] = "config.toml",
    init_path: str | os.PathLike[str] = ROOT_ABSPATH / "init",
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


def read_backup_header(
    backup_path: str | os.PathLike[str],
) -> BackupHeader:
    header, _header_bytes, _ciphertext_offset = _read_header_bytes(backup_path)
    _validate_header(header)
    return header


def encode_backup_key(key: bytes) -> str:
    if len(key) != 32:
        raise ValueError("Backup key must be exactly 32 bytes")
    value = int.from_bytes(key, "big")
    chars = []
    for _ in range(HUMAN_KEY_DATA_LENGTH):
        value, index = divmod(value, len(HUMAN_KEY_ALPHABET))
        chars.append(HUMAN_KEY_ALPHABET[index])
    if value:
        raise ValueError("Backup key is too large for the human-readable format")

    encoded = "".join(reversed(chars))
    groups = [
        encoded[index : index + HUMAN_KEY_GROUP_SIZE]
        for index in range(0, len(encoded), HUMAN_KEY_GROUP_SIZE)
    ]
    return HUMAN_KEY_SEPARATOR.join(groups)


def decode_backup_key(value: str) -> bytes:
    normalized = value.strip()
    if not normalized:
        raise ValueError("Backup key cannot be empty")
    padding = "=" * (-len(normalized) % 4)
    try:
        decoded = base64.urlsafe_b64decode(normalized + padding)
        if len(decoded) == 32:
            return decoded
    except (binascii.Error, ValueError) as exc:
        if _looks_like_human_backup_key(normalized):
            return _decode_human_backup_key(normalized)
        raise ValueError("Backup key is not valid base64url") from exc
    if _looks_like_human_backup_key(normalized):
        return _decode_human_backup_key(normalized)
    raise ValueError("Backup key must decode to exactly 32 bytes")


def _decode_human_backup_key(value: str) -> bytes:
    data = _normalize_human_backup_key(value)
    if len(data) != HUMAN_KEY_DATA_LENGTH:
        raise ValueError(
            f"Human-readable backup key must contain {HUMAN_KEY_DATA_LENGTH} "
            "data characters"
        )

    number = 0
    alphabet_index = {
        character: index for index, character in enumerate(HUMAN_KEY_ALPHABET)
    }
    for character in data:
        try:
            digit = alphabet_index[character]
        except KeyError as exc:
            raise ValueError(
                f"Human-readable backup key contains invalid character {character!r}"
            ) from exc
        number = number * len(HUMAN_KEY_ALPHABET) + digit

    if number >= HUMAN_KEY_MAX_VALUE:
        raise ValueError("Human-readable backup key value is out of range")
    return number.to_bytes(32, "big")


def _looks_like_human_backup_key(value: str) -> bool:
    data = _normalize_human_backup_key(value)
    return len(data) == HUMAN_KEY_DATA_LENGTH or HUMAN_KEY_SEPARATOR in value


def _normalize_human_backup_key(value: str) -> str:
    return value.replace(HUMAN_KEY_SEPARATOR, "").replace(" ", "")


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
        files_dir,
        session_factory,
        storage_provider,
        file_ids=table_export.file_ids,
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
        file_ids = None
        active_compiled_rule_set_ids = _collect_active_compiled_rule_set_ids(
            connection,
            metadata_tables,
        )
        table_names = BACKUP_TABLE_NAMES
        if not full_export:
            file_ids = _collect_selected_file_ids(
                connection,
                metadata_tables,
                components,
            )
            table_names = _selected_table_names(
                components,
                include_files=bool(file_ids),
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
            if not full_export:
                statement = _apply_export_table_filter(
                    statement,
                    table,
                    table_name,
                    metadata_tables,
                    components,
                    file_ids or frozenset(),
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
                    for column in table.columns:
                        value = row[column.name]
                        if (
                            table_name == "nodes"
                            and column.name == "access_rule_set_id"
                            and value not in active_compiled_rule_set_ids
                        ):
                            value = None
                        encoded[str(column.name)] = _serialize_table_value(
                            table_name,
                            column.name,
                            value,
                        )
                    f.write(orjson.dumps(encoded, option=orjson.OPT_SORT_KEYS))
                    f.write(b"\n")
                    row_count += 1

            manifest[table_name] = {"columns": columns, "rows": row_count}
            LOGGER.debug("Exported table %s with %d row(s)", table_name, row_count)

    return _TableExportResult(
        manifest=manifest,
        file_ids=file_ids,
    )


def _export_files(
    files_dir: Path,
    session_factory: sessionmaker,
    storage_provider: StorageProvider,
    *,
    file_ids: frozenset[str] | None = None,
    warning_handler: BackupWarningHandler | None = None,
    progress_reporter: _BackupProgressReporter | None = None,
) -> list[dict[str, Any]]:
    file_rows: list[dict[str, Any]] = []
    files_table = _backup_tables()["files"]

    with session_factory() as session:
        connection = session.connection()
        statement = select(files_table).order_by(files_table.c.id)
        if file_ids is not None:
            if not file_ids:
                statement = statement.where(files_table.c.id.in_([]))
            else:
                statement = statement.where(files_table.c.id.in_(sorted(file_ids)))
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
            progress_reporter,
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


def _coerce_backup_component(value: BackupComponent | str) -> BackupComponent:
    if isinstance(value, BackupComponent):
        return value
    try:
        return BackupComponent(value)
    except ValueError as exc:
        allowed = ", ".join(component.value for component in BackupComponent)
        raise ValueError(
            f"Unknown backup component {value!r}; choose from {allowed}"
        ) from exc


def _selection_components(
    selection: BackupExportSelection | None,
) -> frozenset[BackupComponent]:
    if selection is None:
        return frozenset(BackupComponent)
    return selection.resolved_components()


def _resolve_component_dependencies(
    components: Iterable[BackupComponent],
) -> frozenset[BackupComponent]:
    resolved = set(components)
    changed = True
    while changed:
        changed = False
        for component in tuple(resolved):
            for dependency in BACKUP_COMPONENT_DEPENDENCIES.get(component, ()):
                if dependency not in resolved:
                    resolved.add(dependency)
                    changed = True
    return frozenset(resolved)


def _selected_table_names(
    components: frozenset[BackupComponent],
    *,
    include_files: bool,
) -> tuple[str, ...]:
    selected = set()
    for component in components:
        selected.update(BACKUP_COMPONENT_TABLES[component])
    if include_files:
        selected.add("files")
    return tuple(
        table_name for table_name in BACKUP_TABLE_NAMES if table_name in selected
    )


def _collect_selected_file_ids(
    connection,
    tables: dict[str, Table],
    components: frozenset[BackupComponent],
) -> frozenset[str]:
    file_ids: set[str] = set()
    if BackupComponent.ACCOUNTS in components:
        users = tables["users"]
        statement = select(users.c.avatar_id).where(users.c.avatar_id.is_not(None))
        for row in connection.execute(statement):
            file_ids.add(str(row[0]))

    if BackupComponent.DOCUMENT_LIBRARY in components:
        revisions = tables["document_revisions"]
        statement = select(revisions.c.file_id).where(revisions.c.file_id.is_not(None))
        for row in connection.execute(statement):
            file_ids.add(str(row[0]))

    return frozenset(file_ids)


def _collect_active_compiled_rule_set_ids(
    connection,
    tables: dict[str, Table],
) -> frozenset[str]:
    nodes = tables["nodes"]
    rule_sets = tables["compiled_access_rule_sets"]
    rules = tables["compiled_access_rules"]
    statement = (
        select(rule_sets.c.id)
        .join(nodes, nodes.c.access_rule_set_id == rule_sets.c.id)
        .where(
            rule_sets.c.node_id == nodes.c.id,
            exists(select(1).where(rules.c.rule_set_id == rule_sets.c.id)),
        )
        .order_by(rule_sets.c.id)
    )
    return frozenset(str(row[0]) for row in connection.execute(statement))


def _apply_export_table_filter(
    statement,
    table: Table,
    table_name: str,
    tables: dict[str, Table],
    components: frozenset[BackupComponent],
    file_ids: frozenset[str],
):
    if table_name == "files":
        return statement.where(table.c.id.in_(sorted(file_ids)))
    if (
        table_name == "object_access_entries"
        and BackupComponent.DOCUMENT_LIBRARY in components
    ):
        return statement.where(
            table.c.target_type.in_(sorted(DOCUMENT_ACCESS_TARGET_TYPES))
        )
    if table_name == "comments":
        reference_filters = []
        if BackupComponent.ACCOUNTS in components:
            users = tables["users"]
            reference_filters.append(
                table.c.comment_id.in_(
                    select(users.c.status_comment_id).where(
                        users.c.status_comment_id.is_not(None)
                    )
                )
            )
        if BackupComponent.BANNED_SUBNETS in components:
            banned_subnets = tables["banned_subnets"]
            reference_filters.append(
                table.c.comment_id.in_(
                    select(banned_subnets.c.reason_comment_id).where(
                        banned_subnets.c.reason_comment_id.is_not(None)
                    )
                )
            )
        return statement.where(or_(*reference_filters))
    return statement


def _apply_compiled_access_rule_export_filter(
    statement,
    table: Table,
    table_name: str,
    tables: dict[str, Table],
    active_compiled_rule_set_ids: frozenset[str],
):
    if table_name == "compiled_access_rule_sets":
        return statement.where(table.c.id.in_(sorted(active_compiled_rule_set_ids)))
    if table_name == "compiled_access_rules":
        return statement.where(
            table.c.rule_set_id.in_(sorted(active_compiled_rule_set_ids))
        )
    if table_name == "compiled_access_rule_groups":
        rules = tables["compiled_access_rules"]
        return statement.where(
            table.c.rule_id.in_(
                select(rules.c.id).where(
                    rules.c.rule_set_id.in_(sorted(active_compiled_rule_set_ids))
                )
            )
        )
    if table_name in {
        "compiled_access_rule_memberships",
        "compiled_access_rule_rights",
    }:
        rules = tables["compiled_access_rules"]
        groups = tables["compiled_access_rule_groups"]
        return statement.where(
            table.c.group_id.in_(
                select(groups.c.id).where(
                    groups.c.rule_id.in_(
                        select(rules.c.id).where(
                            rules.c.rule_set_id.in_(
                                sorted(active_compiled_rule_set_ids)
                            )
                        )
                    )
                )
            )
        )
    return statement


def _write_encrypted_archive(
    output_path: Path,
    staging_dir: Path,
    header_bytes: bytes,
    key: bytes,
    nonce: bytes,
    *,
    progress_reporter: _BackupProgressReporter | None = None,
) -> None:
    prefix = _header_prefix(header_bytes)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce))
    encryptor = cipher.encryptor()
    encryptor.authenticate_additional_data(prefix)

    compressed_payload = staging_dir / "payload.tar.xz"
    temp_output = output_path.with_name(f".{output_path.name}.{os.getpid()}.tmp")
    LOGGER.debug("Writing encrypted archive via temporary file %s", temp_output)
    try:
        _write_compressed_payload(
            compressed_payload,
            staging_dir,
            progress_reporter=progress_reporter,
        )
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


def _write_compressed_payload(
    output_path: Path,
    staging_dir: Path,
    *,
    progress_reporter: _BackupProgressReporter | None = None,
) -> None:
    LOGGER.debug("Creating compressed payload at %s", output_path)
    staged_files = sorted((staging_dir / "files").iterdir())
    staged_tables = staging_dir / "tables"
    archive_members = [
        (staging_dir / "manifest.json", "manifest.json"),
        *(
            (
                staged_tables / f"{table_name}.jsonl",
                f"tables/{table_name}.jsonl",
            )
            for table_name in BACKUP_TABLE_NAMES
            if (staged_tables / f"{table_name}.jsonl").is_file()
        ),
        *((staged_file, f"files/{staged_file.name}") for staged_file in staged_files),
    ]
    total_members = len(archive_members)
    with (
        lzma.open(output_path, "wb", preset=6) as compressed,
        tarfile.open(fileobj=compressed, mode="w|") as tar,
    ):
        for member_index, (source_path, archive_path) in enumerate(
            archive_members,
            start=1,
        ):
            _add_staged_file(
                tar,
                source_path,
                archive_path,
                progress_reporter=progress_reporter,
                member_index=member_index,
                total_members=total_members,
            )
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
    deferred_updates: dict[str, list[dict[str, Any]]] = {
        table_name: [] for table_name in DEFERRED_COLUMNS if table_name in table_names
    }

    with session_factory.begin() as session:
        connection = session.connection()
        _restore_legacy_nodes_if_needed(connection, extract_dir, manifest, tables)
        for table_index, table_name in enumerate(table_names, start=1):
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
                connection.execute(insert(table), insert_rows)
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


def _restore_legacy_nodes_if_needed(
    connection,
    extract_dir: Path,
    manifest: dict[str, Any],
    tables: Mapping[str, Table],
) -> None:
    if "nodes" in manifest.get("tables", {}):
        return

    node_rows: dict[str, dict[str, Any]] = {}
    for table_name, node_type in (("folders", "directory"), ("documents", "document")):
        if table_name not in manifest.get("tables", {}):
            continue
        table_manifest = manifest["tables"][table_name]
        path = _safe_payload_path(extract_dir, f"tables/{table_name}.jsonl")
        with path.open("rb") as f:
            rows = [orjson.loads(line) for line in f if line.strip()]
        if len(rows) != table_manifest["rows"]:
            raise BackupFormatError(
                f"Row count mismatch for table {table_name!r}: "
                f"manifest says {table_manifest['rows']}, payload has {len(rows)}"
            )
        for row in rows:
            node_id = str(row["id"])
            if node_id in node_rows:
                raise BackupFormatError(
                    f"Duplicate document/folder node id in backup: {node_id!r}"
                )
            node_rows[node_id] = {
                "id": node_id,
                "type": node_type,
                "inherit": row.get("inherit", True),
                "status": row.get("status", 0),
                "status_operation_id": row.get("status_operation_id"),
            }

    if node_rows:
        connection.execute(insert(tables["nodes"]), list(node_rows.values()))


def _build_missing_compiled_rule_set_mapping(
    extract_dir: Path,
    manifest: dict[str, Any],
) -> dict[str, str]:
    if "compiled_access_rules" not in manifest.get("tables", {}):
        return {}
    if "compiled_access_rule_sets" in manifest.get("tables", {}):
        return {}

    table_manifest = manifest["tables"]["compiled_access_rules"]
    path = _safe_payload_path(extract_dir, "tables/compiled_access_rules.jsonl")
    node_ids: set[str] = set()
    with path.open("rb") as f:
        row_count = 0
        for line_number, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                row = orjson.loads(line)
            except orjson.JSONDecodeError as exc:
                raise BackupFormatError(
                    f"Invalid JSON row in {path} at line {line_number}"
                ) from exc
            row_count += 1
            node_id = row.get("node_id", row.get("target_id"))
            if node_id:
                node_ids.add(str(node_id))
    if row_count != table_manifest["rows"]:
        raise BackupFormatError(
            "Row count mismatch for table 'compiled_access_rules': "
            f"manifest says {table_manifest['rows']}, payload has {row_count}"
        )
    return {node_id: secrets.token_hex(16) for node_id in sorted(node_ids)}


def _load_compiled_rule_node_ids(
    extract_dir: Path,
    manifest: dict[str, Any],
) -> list[str | None]:
    table_manifest = manifest["tables"]["compiled_access_rules"]
    path = _safe_payload_path(extract_dir, "tables/compiled_access_rules.jsonl")
    node_ids: list[str | None] = []
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
            node_id = row.get("node_id", row.get("target_id"))
            node_ids.append(str(node_id) if node_id else None)
    if len(node_ids) != table_manifest["rows"]:
        raise BackupFormatError(
            "Row count mismatch for table 'compiled_access_rules': "
            f"manifest says {table_manifest['rows']}, payload has {len(node_ids)}"
        )
    return node_ids


def _restore_missing_compiled_rule_sets(
    connection,
    tables: Mapping[str, Table],
    rule_set_id_by_node: Mapping[str, str],
) -> None:
    if not rule_set_id_by_node:
        return

    created_at = dt.datetime.now(dt.UTC).timestamp()
    connection.execute(
        insert(tables["compiled_access_rule_sets"]),
        [
            {
                "id": rule_set_id,
                "node_id": node_id,
                "created_at": created_at,
            }
            for node_id, rule_set_id in rule_set_id_by_node.items()
        ],
    )
    nodes = tables["nodes"]
    for node_id, rule_set_id in rule_set_id_by_node.items():
        connection.execute(
            update(nodes)
            .where(nodes.c.id == node_id)
            .values(access_rule_set_id=rule_set_id)
        )


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


def _load_legacy_banned_subnet_reasons(
    extract_dir: Path,
    manifest: dict[str, Any],
) -> dict[str, str | None]:
    table_manifest = manifest.get("tables", {}).get("banned_subnets")
    if table_manifest is None:
        return {}

    path = _safe_payload_path(extract_dir, "tables/banned_subnets.jsonl")
    reasons: dict[str, str | None] = {}
    row_count = 0
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
            row_count += 1
            if "reason" in row and "reason_comment_id" not in row:
                reasons[str(row["subnet"])] = row["reason"]
    if row_count != table_manifest["rows"]:
        raise BackupFormatError(
            "Row count mismatch for table 'banned_subnets': "
            f"manifest says {table_manifest['rows']}, payload has {row_count}"
        )
    return reasons


def _load_legacy_access_rule_rows(
    extract_dir: Path,
    manifest: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    rows_by_table: dict[str, list[dict[str, Any]]] = {}
    for table_name in LEGACY_ACCESS_RULE_TABLE_NAMES:
        if table_name not in manifest.get("tables", {}):
            continue
        table_manifest = manifest["tables"][table_name]
        path = _safe_payload_path(extract_dir, f"tables/{table_name}.jsonl")
        rows = []
        with path.open("rb") as f:
            for line_number, line in enumerate(f, start=1):
                if not line.strip():
                    continue
                try:
                    rows.append(orjson.loads(line))
                except orjson.JSONDecodeError as exc:
                    raise BackupFormatError(
                        f"Invalid JSON row in {path} at line {line_number}"
                    ) from exc
        if len(rows) != table_manifest["rows"]:
            raise BackupFormatError(
                f"Row count mismatch for table {table_name!r}: "
                f"manifest says {table_manifest['rows']}, payload has {len(rows)}"
            )
        rows_by_table[table_name] = rows
    return rows_by_table


def _restore_legacy_access_rules(
    session,
    rows_by_table: dict[str, list[dict[str, Any]]],
) -> None:
    """Convert pre-compiled backup rows into current compiled access rows."""
    rules_by_node: dict[str, list[CompiledAccessRule]] = {}

    for row in rows_by_table.get("document_access_rules", []):
        compiled_rule = compile_access_rule(
            access_type=str(row["access_type"]),
            rule_data=_coerce_legacy_rule_data(row.get("rule_data")),
        )
        if compiled_rule is not None:
            rules_by_node.setdefault(str(row["document_id"]), []).append(compiled_rule)

    for row in rows_by_table.get("folder_access_rules", []):
        compiled_rule = compile_access_rule(
            access_type=str(row["access_type"]),
            rule_data=_coerce_legacy_rule_data(row.get("rule_data")),
        )
        if compiled_rule is not None:
            rules_by_node.setdefault(str(row["folder_id"]), []).append(compiled_rule)

    for node_id, rules in rules_by_node.items():
        node = session.get(Node, node_id)
        if node is None:
            continue
        rule_set = CompiledAccessRuleSet(node_id=node_id)
        rule_set.rules.extend(rules)
        session.add(rule_set)
        session.flush()
        node.active_access_rule_set = rule_set
        node.access_rule_set_id = rule_set.id


def _coerce_legacy_rule_data(value: Any) -> dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        parsed = json.loads(value)
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _decode_row(row: dict[str, Any], table: Table) -> dict[str, Any]:
    if table.name == "banned_subnets":
        created_at = row.get("created_at")
        if isinstance(created_at, str):
            parsed_created_at = dt.datetime.fromisoformat(
                created_at.replace("Z", "+00:00")
            )
            if parsed_created_at.tzinfo is None:
                parsed_created_at = parsed_created_at.replace(tzinfo=dt.UTC)
            created_at = parsed_created_at.timestamp()
            row = {**row, "created_at": created_at}
        if "starts_at" not in row:
            row = {**row, "starts_at": created_at}
        if "expires_at" not in row:
            row = {**row, "expires_at": None}

    decoded = {}
    for column in table.columns:
        if column.name not in row:
            decoded[column.name] = None
            continue
        value = row[column.name]
        if value is not None and isinstance(column.type, DateTime):
            value = dt.datetime.fromisoformat(value)
        if (
            value is not None
            and table.name == "comments"
            and column.name == "content_digest"
        ):
            if not isinstance(value, str) or len(value) != 64:
                raise BackupFormatError("Invalid comment digest in backup")
            try:
                value = bytes.fromhex(value)
            except ValueError as exc:
                raise BackupFormatError("Invalid comment digest in backup") from exc
            if len(value) != 32:
                raise BackupFormatError("Invalid comment digest in backup")
        decoded[column.name] = value
    return decoded


def _validate_manifest(manifest: dict[str, Any]) -> None:
    LOGGER.debug("Validating backup manifest")
    if manifest.get("format_version") != BACKUP_FORMAT_VERSION:
        raise BackupFormatError(
            f"Unsupported payload format version: {manifest.get('format_version')}"
        )
    table_names: set[str] = set(manifest.get("tables", {}).keys())
    expected: set[str] = set(BACKUP_TABLE_NAMES)
    compiled_access_rule_tables = set(COMPILED_ACCESS_RULE_TABLE_NAMES)
    legacy_access_rule_tables = set(LEGACY_ACCESS_RULE_TABLE_NAMES)
    previous_compiled_expected = expected - {"compiled_access_rule_sets"}
    legacy_expected = (
        expected - compiled_access_rule_tables
    ) | legacy_access_rule_tables
    unknown_tables = table_names - expected - legacy_access_rule_tables
    if unknown_tables:
        raise BackupFormatError(
            f"Backup table set contains unsupported tables: {sorted(unknown_tables)}"
        )
    if (
        "components" not in manifest
        and table_names != expected
        and table_names != previous_compiled_expected
        and table_names != legacy_expected
    ):
        raise BackupFormatError(
            "Backup table set does not match this server version: "
            f"expected {sorted(expected)}, got {sorted(table_names)}"
        )
    if "components" in manifest:
        try:
            BackupExportSelection.from_component_values(manifest["components"])
        except (TypeError, ValueError) as exc:
            raise BackupFormatError(
                "Backup manifest contains invalid components"
            ) from exc
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


def _manifest_table_names(manifest: dict[str, Any]) -> tuple[str, ...]:
    table_names = set(manifest.get("tables", {}))
    return tuple(table_name for table_name in INSERT_ORDER if table_name in table_names)


def _manifest_includes_configuration(manifest: dict[str, Any]) -> bool:
    return bool(manifest.get("configuration"))


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
    with (
        lzma.open(source_path, "rb") as compressed,
        tarfile.open(fileobj=compressed, mode="r|") as tar,
    ):
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
                raise BackupFormatError(f"Unable to read archive member: {member.name}")
            with extracted, target_path.open("wb") as target:
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
    tar: tarfile.TarFile,
    source_path: Path,
    archive_path: str,
    *,
    progress_reporter: _BackupProgressReporter | None = None,
    member_index: int | None = None,
    total_members: int | None = None,
) -> None:
    stat_result = source_path.stat()
    LOGGER.debug(
        "Adding archive member %s from %s (%d byte(s), %s/%s)",
        archive_path,
        source_path,
        stat_result.st_size,
        member_index if member_index is not None else "?",
        total_members if total_members is not None else "?",
    )
    _emit_progress(
        progress_reporter,
        phase="archive_member",
        message="Adding archive member",
        current_step=5,
        total_steps=EXPORT_PROGRESS_STEPS,
        detail=archive_path,
        completed_units=member_index,
        total_units=total_members,
        verbose_only=True,
    )
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


def _serialize_table_value(table_name: str, column_name: str, value: Any) -> Any:
    if (
        value is not None
        and table_name == "comments"
        and column_name == "content_digest"
    ):
        if not isinstance(value, (bytes, bytearray, memoryview)):
            raise BackupIntegrityError("Invalid binary comment digest in database")
        digest = bytes(value)
        if len(digest) != 32:
            raise BackupIntegrityError("Invalid binary comment digest in database")
        return digest.hex()
    return _serialize_value(value)


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
    progress_reporter: _BackupProgressReporter | None,
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
    if progress_reporter is None:
        return
    if verbose_only:
        progress_reporter.update_detail(
            phase=phase,
            message=message,
            detail=detail,
            completed_units=completed_units,
            total_units=total_units,
        )
        return
    progress_reporter.update_overall(
        message=message,
        current_step=current_step,
        total_steps=total_steps,
        detail=detail,
    )


def _format_progress_description(message: str, detail: str | None = None) -> str:
    if detail:
        return f"{message}: {detail}"
    return message


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
