import contextlib
import hashlib
import logging
import lzma
import os
import tarfile
from collections.abc import Sequence
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

import orjson

from include.providers.base import StorageProvider
from maintenance.backup.constants import (
    BACKUP_FORMAT_VERSION,
    MAX_BACKUP_FILES,
    MAX_BACKUP_UNCOMPRESSED_BYTES,
    MAX_MANIFEST_BYTES,
)
from maintenance.backup.models import (
    BackupFormatError,
    BackupIntegrityError,
)
from maintenance.backup.progress import (
    EXPORT_PROGRESS_STEPS,
    _BackupProgressReporter,
    _emit_progress,
)
from maintenance.backup.selection import (
    BACKUP_TABLE_NAMES,
    COMPILED_ACCESS_RULE_TABLE_NAMES,
    EXCLUDED_TABLE_NAMES,
    INSERT_ORDER,
    LEGACY_ACCESS_RULE_TABLE_NAMES,
    BackupComponent,
    BackupExportSelection,
    _selected_table_names,
)

LOGGER = logging.getLogger(__name__)


def _validate_manifest(manifest: dict[str, Any]) -> None:
    LOGGER.debug("Validating backup manifest")
    tables = manifest.get("tables")
    files = manifest.get("files")
    if not isinstance(tables, dict):
        raise BackupFormatError("Backup manifest tables must be an object")
    if not isinstance(files, list):
        raise BackupFormatError("Backup manifest files must be an array")
    configuration = manifest.get("configuration", {})
    if not isinstance(configuration, dict):
        raise BackupFormatError("Backup manifest contains invalid configuration")
    for section_name, key_name in (
        ("security", "pepper"),
        ("server", "secret_key"),
    ):
        section = configuration.get(section_name)
        if configuration and (
            not isinstance(section, dict) or not isinstance(section.get(key_name), str)
        ):
            raise BackupFormatError("Backup manifest contains invalid configuration")
    if len(files) > MAX_BACKUP_FILES:
        raise BackupFormatError(
            f"Backup contains more than {MAX_BACKUP_FILES} file entries"
        )
    for table_name, table_manifest in tables.items():
        if not isinstance(table_name, str) or not isinstance(table_manifest, dict):
            raise BackupFormatError("Backup manifest contains invalid table metadata")
        row_count = table_manifest.get("rows")
        if (
            isinstance(row_count, bool)
            or not isinstance(row_count, int)
            or row_count < 0
        ):
            raise BackupFormatError(
                f"Backup manifest contains an invalid row count for {table_name!r}"
            )
    if manifest.get("format_version") != BACKUP_FORMAT_VERSION:
        raise BackupFormatError(
            f"Unsupported payload format version: {manifest.get('format_version')}"
        )
    table_names: set[str] = set(tables)
    expected: set[str] = set(BACKUP_TABLE_NAMES)
    compiled_access_rule_tables = set(COMPILED_ACCESS_RULE_TABLE_NAMES)
    legacy_access_rule_tables = set(LEGACY_ACCESS_RULE_TABLE_NAMES)
    previous_compiled_expected = expected - {"compiled_access_rule_sets"}
    legacy_expected = (
        expected - compiled_access_rule_tables
    ) | legacy_access_rule_tables
    # Schedules were added without changing the backup format version, so full
    # backups created before that table existed remain compatible.
    compatible_table_names = table_names | {"schedules"}
    unknown_tables = table_names - expected - legacy_access_rule_tables
    if unknown_tables:
        raise BackupFormatError(
            f"Backup table set contains unsupported tables: {sorted(unknown_tables)}"
        )
    if (
        "components" not in manifest
        and compatible_table_names != expected
        and compatible_table_names != previous_compiled_expected
        and compatible_table_names != legacy_expected
    ):
        raise BackupFormatError(
            "Backup table set does not match this server version: "
            f"expected {sorted(expected)}, got {sorted(table_names)}"
        )
    if "components" in manifest:
        try:
            selection = BackupExportSelection.from_component_values(
                manifest["components"]
            )
        except (TypeError, ValueError) as exc:
            raise BackupFormatError(
                "Backup manifest contains invalid components"
            ) from exc
        components = selection.resolved_components()
        selected_table_names = set(
            _selected_table_names(
                components,
                include_files=bool(
                    BackupComponent.ACCOUNTS in components
                    or BackupComponent.DOCUMENT_LIBRARY in components
                ),
            )
        )
        allowed_table_names = set(selected_table_names)
        if BackupComponent.DOCUMENT_LIBRARY in components:
            allowed_table_names.update(LEGACY_ACCESS_RULE_TABLE_NAMES)
        outside_selection = table_names - allowed_table_names
        if outside_selection:
            raise BackupFormatError(
                "Backup tables are outside the selected components: "
                f"{sorted(outside_selection)}"
            )
        if configuration and BackupComponent.CONFIGURATION not in components:
            raise BackupFormatError(
                "Backup configuration is outside the selected components"
            )
        component_anchors = {
            BackupComponent.ACCOUNTS: {"users"},
            BackupComponent.DOCUMENT_LIBRARY: {"nodes", "folders", "documents"},
            BackupComponent.AUDIT_LOG: {"audit_entries"},
            BackupComponent.BANNED_SUBNETS: {"banned_subnets"},
        }
        missing_components = [
            component.value
            for component in selection.components
            if (
                component in component_anchors
                and table_names.isdisjoint(component_anchors[component])
            )
            or (component is BackupComponent.CONFIGURATION and not configuration)
        ]
    else:
        missing_components = []
    for excluded in EXCLUDED_TABLE_NAMES:
        if excluded in table_names:
            raise BackupFormatError(f"Excluded table {excluded!r} is present")
    storage_paths: set[str] = set()
    archive_paths: set[str] = set()
    file_ids: set[str] = set()
    for entry in files:
        if not isinstance(entry, dict):
            raise BackupFormatError("Backup manifest contains an invalid file entry")
        file_id = entry.get("file_id")
        storage_path = entry.get("storage_path")
        archive_path = entry.get("archive_path")
        size = entry.get("size")
        digest = entry.get("sha256")
        if (
            not isinstance(file_id, str)
            or not isinstance(storage_path, str)
            or not isinstance(archive_path, str)
            or isinstance(size, bool)
            or not isinstance(size, int)
            or size < 0
            or not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdefABCDEF" for character in digest)
        ):
            raise BackupFormatError("Backup manifest contains an invalid file entry")
        _validate_storage_path(storage_path)
        archive_parts = _archive_path_parts(archive_path)
        if len(archive_parts) != 2 or archive_parts[0] != "files":
            raise BackupFormatError(
                f"Unsafe file archive path in backup: {archive_path!r}"
            )
        if file_id in file_ids:
            raise BackupFormatError("Backup manifest contains duplicate file IDs")
        if storage_path in storage_paths or archive_path in archive_paths:
            raise BackupFormatError("Backup manifest contains duplicate file paths")
        file_ids.add(file_id)
        storage_paths.add(storage_path)
        archive_paths.add(archive_path)
    if missing_components:
        raise BackupFormatError(
            "Backup payload does not match the selected components: "
            f"{sorted(missing_components)}"
        )
    LOGGER.debug(
        "Backup manifest validated: tables=%d files=%d",
        len(table_names),
        len(files),
    )


def _manifest_table_names(manifest: dict[str, Any]) -> tuple[str, ...]:
    table_names = set(manifest.get("tables", {}))
    return tuple(table_name for table_name in INSERT_ORDER if table_name in table_names)


def _manifest_includes_configuration(manifest: dict[str, Any]) -> bool:
    return bool(manifest.get("configuration"))


def _load_manifest(path: Path) -> dict[str, Any]:
    LOGGER.debug("Loading backup manifest from %s", path)
    try:
        with path.open("rb") as manifest_file:
            contents = manifest_file.read(MAX_MANIFEST_BYTES + 1)
        if len(contents) > MAX_MANIFEST_BYTES:
            raise BackupFormatError(
                f"Backup manifest exceeds the {MAX_MANIFEST_BYTES}-byte limit"
            )
        manifest = orjson.loads(contents)
    except BackupFormatError:
        raise
    except (OSError, orjson.JSONDecodeError) as exc:
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
        member_count = 0
        declared_size = 0
        extracted_size = 0
        extracted_paths: set[Path] = set()
        for member in tar:
            member_count += 1
            if member_count > MAX_BACKUP_FILES + len(BACKUP_TABLE_NAMES) + 1:
                raise BackupFormatError("Backup archive contains too many members")
            LOGGER.debug("Extracting archive member %s", member.name)
            target_path = _safe_payload_path(target_dir, member.name)
            if target_path in extracted_paths:
                raise BackupFormatError(
                    f"Duplicate backup archive member: {member.name}"
                )
            extracted_paths.add(target_path)
            if member.isdir():
                target_path.mkdir(parents=True, exist_ok=True)
                continue
            if not member.isfile():
                raise BackupFormatError(
                    f"Unsupported archive member type: {member.name}"
                )
            declared_size += member.size
            if declared_size > MAX_BACKUP_UNCOMPRESSED_BYTES:
                raise BackupFormatError(
                    "Backup archive exceeds the uncompressed size limit"
                )
            target_path.parent.mkdir(parents=True, exist_ok=True)
            extracted = tar.extractfile(member)
            if extracted is None:
                raise BackupFormatError(f"Unable to read archive member: {member.name}")
            with extracted, target_path.open("wb") as target:
                while chunk := extracted.read(1024 * 1024):
                    extracted_size += len(chunk)
                    if extracted_size > MAX_BACKUP_UNCOMPRESSED_BYTES:
                        raise BackupFormatError(
                            "Backup archive exceeds the uncompressed size limit"
                        )
                    target.write(chunk)
    LOGGER.debug("Compressed payload extracted to %s", target_dir)


def _validate_payload_tree(root: Path, manifest: dict[str, Any]) -> None:
    expected_files = {
        "manifest.json",
        *(f"tables/{table_name}.jsonl" for table_name in manifest["tables"]),
        *(entry["archive_path"] for entry in manifest["files"]),
    }
    expected_directories = {
        parent.as_posix()
        for relative_path in expected_files
        for parent in PurePosixPath(relative_path).parents
        if parent != PurePosixPath(".")
    }
    remaining = set(expected_files)
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            if path.is_symlink() or path.is_junction():
                raise BackupFormatError(
                    "Backup archive contents do not match its manifest"
                )
            relative_path = path.relative_to(root).as_posix()
            if path.is_dir():
                if relative_path not in expected_directories:
                    raise BackupFormatError(
                        "Backup archive contents do not match its manifest"
                    )
                pending.append(path)
                continue
            if not path.is_file() or relative_path not in remaining:
                raise BackupFormatError(
                    "Backup archive contents do not match its manifest"
                )
            remaining.remove(relative_path)
    if remaining:
        raise BackupFormatError("Backup archive contents do not match its manifest")


def _safe_payload_path(root: Path, archive_path: str) -> Path:
    parts = _archive_path_parts(archive_path)
    target = root.joinpath(*parts)
    resolved_root = root.resolve()
    resolved_target = target.resolve(strict=False)
    if not resolved_target.is_relative_to(resolved_root):
        raise BackupFormatError(f"Unsafe archive path: {archive_path}")
    return target


def _archive_path_parts(archive_path: str) -> tuple[str, ...]:
    if (
        not archive_path
        or "\\" in archive_path
        or "\x00" in archive_path
        or PureWindowsPath(archive_path).drive
        or PurePosixPath(archive_path).is_absolute()
    ):
        raise BackupFormatError(f"Unsafe archive path: {archive_path}")
    parts = archive_path.removesuffix("/").split("/")
    if any(
        part in ("", ".", "..") or ":" in part or part.endswith((" ", "."))
        for part in parts
    ):
        raise BackupFormatError(f"Unsafe archive path: {archive_path}")
    return tuple(parts)


def _validate_storage_path(path: str) -> None:
    if (
        not path
        or "\\" in path
        or "\x00" in path
        or os.path.isabs(path)
        or PureWindowsPath(path).drive
        or PurePosixPath(path).is_absolute()
    ):
        raise BackupFormatError(f"Unsafe storage path in backup: {path!r}")
    parts = path.split("/")
    if any(
        part in ("", ".", "..") or ":" in part or part.endswith((" ", "."))
        for part in parts
    ):
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
    if size != expected_size or sha256.hexdigest() != expected_sha256.lower():
        raise BackupIntegrityError(
            f"File payload failed verification for {entry['storage_path']}"
        )
    LOGGER.debug("Verified file payload for %s", entry["storage_path"])


def _cleanup_restored_files(
    storage_provider: StorageProvider,
    paths: Sequence[str],
) -> None:
    for path in reversed(paths):
        with contextlib.suppress(Exception):
            LOGGER.debug("Removing restored file after failed import: %s", path)
            storage_provider.remove(path)


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
        detail_task=True,
    )
    info = tarfile.TarInfo(archive_path)
    info.size = stat_result.st_size
    info.mtime = int(stat_result.st_mtime)
    with source_path.open("rb") as f:
        tar.addfile(info, f)


def _write_json(path: Path, data: dict[str, Any]) -> None:
    encoded = orjson.dumps(
        data,
        option=orjson.OPT_INDENT_2 | orjson.OPT_SORT_KEYS,
    )
    if len(encoded) > MAX_MANIFEST_BYTES:
        raise BackupFormatError(
            f"Backup manifest exceeds the {MAX_MANIFEST_BYTES}-byte limit"
        )
    path.write_bytes(encoded)
