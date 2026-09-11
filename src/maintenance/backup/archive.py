import contextlib
import hashlib
import logging
import lzma
import os
import shutil
import tarfile
from collections.abc import Iterable
from pathlib import Path, PurePosixPath
from typing import Any

import orjson

from include.providers.base import StorageProvider
from maintenance.backup.constants import BACKUP_FORMAT_VERSION
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
    BackupExportSelection,
)

LOGGER = logging.getLogger(__name__)


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
