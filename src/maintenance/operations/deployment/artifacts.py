import secrets
import shutil
import stat
import tarfile
import zipfile
from pathlib import Path

from maintenance.operations.deployment.constants import (
    _ALLOWED_ZIP_COMPRESSIONS,
    _COPY_CHUNK_BYTES,
    _SHA256_PATTERN,
    MAX_ARCHIVE_MEMBERS,
    MAX_PACKAGE_BYTES,
    MAX_UNCOMPRESSED_BYTES,
)
from maintenance.operations.deployment.models import _Release
from maintenance.operations.deployment.repository import (
    _archive_parts,
    _hash_file,
    _maintenance_root,
    _parse_manifest,
    _release_from_tree,
)
from maintenance.operations.exceptions import MaintenanceOperationError


def _expected_digest(
    package_path: Path,
    expected_sha256: str | None,
    checksums_path: str | Path | None,
) -> str | None:
    if expected_sha256 is not None and checksums_path is not None:
        raise MaintenanceOperationError(
            "Choose at most one package digest source: --sha256 or --checksums"
        )
    if expected_sha256 is None and checksums_path is None:
        return None
    if expected_sha256 is not None:
        if _SHA256_PATTERN(expected_sha256) is None:
            raise MaintenanceOperationError(
                "--sha256 must be exactly 64 hexadecimal digits"
            )
        return expected_sha256.lower()

    checksum_file = Path(checksums_path).expanduser().resolve()
    try:
        lines = checksum_file.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise MaintenanceOperationError(
            f"Unable to read checksum file {checksum_file}: {exc}"
        ) from exc
    matches = []
    for line in lines:
        parts = line.split(maxsplit=1)
        if len(parts) == 2 and Path(parts[1].lstrip("* ")).name == package_path.name:
            matches.append(parts[0])
    if len(matches) != 1 or _SHA256_PATTERN(matches[0]) is None:
        raise MaintenanceOperationError(
            f"Checksum file must contain exactly one valid entry for {package_path.name}"
        )
    return matches[0].lower()


def _validate_path_set(
    entries: list[tuple[str, bool, int]],
) -> tuple[str, dict[str, tuple[str, ...]]]:
    if len(entries) > MAX_ARCHIVE_MEMBERS:
        raise MaintenanceOperationError(
            f"Release package contains more than {MAX_ARCHIVE_MEMBERS} members"
        )
    roots = set()
    paths = {}
    kinds: dict[str, bool] = {}
    total_size = 0
    for name, is_directory, size in entries:
        parts = _archive_parts(name)
        roots.add(parts[0])
        normalized = "/".join(parts).casefold()
        if normalized in kinds:
            raise MaintenanceOperationError(f"Duplicate release archive path: {name}")
        for index in range(1, len(parts)):
            if kinds.get("/".join(parts[:index]).casefold()) is False:
                raise MaintenanceOperationError(
                    f"Release archive file/directory conflict: {name}"
                )
        if not is_directory:
            prefix = f"{normalized}/"
            if any(path.startswith(prefix) for path in kinds):
                raise MaintenanceOperationError(
                    f"Release archive file/directory conflict: {name}"
                )
            total_size += size
            if total_size > MAX_UNCOMPRESSED_BYTES:
                raise MaintenanceOperationError(
                    "Release package exceeds the 256 MiB uncompressed limit"
                )
        kinds[normalized] = is_directory
        paths[name] = parts
    if len(roots) != 1:
        raise MaintenanceOperationError(
            "Release package must contain exactly one top-level directory"
        )
    return roots.pop(), paths


def _extract_zip(package_path: Path, target: Path) -> str:
    with zipfile.ZipFile(package_path) as archive:
        entries = []
        for info in archive.infolist():
            if info.flag_bits & 0x1:
                raise MaintenanceOperationError(
                    f"Encrypted release member is not supported: {info.filename}"
                )
            if info.compress_type not in _ALLOWED_ZIP_COMPRESSIONS:
                raise MaintenanceOperationError(
                    f"Unsupported release compression: {info.filename}"
                )
            mode = (info.external_attr >> 16) & 0xFFFF
            expected_type = stat.S_IFDIR if info.is_dir() else stat.S_IFREG
            if stat.S_IFMT(mode) not in {0, expected_type}:
                raise MaintenanceOperationError(
                    f"Unsupported release member type: {info.filename}"
                )
            entries.append((info.orig_filename, info.is_dir(), info.file_size))
        top_level, paths = _validate_path_set(entries)
        actual_size = 0
        for info in archive.infolist():
            parts = paths[info.orig_filename][1:]
            if not parts:
                continue
            destination = target.joinpath(*parts)
            if info.is_dir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            destination.parent.mkdir(parents=True, exist_ok=True)
            with archive.open(info) as source, destination.open("xb") as output:
                while chunk := source.read(_COPY_CHUNK_BYTES):
                    actual_size += len(chunk)
                    if actual_size > MAX_UNCOMPRESSED_BYTES:
                        raise MaintenanceOperationError(
                            "Release package exceeds the uncompressed limit"
                        )
                    output.write(chunk)
        return top_level


def _extract_tar(package_path: Path, target: Path) -> str:
    with tarfile.open(package_path, "r:gz") as archive:
        members = archive.getmembers()
        entries = []
        for member in members:
            if not member.isfile() and not member.isdir():
                raise MaintenanceOperationError(
                    f"Unsupported release member type: {member.name}"
                )
            entries.append((member.name, member.isdir(), member.size))
        top_level, paths = _validate_path_set(entries)
        actual_size = 0
        for member in members:
            parts = paths[member.name][1:]
            if not parts:
                continue
            destination = target.joinpath(*parts)
            if member.isdir():
                destination.mkdir(parents=True, exist_ok=True)
                continue
            source = archive.extractfile(member)
            if source is None:
                raise MaintenanceOperationError(
                    f"Unable to read release member: {member.name}"
                )
            destination.parent.mkdir(parents=True, exist_ok=True)
            with source, destination.open("xb") as output:
                while chunk := source.read(_COPY_CHUNK_BYTES):
                    actual_size += len(chunk)
                    if actual_size > MAX_UNCOMPRESSED_BYTES:
                        raise MaintenanceOperationError(
                            "Release package exceeds the uncompressed limit"
                        )
                    output.write(chunk)
        return top_level


def _stage_release(
    package: str | Path,
    project_root: Path,
    *,
    expected_sha256: str | None,
    checksums_path: str | Path | None,
) -> tuple[_Release, str, Path]:
    package_path = Path(package).expanduser().resolve()
    try:
        package_size = package_path.stat().st_size
    except OSError as exc:
        raise MaintenanceOperationError(
            f"Unable to read release package {package_path}: {exc}"
        ) from exc
    if package_size > MAX_PACKAGE_BYTES:
        raise MaintenanceOperationError("Release package exceeds the 64 MiB limit")
    expected = _expected_digest(package_path, expected_sha256, checksums_path)
    actual = _hash_file(package_path)
    if expected is not None and actual != expected:
        raise MaintenanceOperationError(
            f"Release package SHA-256 mismatch: expected {expected}, got {actual}"
        )

    staging_root = _maintenance_root(project_root) / "staging"
    staging_root.mkdir(parents=True, exist_ok=True)
    stage = staging_root / secrets.token_hex(16)
    stage.mkdir()
    try:
        if zipfile.is_zipfile(package_path):
            top_level = _extract_zip(package_path, stage)
        elif package_path.name.endswith(".tar.gz"):
            top_level = _extract_tar(package_path, stage)
        else:
            raise MaintenanceOperationError(
                "Release package must be an official ZIP or tar.gz archive"
            )
        manifest = _parse_manifest(
            (stage / "release-manifest.json").read_bytes(), top_level=top_level
        )
        release = _release_from_tree(stage, exact=True)
        if release.manifest != manifest:
            raise MaintenanceOperationError("Release manifest changed during staging")
        return release, actual, stage
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
