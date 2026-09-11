import hashlib
import re
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path, PurePosixPath, PureWindowsPath

from include.extensions.manager import (
    DiscoveredExtension,
    ExtensionManifestError,
    parse_extension_manifest,
)
from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.operations.extensions.models import ExtensionPackageInspection

MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
_COPY_CHUNK_BYTES = 1024 * 1024
_SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}").fullmatch
_ALLOWED_COMPRESSIONS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as package_file:
        for chunk in iter(lambda: package_file.read(_COPY_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_expected_sha256(expected_sha256: str | None) -> str | None:
    if expected_sha256 is None:
        return None
    if _SHA256_PATTERN(expected_sha256) is None:
        raise MaintenanceOperationError(
            "--sha256 must be exactly 64 hexadecimal digits"
        )
    return expected_sha256.lower()


def _archive_member_path(name: str) -> tuple[str, ...]:
    if not name or "\\" in name or "\x00" in name:
        raise MaintenanceOperationError(f"Unsafe extension archive path: {name!r}")
    if PureWindowsPath(name).drive or PurePosixPath(name).is_absolute():
        raise MaintenanceOperationError(f"Unsafe extension archive path: {name!r}")
    normalized_name = name.removesuffix("/")
    raw_parts = normalized_name.split("/")
    if not raw_parts or any(
        part in {"", ".", ".."} or ":" in part or part.endswith((" ", "."))
        for part in raw_parts
    ):
        raise MaintenanceOperationError(f"Unsafe extension archive path: {name!r}")
    return tuple(raw_parts)


def _validate_member_type(info: zipfile.ZipInfo) -> None:
    mode = (info.external_attr >> 16) & 0xFFFF
    file_type = stat.S_IFMT(mode)
    expected_type = stat.S_IFDIR if info.is_dir() else stat.S_IFREG
    if file_type not in {0, expected_type}:
        raise MaintenanceOperationError(
            f"Unsupported extension archive member type: {info.filename}"
        )


def _validate_archive_members(
    members: list[zipfile.ZipInfo],
) -> tuple[list[tuple[zipfile.ZipInfo, tuple[str, ...]]], int]:
    if len(members) > MAX_ARCHIVE_MEMBERS:
        raise MaintenanceOperationError(
            f"Extension package contains more than {MAX_ARCHIVE_MEMBERS} members"
        )
    validated = []
    kinds: dict[str, bool] = {}
    total_size = 0
    for info in members:
        archive_name = info.orig_filename
        if info.flag_bits & 0x1:
            raise MaintenanceOperationError(
                f"Encrypted extension archive member is not supported: {archive_name}"
            )
        if info.compress_type not in _ALLOWED_COMPRESSIONS:
            raise MaintenanceOperationError(
                f"Unsupported compression for extension archive member: {archive_name}"
            )
        _validate_member_type(info)
        parts = _archive_member_path(archive_name)
        normalized = "/".join(parts).casefold()
        if normalized in kinds:
            raise MaintenanceOperationError(
                f"Duplicate extension archive path: {archive_name}"
            )
        is_directory = info.is_dir()
        for index in range(1, len(parts)):
            parent = "/".join(parts[:index]).casefold()
            if kinds.get(parent) is False:
                raise MaintenanceOperationError(
                    f"Extension archive file/directory conflict: {archive_name}"
                )
        if not is_directory:
            prefix = f"{normalized}/"
            if any(path.startswith(prefix) for path in kinds):
                raise MaintenanceOperationError(
                    f"Extension archive file/directory conflict: {archive_name}"
                )
            total_size += info.file_size
            if total_size > MAX_UNCOMPRESSED_BYTES:
                raise MaintenanceOperationError(
                    "Extension package exceeds the 256 MiB uncompressed limit"
                )
        kinds[normalized] = is_directory
        validated.append((info, parts))
    for required in ("manifest.toml", "_extension.py"):
        if kinds.get(required.casefold()) is not False:
            raise MaintenanceOperationError(
                f"Extension package root is missing required file {required}"
            )
    return validated, total_size


def _extract_package(
    package_path: str | Path,
    expected_sha256: str | None,
    extension_root: Path,
) -> tuple[ExtensionPackageInspection, DiscoveredExtension, Path]:
    candidate = Path(package_path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    resolved_package = candidate.resolve()
    try:
        package_size = resolved_package.stat().st_size
    except OSError as exc:
        raise MaintenanceOperationError(
            f"Unable to read extension package {resolved_package}: {exc}"
        ) from exc
    if package_size > MAX_PACKAGE_BYTES:
        raise MaintenanceOperationError("Extension package exceeds the 64 MiB limit")
    expected = _validate_expected_sha256(expected_sha256)
    try:
        actual_sha256 = _hash_file(resolved_package)
    except OSError as exc:
        raise MaintenanceOperationError(
            f"Unable to read extension package {resolved_package}: {exc}"
        ) from exc
    if expected is not None and actual_sha256 != expected:
        raise MaintenanceOperationError(
            f"Extension package SHA-256 mismatch: expected {expected}, "
            f"got {actual_sha256}"
        )

    stage = Path(tempfile.mkdtemp(prefix=".cfms-extension-stage-", dir=extension_root))
    try:
        with zipfile.ZipFile(resolved_package) as archive:
            validated, _ = _validate_archive_members(archive.infolist())
            actual_total = 0
            for info, parts in validated:
                target = stage.joinpath(*parts)
                if info.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(info) as source, target.open("xb") as output:
                    while chunk := source.read(_COPY_CHUNK_BYTES):
                        actual_total += len(chunk)
                        if actual_total > MAX_UNCOMPRESSED_BYTES:
                            raise MaintenanceOperationError(
                                "Extension package exceeds the 256 MiB "
                                "uncompressed limit"
                            )
                        output.write(chunk)
        try:
            manifest = parse_extension_manifest(stage / "manifest.toml")
        except ExtensionManifestError as exc:
            raise MaintenanceOperationError(str(exc)) from exc
        identifier = manifest.extension.identifier
        if identifier == "builtin":
            raise MaintenanceOperationError("The built-in extension cannot be managed")
        if identifier in manifest.dependencies.extensions:
            raise MaintenanceOperationError(
                f"Extension {identifier!r} cannot depend on itself"
            )
        inspection = ExtensionPackageInspection(
            package_path=resolved_package,
            sha256=actual_sha256,
            manifest=manifest,
        )
        discovered = DiscoveredExtension(
            manifest=manifest,
            directory=stage,
            entrypoint=stage / "_extension.py",
        )
        return inspection, discovered, stage
    except (OSError, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError) as exc:
        shutil.rmtree(stage, ignore_errors=True)
        if isinstance(exc, MaintenanceOperationError):
            raise
        raise MaintenanceOperationError(
            f"Unable to extract extension package {resolved_package}: {exc}"
        ) from exc
    except Exception:
        shutil.rmtree(stage, ignore_errors=True)
        raise
