import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import tempfile
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath

import tomlkit
from packaging.version import InvalidVersion
from packaging.version import Version as PackageVersion
from tomlkit.exceptions import TOMLKitError

from include.config.constants import CORE_VERSION
from include.config.paths import APPLICATION_ABSPATH, EXTENSION_ROOT
from include.config.validation import (
    ConfigValidationError,
    get_enabled_extensions,
    parse_config_document,
)
from include.extensions.manager import (
    DiscoveredExtension,
    ExtensionDiscoveryError,
    ExtensionLoadError,
    ExtensionManifest,
    ExtensionManifestError,
    discover_extensions,
    parse_extension_manifest,
    resolve_extension_selection,
)
from maintenance.operations.config import write_config_atomically
from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.runtime import enter_server_root

MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
_COPY_CHUNK_BYTES = 1024 * 1024
_SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}").fullmatch
_TRANSACTION_PREFIXES = (
    ".cfms-extension-stage-",
    ".cfms-extension-rollback-",
)
_ALLOWED_COMPRESSIONS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}


@dataclass(frozen=True, slots=True)
class ExtensionRecord:
    manifest: ExtensionManifest
    directory: Path
    enabled: bool
    compatible: bool
    issues: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ExtensionCatalogInspection:
    extensions: tuple[ExtensionRecord, ...]
    activation_error: str | None


@dataclass(frozen=True, slots=True)
class ExtensionPackageInspection:
    package_path: Path
    sha256: str
    manifest: ExtensionManifest


@dataclass(frozen=True, slots=True)
class ExtensionChangeResult:
    action: str
    extension: ExtensionRecord
    package_path: Path | None
    package_sha256: str | None
    enabled_added: tuple[str, ...]
    enabled_removed: tuple[str, ...]
    config_backup_path: Path | None
    changed: bool


def _extension_root(*, mutating: bool) -> tuple[Path, Path]:
    workdir = enter_server_root()
    if not EXTENSION_ROOT.is_dir():
        raise MaintenanceOperationError(
            f"Extension directory not found: {EXTENSION_ROOT}"
        )
    if mutating:
        artifacts = sorted(
            path
            for path in EXTENSION_ROOT.iterdir()
            if path.name.startswith(_TRANSACTION_PREFIXES)
        )
        if artifacts:
            rendered = ", ".join(str(path) for path in artifacts)
            raise MaintenanceOperationError(
                "Unfinished extension transaction artifacts require manual review: "
                f"{rendered}"
            )
    return workdir, EXTENSION_ROOT


def _discover(root: Path) -> dict[str, DiscoveredExtension]:
    try:
        return discover_extensions(root)
    except (ExtensionDiscoveryError, ExtensionManifestError) as exc:
        raise MaintenanceOperationError(str(exc)) from exc


def _managed_extension_identifiers() -> frozenset[str]:
    manifest_path = APPLICATION_ABSPATH.parent / "release-manifest.json"
    if not manifest_path.is_file():
        return frozenset({"builtin"})
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        identifiers = data["managed_extensions"]
    except (KeyError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MaintenanceOperationError(
            f"Unable to read managed extensions from {manifest_path}: {exc}"
        ) from exc
    if not isinstance(identifiers, list) or any(
        not isinstance(identifier, str) for identifier in identifiers
    ):
        raise MaintenanceOperationError(
            f"Release manifest has invalid managed_extensions: {manifest_path}"
        )
    return frozenset(identifiers) | {"builtin"}


def _read_config(
    workdir: Path,
) -> tuple[Path, str, tomlkit.TOMLDocument, tuple[str, ...]]:
    config_path = workdir / "config.toml"
    try:
        source = config_path.read_text(encoding="utf-8")
        document = tomlkit.parse(source)
        enabled = get_enabled_extensions(document)
    except (OSError, TOMLKitError, ConfigValidationError) as exc:
        raise MaintenanceOperationError(f"Unable to read {config_path}: {exc}") from exc
    return config_path, source, document, enabled


def _dependency_issues(
    extension: DiscoveredExtension,
    discovered: dict[str, DiscoveredExtension],
    enabled: set[str],
) -> tuple[str, ...]:
    identifier = extension.manifest.extension.identifier
    issues = []
    for (
        dependency,
        minimum_version,
    ) in extension.manifest.dependencies.extensions.items():
        if dependency == identifier:
            issues.append("declares a self-dependency")
            continue
        installed = discovered.get(dependency)
        if installed is None:
            issues.append(f"dependency {dependency!r} is not installed")
            continue
        try:
            installed_version = PackageVersion(installed.manifest.extension.version)
        except InvalidVersion:
            issues.append(
                f"dependency {dependency!r} has an incomparable version "
                f"{installed.manifest.extension.version!r}"
            )
            continue
        if installed_version < PackageVersion(minimum_version):
            issues.append(
                f"dependency {dependency!r} requires {minimum_version} or newer; "
                f"installed version is {installed.manifest.extension.version}"
            )
        if (
            identifier in enabled
            and dependency != "builtin"
            and dependency not in enabled
        ):
            issues.append(f"dependency {dependency!r} is not enabled")
    return tuple(issues)


def _record(
    extension: DiscoveredExtension,
    discovered: dict[str, DiscoveredExtension],
    enabled: set[str],
) -> ExtensionRecord:
    identifier = extension.manifest.extension.identifier
    minimum = extension.manifest.compatibility.minimum_server_version
    compatible = minimum is None or CORE_VERSION >= minimum
    issues = list(_dependency_issues(extension, discovered, enabled))
    if identifier in enabled and not compatible:
        issues.append(
            f"requires server version {minimum} or newer; current version is "
            f"{CORE_VERSION}"
        )
    return ExtensionRecord(
        manifest=extension.manifest,
        directory=extension.directory,
        enabled=identifier == "builtin" or identifier in enabled,
        compatible=compatible,
        issues=tuple(issues),
    )


def inspect_extensions() -> ExtensionCatalogInspection:
    workdir, root = _extension_root(mutating=False)
    discovered = _discover(root)
    _, _, _, enabled = _read_config(workdir)
    activation_error = None
    try:
        resolve_extension_selection(discovered, enabled)
    except (ExtensionDiscoveryError, ExtensionLoadError) as exc:
        activation_error = str(exc)
    enabled_set = set(enabled)
    records = tuple(
        _record(extension, discovered, enabled_set)
        for _, extension in sorted(discovered.items())
    )
    return ExtensionCatalogInspection(records, activation_error)


def inspect_extension(identifier: str) -> ExtensionRecord:
    catalog = inspect_extensions()
    for extension in catalog.extensions:
        if extension.manifest.extension.identifier == identifier:
            return extension
    raise MaintenanceOperationError(f"Extension {identifier!r} is not installed")


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


def _render_enabled_config(
    document: tomlkit.TOMLDocument,
    enabled: tuple[str, ...],
) -> str:
    document["extensions"]["enabled"] = list(enabled)
    rendered = tomlkit.dumps(document)
    try:
        parse_config_document(rendered)
    except ConfigValidationError as exc:
        raise MaintenanceOperationError(
            f"Updated extension configuration would be invalid: {exc}"
        ) from exc
    return rendered


def _required_extension_order(
    identifier: str,
    discovered: dict[str, DiscoveredExtension],
) -> tuple[str, ...]:
    visiting = []
    visited = set()
    ordered = []

    def visit(current: str) -> None:
        if current in visiting:
            start = visiting.index(current)
            cycle = (*visiting[start:], current)
            raise MaintenanceOperationError(
                "Extension dependency cycle detected: " + " -> ".join(cycle)
            )
        if current in visited:
            return
        extension = discovered.get(current)
        if extension is None:
            parent = visiting[-1] if visiting else identifier
            raise MaintenanceOperationError(
                f"Extension {parent!r} requires extension {current!r}, "
                "but it is not installed"
            )
        visiting.append(current)
        for (
            dependency,
            minimum_version,
        ) in extension.manifest.dependencies.extensions.items():
            installed = discovered.get(dependency)
            if installed is None:
                raise MaintenanceOperationError(
                    f"Extension {current!r} requires extension {dependency!r}, "
                    "but it is not installed"
                )
            try:
                installed_version = PackageVersion(installed.manifest.extension.version)
            except InvalidVersion as exc:
                raise MaintenanceOperationError(
                    f"Extension {dependency!r} has an invalid version "
                    f"{installed.manifest.extension.version!r}"
                ) from exc
            if installed_version < PackageVersion(minimum_version):
                raise MaintenanceOperationError(
                    f"Extension {current!r} requires extension {dependency!r} "
                    f"version {minimum_version} or newer; installed version is "
                    f"{installed.manifest.extension.version}"
                )
            visit(dependency)
        visiting.pop()
        visited.add(current)
        ordered.append(current)

    visit(identifier)
    return tuple(ordered)


def install_extension(
    package_path: str | Path,
    *,
    expected_sha256: str | None = None,
    write: bool = False,
) -> ExtensionChangeResult:
    _, root = _extension_root(mutating=True)
    package, staged, stage = _extract_package(package_path, expected_sha256, root)
    try:
        discovered = _discover(root)
        identifier = staged.manifest.extension.identifier
        if identifier in discovered:
            raise MaintenanceOperationError(
                f"Extension {identifier!r} is already installed; use upgrade instead"
            )
        destination = root / identifier
        if destination.exists() or any(
            child.name.casefold() == identifier.casefold() for child in root.iterdir()
        ):
            raise MaintenanceOperationError(
                f"Extension destination already exists: {destination}"
            )
        installed = DiscoveredExtension(
            manifest=staged.manifest,
            directory=destination,
            entrypoint=destination / "_extension.py",
        )
        candidate_catalog = {**discovered, identifier: installed}
        record = _record(installed, candidate_catalog, set())
        if write:
            try:
                os.replace(stage, destination)
            except OSError as exc:
                raise MaintenanceOperationError(
                    f"Unable to install extension {identifier!r}: {exc}"
                ) from exc
        return ExtensionChangeResult(
            action="install",
            extension=record,
            package_path=package.package_path,
            package_sha256=package.sha256,
            enabled_added=(),
            enabled_removed=(),
            config_backup_path=None,
            changed=True,
        )
    finally:
        if stage.exists():
            shutil.rmtree(stage, ignore_errors=True)


def _compare_upgrade_versions(
    installed: DiscoveredExtension,
    replacement: DiscoveredExtension,
) -> None:
    old_value = installed.manifest.extension.version
    new_value = replacement.manifest.extension.version
    try:
        old_version = PackageVersion(old_value)
        new_version = PackageVersion(new_value)
    except InvalidVersion as exc:
        raise MaintenanceOperationError(
            "Extension upgrades require PEP 440-comparable installed and package "
            f"versions; got {old_value!r} and {new_value!r}"
        ) from exc
    if new_version <= old_version:
        raise MaintenanceOperationError(
            f"Extension upgrade requires a version newer than {old_value}; "
            f"package version is {new_value}"
        )


def _restore_replacement(stage: Path, target: Path, rollback: Path) -> None:
    if target.exists():
        os.replace(target, stage)
    os.replace(rollback, target)


def upgrade_extension(
    package_path: str | Path,
    *,
    expected_sha256: str | None = None,
    write: bool = False,
) -> ExtensionChangeResult:
    workdir, root = _extension_root(mutating=True)
    package, staged, stage = _extract_package(package_path, expected_sha256, root)
    preserve_stage = False
    try:
        discovered = _discover(root)
        identifier = staged.manifest.extension.identifier
        installed = discovered.get(identifier)
        if installed is None:
            raise MaintenanceOperationError(
                f"Extension {identifier!r} is not installed; use install instead"
            )
        if identifier in _managed_extension_identifiers():
            raise MaintenanceOperationError(
                f"Packaged extension {identifier!r} must be upgraded with the server"
            )
        _compare_upgrade_versions(installed, staged)

        config_path, current_source, document, enabled = _read_config(workdir)
        replacement = DiscoveredExtension(
            manifest=staged.manifest,
            directory=installed.directory,
            entrypoint=installed.directory / "_extension.py",
        )
        candidate_catalog = {**discovered, identifier: replacement}
        candidate_enabled = list(enabled)
        enabled_added = []
        if identifier in enabled:
            for required in _required_extension_order(identifier, candidate_catalog):
                if required != "builtin" and required not in candidate_enabled:
                    candidate_enabled.append(required)
                    enabled_added.append(required)
            try:
                resolve_extension_selection(candidate_catalog, candidate_enabled)
            except (ExtensionDiscoveryError, ExtensionLoadError) as exc:
                raise MaintenanceOperationError(str(exc)) from exc
        rendered = current_source
        if tuple(candidate_enabled) != enabled:
            rendered = _render_enabled_config(document, tuple(candidate_enabled))
        record = _record(replacement, candidate_catalog, set(candidate_enabled))
        backup_path = None
        if write:
            rollback = root / (
                f".cfms-extension-rollback-{identifier}-{secrets.token_hex(8)}"
            )
            config_applied = False
            try:
                os.replace(installed.directory, rollback)
                os.replace(stage, installed.directory)
                if rendered != current_source:
                    backup_path = write_config_atomically(
                        config_path, current_source, rendered
                    )
                    config_applied = True
            except (OSError, MaintenanceOperationError) as exc:
                try:
                    if rollback.exists():
                        _restore_replacement(stage, installed.directory, rollback)
                    if config_applied:
                        write_config_atomically(config_path, rendered, current_source)
                except (OSError, MaintenanceOperationError) as rollback_exc:
                    preserve_stage = True
                    raise MaintenanceOperationError(
                        f"Unable to upgrade extension {identifier!r}; rollback also "
                        f"failed: {rollback_exc}"
                    ) from exc
                raise MaintenanceOperationError(
                    f"Unable to upgrade extension {identifier!r}: {exc}"
                ) from exc
            try:
                shutil.rmtree(rollback)
            except OSError as exc:
                raise MaintenanceOperationError(
                    f"Extension {identifier!r} was upgraded, but its rollback "
                    f"directory could not be removed and requires manual review: "
                    f"{rollback} ({exc})"
                ) from exc
        return ExtensionChangeResult(
            action="upgrade",
            extension=record,
            package_path=package.package_path,
            package_sha256=package.sha256,
            enabled_added=tuple(enabled_added),
            enabled_removed=(),
            config_backup_path=backup_path,
            changed=True,
        )
    finally:
        if stage.exists() and not preserve_stage:
            shutil.rmtree(stage, ignore_errors=True)


def _dependent_disable_set(
    identifier: str,
    discovered: dict[str, DiscoveredExtension],
    enabled: tuple[str, ...],
) -> set[str]:
    disabled = {identifier}
    changed = True
    while changed:
        changed = False
        for current in enabled:
            if current in disabled:
                continue
            extension = discovered.get(current)
            if extension is None:
                continue
            dependencies = extension.manifest.dependencies.extensions
            if any(dependency in disabled for dependency in dependencies):
                disabled.add(current)
                changed = True
    return disabled


def _selection_change(
    identifier: str,
    *,
    enable: bool,
    write: bool,
) -> ExtensionChangeResult:
    workdir, root = _extension_root(mutating=True)
    discovered = _discover(root)
    extension = discovered.get(identifier)
    if extension is None:
        raise MaintenanceOperationError(f"Extension {identifier!r} is not installed")
    if identifier == "builtin":
        raise MaintenanceOperationError(
            "The built-in extension is always enabled and cannot be changed"
        )
    config_path, current_source, document, enabled = _read_config(workdir)
    candidate = list(enabled)
    added = []
    removed = []
    if enable:
        for required in _required_extension_order(identifier, discovered):
            if required != "builtin" and required not in candidate:
                candidate.append(required)
                added.append(required)
    else:
        disabled = _dependent_disable_set(identifier, discovered, enabled)
        removed = [current for current in enabled if current in disabled]
        candidate = [current for current in enabled if current not in disabled]
    try:
        resolve_extension_selection(discovered, candidate)
    except (ExtensionDiscoveryError, ExtensionLoadError) as exc:
        raise MaintenanceOperationError(str(exc)) from exc
    changed = tuple(candidate) != enabled
    backup_path = None
    if write and changed:
        rendered = _render_enabled_config(document, tuple(candidate))
        backup_path = write_config_atomically(config_path, current_source, rendered)
    record = _record(extension, discovered, set(candidate))
    return ExtensionChangeResult(
        action="enable" if enable else "disable",
        extension=record,
        package_path=None,
        package_sha256=None,
        enabled_added=tuple(added),
        enabled_removed=tuple(removed),
        config_backup_path=backup_path,
        changed=changed,
    )


def enable_extension(identifier: str, *, write: bool = False) -> ExtensionChangeResult:
    return _selection_change(identifier, enable=True, write=write)


def disable_extension(identifier: str, *, write: bool = False) -> ExtensionChangeResult:
    return _selection_change(identifier, enable=False, write=write)


def uninstall_extension(
    identifier: str, *, write: bool = False
) -> ExtensionChangeResult:
    workdir, root = _extension_root(mutating=True)
    discovered = _discover(root)
    extension = discovered.get(identifier)
    if extension is None:
        raise MaintenanceOperationError(f"Extension {identifier!r} is not installed")
    if identifier in _managed_extension_identifiers():
        raise MaintenanceOperationError(
            f"Packaged extension {identifier!r} cannot be uninstalled"
        )
    config_path, current_source, document, enabled = _read_config(workdir)
    disabled = _dependent_disable_set(identifier, discovered, enabled)
    removed = tuple(current for current in enabled if current in disabled)
    candidate_enabled = tuple(current for current in enabled if current not in disabled)
    candidate_catalog = {
        current: item for current, item in discovered.items() if current != identifier
    }
    try:
        resolve_extension_selection(candidate_catalog, candidate_enabled)
    except (ExtensionDiscoveryError, ExtensionLoadError) as exc:
        raise MaintenanceOperationError(str(exc)) from exc
    rendered = current_source
    if candidate_enabled != enabled:
        rendered = _render_enabled_config(document, candidate_enabled)
    record = _record(extension, discovered, set(enabled))
    backup_path = None
    if write:
        rollback = root / (
            f".cfms-extension-rollback-{identifier}-{secrets.token_hex(8)}"
        )
        config_applied = False
        try:
            os.replace(extension.directory, rollback)
            if rendered != current_source:
                backup_path = write_config_atomically(
                    config_path, current_source, rendered
                )
                config_applied = True
        except (OSError, MaintenanceOperationError) as exc:
            try:
                if rollback.exists():
                    os.replace(rollback, extension.directory)
                if config_applied:
                    write_config_atomically(config_path, rendered, current_source)
            except (OSError, MaintenanceOperationError) as rollback_exc:
                raise MaintenanceOperationError(
                    f"Unable to uninstall extension {identifier!r}; rollback also "
                    f"failed: {rollback_exc}"
                ) from exc
            raise MaintenanceOperationError(
                f"Unable to uninstall extension {identifier!r}: {exc}"
            ) from exc
        try:
            shutil.rmtree(rollback)
        except OSError as exc:
            raise MaintenanceOperationError(
                f"Extension {identifier!r} was uninstalled, but its rollback "
                f"directory could not be removed and requires manual review: "
                f"{rollback} ({exc})"
            ) from exc
    return ExtensionChangeResult(
        action="uninstall",
        extension=record,
        package_path=None,
        package_sha256=None,
        enabled_added=(),
        enabled_removed=removed,
        config_backup_path=backup_path,
        changed=True,
    )
