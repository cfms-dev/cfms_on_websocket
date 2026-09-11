import json
from pathlib import Path

import tomlkit
from packaging.version import InvalidVersion
from packaging.version import Version as PackageVersion
from tomlkit.exceptions import TOMLKitError

from include.config import paths
from include.config.constants import CORE_VERSION
from include.config.validation import (
    ConfigValidationError,
    get_enabled_extensions,
)
from include.extensions.manager import (
    DiscoveredExtension,
    ExtensionDiscoveryError,
    ExtensionLoadError,
    ExtensionManifestError,
    discover_extensions,
    resolve_extension_selection,
)
from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.operations.extensions.models import (
    ExtensionCatalogInspection,
    ExtensionRecord,
)
from maintenance.runtime import enter_server_root

_TRANSACTION_PREFIXES = (
    ".cfms-extension-stage-",
    ".cfms-extension-rollback-",
)


def _extension_root(*, mutating: bool) -> tuple[Path, Path]:
    workdir = enter_server_root()
    if not paths.EXTENSION_ROOT.is_dir():
        raise MaintenanceOperationError(
            f"Extension directory not found: {paths.EXTENSION_ROOT}"
        )
    if mutating:
        artifacts = sorted(
            path
            for path in paths.EXTENSION_ROOT.iterdir()
            if path.name.startswith(_TRANSACTION_PREFIXES)
        )
        if artifacts:
            rendered = ", ".join(str(path) for path in artifacts)
            raise MaintenanceOperationError(
                "Unfinished extension transaction artifacts require manual review: "
                f"{rendered}"
            )
    return workdir, paths.EXTENSION_ROOT


def _discover(root: Path) -> dict[str, DiscoveredExtension]:
    try:
        return discover_extensions(root)
    except (ExtensionDiscoveryError, ExtensionManifestError) as exc:
        raise MaintenanceOperationError(str(exc)) from exc


def _managed_extension_identifiers() -> frozenset[str]:
    manifest_path = paths.PROJECT_ABSPATH / "release-manifest.json"
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
