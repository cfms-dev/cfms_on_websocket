import os
import secrets
import shutil
from pathlib import Path

from packaging.version import InvalidVersion
from packaging.version import Version as PackageVersion

from include.extensions.manager import (
    DiscoveredExtension,
    ExtensionDiscoveryError,
    ExtensionLoadError,
    resolve_extension_selection,
)
from maintenance.operations.config import write_config_atomically
from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.operations.extensions.catalog import (
    _discover,
    _extension_root,
    _managed_extension_identifiers,
    _read_config,
    _record,
)
from maintenance.operations.extensions.models import ExtensionChangeResult
from maintenance.operations.extensions.packages import _extract_package
from maintenance.operations.extensions.selection import (
    _dependent_disable_set,
    _render_enabled_config,
    _required_extension_order,
)


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
