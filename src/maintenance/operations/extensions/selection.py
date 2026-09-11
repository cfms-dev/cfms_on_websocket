import tomlkit
from packaging.version import InvalidVersion
from packaging.version import Version as PackageVersion

from include.config.validation import (
    ConfigValidationError,
    parse_config_document,
)
from include.extensions.manager import (
    DiscoveredExtension,
)
from maintenance.operations.exceptions import MaintenanceOperationError


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
