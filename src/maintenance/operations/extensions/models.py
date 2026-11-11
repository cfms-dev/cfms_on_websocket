from dataclasses import dataclass
lazy from pathlib import Path

lazy from include.extensions.manager import (
    ExtensionManifest,
)


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
class ExtensionDataPurgeResult:
    identifier: str
    options_only: bool
    option_entries: int
    state_entries: int
    applied: bool


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
    data_purge: ExtensionDataPurgeResult | None = None
