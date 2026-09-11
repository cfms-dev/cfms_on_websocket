from dataclasses import dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True, slots=True)
class DeploymentSettings:
    format_version: int = 1
    extras: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class DeploymentVersion:
    release_id: str
    version: str
    active: bool


@dataclass(frozen=True, slots=True)
class DeploymentResult:
    action: str
    deployment_root: Path
    active_version: str
    active_release_id: str
    versions: tuple[DeploymentVersion, ...] = ()
    package_sha256: str | None = None


@dataclass(frozen=True, slots=True)
class DeploymentPruneResult:
    deployment_root: Path
    active_version: str
    active_release_id: str
    removed_versions: tuple[DeploymentVersion, ...]


@dataclass(frozen=True, slots=True)
class _Release:
    root: Path
    manifest: dict[str, Any]
    manifest_bytes: bytes
    release_id: str

    @property
    def version(self) -> str:
        return self.manifest["version"]

    @property
    def managed_extensions(self) -> frozenset[str]:
        return frozenset(self.manifest["managed_extensions"])
