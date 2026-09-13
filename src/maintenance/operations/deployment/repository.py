import hashlib
import json
import os
import secrets
import shutil
from dataclasses import asdict
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from packaging.specifiers import InvalidSpecifier, SpecifierSet

from include.extensions.manager import ExtensionDiscoveryError, discover_extensions
from maintenance.operations.deployment.constants import (
    _COPY_CHUNK_BYTES,
    _EXTENSION_IDENTIFIER_PATTERN,
    _OPERATOR_OWNED_PREFIXES,
    _REQUIRED_RELEASE_FILES,
    _SHA256_PATTERN,
    _VERSION_PATTERN,
    MAX_ARCHIVE_MEMBERS,
    MAX_MANIFEST_BYTES,
    MAX_STATE_BYTES,
    MAX_STORED_RELEASES,
)
from maintenance.operations.deployment.models import DeploymentSettings, _Release
from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.operations.extensions.packages import (
    _validate_extension_root_size,
    _validate_extension_tree,
)


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(_COPY_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_write(path: Path, contents: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(8)}")
    try:
        with temporary.open("xb") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_copy(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp-{secrets.token_hex(8)}")
    try:
        with source.open("rb") as input_file, temporary.open("xb") as output_file:
            shutil.copyfileobj(input_file, output_file, length=_COPY_CHUNK_BYTES)
            output_file.flush()
            os.fsync(output_file.fileno())
        shutil.copymode(source, temporary)
        os.replace(temporary, target)
    finally:
        temporary.unlink(missing_ok=True)


def _atomic_copytree(source: Path, target: Path) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp-{secrets.token_hex(8)}")
    try:
        _validate_extension_tree(source)
        shutil.copytree(source, temporary, symlinks=True)
        _validate_extension_tree(temporary)
        os.rename(temporary, target)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)


def _read_limited_bytes(path: Path, *, maximum: int, description: str) -> bytes:
    try:
        with path.open("rb") as input_file:
            contents = input_file.read(maximum + 1)
    except OSError as exc:
        raise MaintenanceOperationError(
            f"Unable to read {description} {path}: {exc}"
        ) from exc
    if len(contents) > maximum:
        raise MaintenanceOperationError(
            f"{description.capitalize()} exceeds the {maximum}-byte limit: {path}"
        )
    return contents


def _project_root(value: str | Path) -> Path:
    root = Path(value).expanduser().resolve()
    if (root / "pyproject.toml").is_file() and (
        (root / "src" / "main.py").is_file()
        or (root / "src" / ".maintenance" / "transaction.json").is_file()
    ):
        project_root = root
    elif (root.parent / "pyproject.toml").is_file() and (
        (root / "main.py").is_file()
        or (root / ".maintenance" / "transaction.json").is_file()
    ):
        project_root = root.parent
    else:
        raise MaintenanceOperationError(
            f"Deployment root must contain pyproject.toml and src/main.py: {root}"
        )
    if (
        (project_root / "deployment.json").exists()
        or (project_root / "shared").exists()
        or (project_root / "releases").exists()
    ):
        raise MaintenanceOperationError(
            "The unreleased releases/shared deployment layout is not supported"
        )
    if (project_root / ".git").exists():
        raise MaintenanceOperationError(
            "Versioned deployment commands do not support source repository "
            "checkouts; update the repository with Git and run database "
            "maintenance explicitly"
        )
    return project_root


def _maintenance_root(project_root: Path) -> Path:
    return project_root / "src" / ".maintenance"


def _settings_path(project_root: Path) -> Path:
    return _maintenance_root(project_root) / "settings.json"


def _load_settings(project_root: Path) -> DeploymentSettings:
    path = _settings_path(project_root)
    if not path.exists():
        return DeploymentSettings()
    try:
        data = json.loads(
            _read_limited_bytes(
                path,
                maximum=MAX_STATE_BYTES,
                description="deployment settings",
            )
        )
        settings = DeploymentSettings(
            format_version=data["format_version"],
            extras=tuple(data.get("extras", ())),
        )
    except (KeyError, OSError, TypeError, UnicodeError, json.JSONDecodeError) as exc:
        raise MaintenanceOperationError(f"Unable to read {path}: {exc}") from exc
    if settings.format_version != 1 or any(
        not isinstance(extra, str) or not extra for extra in settings.extras
    ):
        raise MaintenanceOperationError(f"Invalid deployment settings: {path}")
    return settings


def _write_settings(project_root: Path, settings: DeploymentSettings) -> None:
    _atomic_write(
        _settings_path(project_root),
        (json.dumps(asdict(settings), indent=2, sort_keys=True) + "\n").encode(),
    )


def _archive_parts(name: str) -> tuple[str, ...]:
    if not name or "\\" in name or "\x00" in name:
        raise MaintenanceOperationError(f"Unsafe release archive path: {name!r}")
    if PureWindowsPath(name).drive or PurePosixPath(name).is_absolute():
        raise MaintenanceOperationError(f"Unsafe release archive path: {name!r}")
    parts = name.removesuffix("/").split("/")
    if not parts or any(
        part in {"", ".", ".."} or ":" in part or part.endswith((" ", "."))
        for part in parts
    ):
        raise MaintenanceOperationError(f"Unsafe release archive path: {name!r}")
    return tuple(parts)


def _parse_manifest(contents: bytes, *, top_level: str | None = None) -> dict[str, Any]:
    if len(contents) > MAX_MANIFEST_BYTES:
        raise MaintenanceOperationError(
            f"Release manifest exceeds the {MAX_MANIFEST_BYTES}-byte limit"
        )
    try:
        manifest = json.loads(contents)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MaintenanceOperationError("Release manifest is invalid") from exc
    if not isinstance(manifest, dict):
        raise MaintenanceOperationError("Release manifest metadata is invalid")
    version = manifest.get("version")
    managed_extensions = manifest.get("managed_extensions")
    expected_files = manifest.get("files")
    requires_python = manifest.get("requires_python")
    if not isinstance(requires_python, str):
        raise MaintenanceOperationError("Release manifest metadata is invalid")
    try:
        SpecifierSet(requires_python)
    except (InvalidSpecifier, TypeError) as exc:
        raise MaintenanceOperationError("Release manifest metadata is invalid") from exc
    if (
        manifest.get("format_version") != 1
        or manifest.get("product") != "cfms-on-websocket"
        or not isinstance(version, str)
        or _VERSION_PATTERN(version) is None
        or (top_level is not None and top_level != f"cfms-on-websocket-{version}")
        or not isinstance(expected_files, dict)
        or len(expected_files) > MAX_ARCHIVE_MEMBERS
        or not isinstance(managed_extensions, list)
        or any(
            not isinstance(identifier, str)
            or _EXTENSION_IDENTIFIER_PATTERN(identifier) is None
            for identifier in managed_extensions
        )
        or len(managed_extensions) != len(set(managed_extensions))
    ):
        raise MaintenanceOperationError("Release manifest metadata is invalid")
    for relative_path, digest in expected_files.items():
        if not isinstance(relative_path, str):
            raise MaintenanceOperationError(
                f"Release manifest contains an invalid path or digest: {relative_path!r}"
            )
        path_parts = _archive_parts(relative_path)
        if (
            not path_parts
            or not isinstance(digest, str)
            or _SHA256_PATTERN(digest) is None
            or relative_path.startswith(_OPERATOR_OWNED_PREFIXES)
            or "__pycache__" in path_parts
            or PurePosixPath(relative_path).suffix in {".pyc", ".pyo"}
        ):
            raise MaintenanceOperationError(
                f"Release manifest contains an invalid path or digest: {relative_path!r}"
            )
    missing = _REQUIRED_RELEASE_FILES - set(expected_files)
    if missing:
        raise MaintenanceOperationError(
            "Release package is missing required files: " + ", ".join(sorted(missing))
        )
    return manifest


def _release_directories(expected_files: dict[str, Any]) -> set[str]:
    return {
        parent.as_posix()
        for relative_path in expected_files
        for parent in PurePosixPath(relative_path).parents
        if parent != PurePosixPath(".")
    }


def _release_from_tree(root: Path, *, exact: bool) -> _Release:
    manifest_path = root / "release-manifest.json"
    if manifest_path.is_symlink() or manifest_path.is_junction():
        raise MaintenanceOperationError(
            f"Release manifest is not a regular file: {manifest_path}"
        )
    contents = _read_limited_bytes(
        manifest_path,
        maximum=MAX_MANIFEST_BYTES,
        description="release manifest",
    )
    manifest = _parse_manifest(contents)
    expected_files = manifest["files"]
    if exact:
        expected_directories = _release_directories(expected_files)
        remaining = set(expected_files)
        pending = [root]
        while pending:
            directory = pending.pop()
            for path in directory.iterdir():
                if path.is_symlink() or path.is_junction():
                    raise MaintenanceOperationError(
                        "Release archive contents do not match its manifest"
                    )
                if path == manifest_path:
                    continue
                relative_path = path.relative_to(root).as_posix()
                if path.is_dir():
                    if relative_path not in expected_directories:
                        raise MaintenanceOperationError(
                            "Release archive contents do not match its manifest"
                        )
                    pending.append(path)
                    continue
                if not path.is_file() or relative_path not in remaining:
                    raise MaintenanceOperationError(
                        "Release archive contents do not match its manifest"
                    )
                remaining.remove(relative_path)
        if remaining:
            raise MaintenanceOperationError(
                "Release archive contents do not match its manifest"
            )
    for relative_path, expected in expected_files.items():
        path = root / Path(relative_path)
        current = path
        while current != root:
            if current.is_symlink() or current.is_junction():
                raise MaintenanceOperationError(
                    f"Release file is not a regular file: {relative_path}"
                )
            current = current.parent
        if not path.is_file() or _hash_file(path) != expected.lower():
            raise MaintenanceOperationError(
                f"Release file failed SHA-256 verification: {relative_path}"
            )
    return _Release(
        root,
        manifest,
        contents,
        hashlib.sha256(contents).hexdigest(),
    )


def _active_release(project_root: Path) -> _Release:
    if not (project_root / "release-manifest.json").is_file():
        raise MaintenanceOperationError(
            "Versioned deployment commands require an active "
            "release-manifest.json; pre-manifest releases are not supported"
        )
    return _release_from_tree(project_root, exact=False)


def _version_root(project_root: Path, release_id: str) -> Path:
    return _maintenance_root(project_root) / "versions" / release_id


def _verified_stored_release(root: Path) -> _Release:
    release = _release_from_tree(root, exact=False)
    expected_directories = _release_directories(release.manifest["files"])
    maximum_entries = (
        len(release.manifest["files"])
        + len(expected_directories)
        + MAX_ARCHIVE_MEMBERS
        + 1
    )
    entry_count = 0
    cache_paths = []
    pending = [root]
    while pending:
        directory = pending.pop()
        for path in directory.iterdir():
            entry_count += 1
            if entry_count > maximum_entries:
                raise MaintenanceOperationError(
                    f"Stored release contains more than {maximum_entries} entries: "
                    f"{root}"
                )
            if path.is_symlink() or path.is_junction():
                raise MaintenanceOperationError(
                    f"Stored release contains a filesystem link: {path}"
                )
            if path.is_dir():
                pending.append(path)
                if path.name == "__pycache__":
                    cache_paths.append(path)
            elif not path.is_file():
                raise MaintenanceOperationError(
                    f"Stored release contains an unsupported filesystem entry: {path}"
                )
    for cache_path in sorted(
        cache_paths,
        key=lambda path: len(path.parts),
        reverse=True,
    ):
        if not cache_path.exists():
            continue
        try:
            shutil.rmtree(cache_path)
        except OSError as exc:
            raise MaintenanceOperationError(
                f"Unable to remove generated Python bytecode cache {cache_path}: {exc}"
            ) from exc
        parent = cache_path.parent
        while (
            parent != root
            and parent.relative_to(root).as_posix() not in expected_directories
        ):
            try:
                parent.rmdir()
            except OSError:
                break
            parent = parent.parent
    return _release_from_tree(root, exact=True)


def _stored_releases(project_root: Path) -> tuple[tuple[Path, _Release], ...]:
    versions_root = _maintenance_root(project_root) / "versions"
    if versions_root.is_symlink() or versions_root.is_junction():
        raise MaintenanceOperationError(
            f"Stored release root is not a regular directory: {versions_root}"
        )
    if not versions_root.exists():
        return ()
    if not versions_root.is_dir():
        raise MaintenanceOperationError(
            f"Stored release root is not a regular directory: {versions_root}"
        )
    try:
        resolved_versions_root = versions_root.resolve(strict=True)
        resolved_versions_root.relative_to(project_root)
    except (OSError, ValueError) as exc:
        raise MaintenanceOperationError(
            f"Stored release root escapes the deployment: {versions_root}"
        ) from exc
    try:
        stored_paths = []
        for path in versions_root.iterdir():
            if _SHA256_PATTERN(path.name) is None:
                continue
            stored_paths.append(path)
            if len(stored_paths) > MAX_STORED_RELEASES:
                raise MaintenanceOperationError(
                    f"Deployment contains more than {MAX_STORED_RELEASES} "
                    "stored releases"
                )
        stored_paths.sort()
    except MaintenanceOperationError:
        raise
    except OSError as exc:
        raise MaintenanceOperationError(
            f"Unable to inspect stored release root {versions_root}: {exc}"
        ) from exc

    releases = []
    for path in stored_paths:
        if not path.is_dir() or path.is_symlink() or path.is_junction():
            raise MaintenanceOperationError(
                f"Stored release path is not a regular directory: {path}"
            )
        try:
            if path.resolve(strict=True).parent != resolved_versions_root:
                raise MaintenanceOperationError(
                    f"Stored release path escapes its version root: {path}"
                )
        except OSError as exc:
            raise MaintenanceOperationError(
                f"Unable to resolve stored release path {path}: {exc}"
            ) from exc
        release = _verified_stored_release(path / "release")
        if path.name != release.release_id:
            raise MaintenanceOperationError(
                f"Stored release does not match its directory: {path}"
            )
        releases.append((path, release))
    return tuple(releases)


def _snapshot_release(project_root: Path, release: _Release) -> Path:
    version_root = _version_root(project_root, release.release_id)
    snapshot = version_root / "release"
    if snapshot.exists():
        existing = _verified_stored_release(snapshot)
        if existing.release_id != release.release_id:
            raise MaintenanceOperationError(
                f"Stored release does not match its directory: {version_root}"
            )
        return snapshot

    temporary = version_root.with_name(
        f".{release.release_id}.tmp-{secrets.token_hex(8)}"
    )
    temporary_release = temporary / "release"
    temporary_release.mkdir(parents=True)
    try:
        for relative_path in release.manifest["files"]:
            source = release.root / Path(relative_path)
            target = temporary_release / Path(relative_path)
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
        (temporary_release / "release-manifest.json").write_bytes(
            release.manifest_bytes
        )
        _release_from_tree(temporary_release, exact=True)
        version_root.parent.mkdir(parents=True, exist_ok=True)
        os.replace(temporary, version_root)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise
    return snapshot


def _discover(root: Path) -> dict[str, Any]:
    try:
        extension_root = root / "src" / "include" / "extensions"
        _validate_extension_root_size(extension_root)
        return discover_extensions(extension_root)
    except (OSError, ExtensionDiscoveryError) as exc:
        raise MaintenanceOperationError(str(exc)) from exc


def _snapshot_state(project_root: Path, release: _Release) -> None:
    version_root = _version_root(project_root, release.release_id)
    state = version_root / "state"
    temporary = version_root / f".state-{secrets.token_hex(8)}"
    extensions = temporary / "extensions"
    extensions.mkdir(parents=True)
    try:
        config_path = project_root / "src" / "config.toml"
        shutil.copy2(config_path, temporary / "config.toml")
        for identifier, extension in _discover(project_root).items():
            if identifier not in release.managed_extensions:
                _validate_extension_tree(extension.directory)
                shutil.copytree(
                    extension.directory,
                    extensions / extension.directory.name,
                    symlinks=True,
                )
                _validate_extension_tree(extensions / extension.directory.name)
        old = version_root / f".state-old-{secrets.token_hex(8)}"
        moved_old_state = False
        try:
            if state.exists():
                os.replace(state, old)
                moved_old_state = True
            os.replace(temporary, state)
        except Exception:
            if moved_old_state and not state.exists():
                os.replace(old, state)
            raise
        shutil.rmtree(old, ignore_errors=True)
    except Exception:
        shutil.rmtree(temporary, ignore_errors=True)
        raise


def _remove_active_release(project_root: Path, release: _Release) -> None:
    catalog = _discover(project_root)
    for identifier, extension in catalog.items():
        if identifier not in release.managed_extensions:
            shutil.rmtree(extension.directory)
    for relative_path in release.manifest["files"]:
        path = project_root / Path(relative_path)
        if path.is_file():
            path.unlink()
    (project_root / "release-manifest.json").unlink(missing_ok=True)
    _remove_empty_release_directories(project_root, release.manifest["files"])


def _remove_empty_release_directories(
    project_root: Path,
    relative_paths,
) -> None:
    maintenance_root = _maintenance_root(project_root)
    candidates = set()
    for relative_path in relative_paths:
        parent = (project_root / Path(relative_path)).parent
        while parent != project_root and not parent.is_relative_to(maintenance_root):
            candidates.add(parent)
            parent = parent.parent
    for path in sorted(candidates, key=lambda item: len(item.parts), reverse=True):
        try:
            path.rmdir()
        except OSError:
            pass


def _copy_release_to_active(project_root: Path, release: _Release) -> None:
    for relative_path in release.manifest["files"]:
        source = release.root / Path(relative_path)
        target = project_root / Path(relative_path)
        if target.exists():
            raise MaintenanceOperationError(
                f"New release conflicts with an operator-owned path: {target}"
            )
        _atomic_copy(source, target)
    _atomic_copy(
        release.root / "release-manifest.json",
        project_root / "release-manifest.json",
    )


def _copy_state_extensions(project_root: Path, release: _Release) -> None:
    state_root = (
        _version_root(project_root, release.release_id) / "state" / "extensions"
    )
    target_root = project_root / "src" / "include" / "extensions"
    target_root.mkdir(parents=True, exist_ok=True)
    if not state_root.is_dir():
        return
    try:
        _validate_extension_root_size(state_root)
        source_catalog = discover_extensions(state_root)
    except (OSError, ExtensionDiscoveryError) as exc:
        raise MaintenanceOperationError(str(exc)) from exc
    target_catalog = _discover(project_root)
    for identifier, extension in source_catalog.items():
        if identifier in release.managed_extensions or identifier in target_catalog:
            raise MaintenanceOperationError(
                f"Third-party extension {identifier!r} conflicts with target release"
            )
        target = target_root / extension.directory.name
        if target.exists():
            raise MaintenanceOperationError(
                f"Third-party extension directory conflicts with target: {target}"
            )
        _atomic_copytree(extension.directory, target)
    _discover(project_root)


def _archive_active(project_root: Path, release: _Release) -> None:
    _snapshot_release(project_root, release)
    _snapshot_state(project_root, release)
    _remove_active_release(project_root, release)


def _stored_release(project_root: Path, release_id: str) -> _Release:
    matches = [
        release
        for _, release in _stored_releases(project_root)
        if release.release_id.startswith(release_id.lower())
    ]
    if not matches:
        raise MaintenanceOperationError(f"Stored release not found: {release_id}")
    if len(matches) != 1:
        raise MaintenanceOperationError(f"Release ID prefix is ambiguous: {release_id}")
    return matches[0]
