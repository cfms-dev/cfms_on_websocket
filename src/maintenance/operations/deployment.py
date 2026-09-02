import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import tarfile
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.script.revision import RangeNotAncestorError, ResolutionError
from alembic.util.exc import CommandError
from packaging.specifiers import InvalidSpecifier, SpecifierSet
from packaging.version import Version
from sqlalchemy.exc import SQLAlchemyError

from alembic import command
from include.config.validation import parse_config_document
from include.database.engine import create_database_engine
from include.extensions.manager import ExtensionDiscoveryError, discover_extensions
from include.runtime_lock import RuntimeLockError, server_runtime_lock
from maintenance.operations.config import sync_config_template
from maintenance.operations.exceptions import MaintenanceOperationError

MAX_PACKAGE_BYTES = 64 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_ARCHIVE_MEMBERS = 4096
_COPY_CHUNK_BYTES = 1024 * 1024
_SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}").fullmatch
_VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+").fullmatch
_EXTENSION_IDENTIFIER_PATTERN = re.compile(r"[a-z][a-z0-9_]{0,254}").fullmatch
_ALLOWED_ZIP_COMPRESSIONS = {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}
_REQUIRED_RELEASE_FILES = {
    "pyproject.toml",
    "uv.lock",
    "src/alembic.ini",
    "src/config.toml.sample",
    "src/main.py",
}
_OPERATOR_OWNED_PREFIXES = (
    "src/.maintenance/",
    "src/content/files/",
    "src/content/logs/",
)


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
        data = json.loads(path.read_text(encoding="utf-8"))
        settings = DeploymentSettings(
            format_version=data["format_version"],
            extras=tuple(data.get("extras", ())),
        )
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
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


def _expected_digest(
    package_path: Path,
    expected_sha256: str | None,
    checksums_path: str | Path | None,
) -> str:
    if (expected_sha256 is None) == (checksums_path is None):
        raise MaintenanceOperationError(
            "Choose exactly one package digest source: --sha256 or --checksums"
        )
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


def _parse_manifest(contents: bytes, *, top_level: str | None = None) -> dict[str, Any]:
    try:
        manifest = json.loads(contents)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise MaintenanceOperationError("Release manifest is invalid") from exc
    version = manifest.get("version")
    managed_extensions = manifest.get("managed_extensions")
    expected_files = manifest.get("files")
    try:
        SpecifierSet(manifest.get("requires_python", ""))
    except (InvalidSpecifier, TypeError) as exc:
        raise MaintenanceOperationError("Release manifest metadata is invalid") from exc
    if (
        manifest.get("format_version") != 1
        or manifest.get("product") != "cfms-on-websocket"
        or not isinstance(version, str)
        or _VERSION_PATTERN(version) is None
        or (top_level is not None and top_level != f"cfms-on-websocket-{version}")
        or not isinstance(expected_files, dict)
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
        if (
            not isinstance(relative_path, str)
            or not _archive_parts(relative_path)
            or not isinstance(digest, str)
            or _SHA256_PATTERN(digest) is None
            or relative_path.startswith(_OPERATOR_OWNED_PREFIXES)
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


def _release_from_tree(root: Path, *, exact: bool) -> _Release:
    manifest_path = root / "release-manifest.json"
    try:
        contents = manifest_path.read_bytes()
    except OSError as exc:
        raise MaintenanceOperationError(
            f"Release is missing release-manifest.json: {root}"
        ) from exc
    manifest = _parse_manifest(contents)
    expected_files = manifest["files"]
    for relative_path, expected in expected_files.items():
        path = root / Path(relative_path)
        if not path.is_file() or _hash_file(path) != expected.lower():
            raise MaintenanceOperationError(
                f"Release file failed SHA-256 verification: {relative_path}"
            )
    if exact:
        actual = {
            path.relative_to(root).as_posix()
            for path in root.rglob("*")
            if path.is_file() and path != manifest_path
        }
        if actual != set(expected_files):
            raise MaintenanceOperationError(
                "Release archive contents do not match its manifest"
            )
    return _Release(
        root,
        manifest,
        contents,
        hashlib.sha256(contents).hexdigest(),
    )


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
    if actual != expected:
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


def _active_release(project_root: Path) -> _Release:
    if not (project_root / "release-manifest.json").is_file():
        raise MaintenanceOperationError(
            "Versioned deployment commands require an active "
            "release-manifest.json; pre-manifest releases are not supported"
        )
    return _release_from_tree(project_root, exact=False)


def _version_root(project_root: Path, release_id: str) -> Path:
    return _maintenance_root(project_root) / "versions" / release_id


def _snapshot_release(project_root: Path, release: _Release) -> Path:
    version_root = _version_root(project_root, release.release_id)
    snapshot = version_root / "release"
    if snapshot.exists():
        existing = _release_from_tree(snapshot, exact=True)
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
        return discover_extensions(root / "src" / "include" / "extensions")
    except ExtensionDiscoveryError as exc:
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
                shutil.copytree(
                    extension.directory, extensions / extension.directory.name
                )
        old = version_root / f".state-old-{secrets.token_hex(8)}"
        if state.exists():
            os.replace(state, old)
        os.replace(temporary, state)
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
    for path in sorted(project_root.rglob("*"), reverse=True):
        if path.is_dir() and path != _maintenance_root(project_root):
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
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, target)
    shutil.copy2(release.root / "release-manifest.json", project_root)


def _copy_state_extensions(project_root: Path, release: _Release) -> None:
    state_root = (
        _version_root(project_root, release.release_id) / "state" / "extensions"
    )
    target_root = project_root / "src" / "include" / "extensions"
    target_root.mkdir(parents=True, exist_ok=True)
    if not state_root.is_dir():
        return
    try:
        source_catalog = discover_extensions(state_root)
    except ExtensionDiscoveryError as exc:
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
        shutil.copytree(extension.directory, target)
    _discover(project_root)


def _archive_active(project_root: Path, release: _Release) -> None:
    _snapshot_release(project_root, release)
    _snapshot_state(project_root, release)
    _remove_active_release(project_root, release)


def _stored_release(project_root: Path, release_id: str) -> _Release:
    versions_root = _maintenance_root(project_root) / "versions"
    matches = (
        [
            path
            for path in versions_root.iterdir()
            if path.is_dir() and path.name.startswith(release_id.lower())
        ]
        if versions_root.is_dir()
        else []
    )
    if not matches:
        raise MaintenanceOperationError(f"Stored release not found: {release_id}")
    if len(matches) != 1:
        raise MaintenanceOperationError(f"Release ID prefix is ambiguous: {release_id}")
    return _release_from_tree(matches[0] / "release", exact=True)


def _run(command_line: list[str], *, cwd: Path) -> None:
    # Callers construct uv argv sequences; no argument is interpreted by a shell.
    result = subprocess.run(  # nosemgrep: python.lang.security.audit.dangerous-subprocess-use-audit
        command_line,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=False,
        shell=False,
    )
    if result.returncode:
        output = "\n".join(
            part.strip() for part in (result.stdout, result.stderr) if part.strip()
        )
        raise MaintenanceOperationError(
            f"Command failed with exit code {result.returncode}: "
            + " ".join(command_line)
            + (f"\n{output}" if output else "")
        )


def _sync_environment(project_root: Path, settings: DeploymentSettings) -> None:
    uv = shutil.which("uv")
    if uv is None:
        raise MaintenanceOperationError("uv is required to switch a release")
    command_line = [
        uv,
        "sync",
        "--project",
        str(project_root),
        "--locked",
        "--no-dev",
    ]
    for extra in settings.extras:
        command_line.extend(("--extra", extra))
    _run(command_line, cwd=project_root)
    requirements = _maintenance_root(project_root) / "requirements.lock"
    if requirements.is_file() and requirements.stat().st_size:
        python = (
            project_root / ".venv" / "Scripts" / "python.exe"
            if os.name == "nt"
            else project_root / ".venv" / "bin" / "python"
        )
        _run(
            [
                uv,
                "pip",
                "install",
                "--python",
                str(python),
                "--requirements",
                str(requirements),
                "--require-hashes",
                "--strict",
            ],
            cwd=project_root,
        )


def _alembic(release: _Release, connection=None) -> tuple[Config, ScriptDirectory, str]:
    config = Config(str(release.root / "src" / "alembic.ini"))
    config.set_main_option("script_location", str(release.root / "src" / "alembic"))
    if connection is not None:
        config.attributes["connection"] = connection
    scripts = ScriptDirectory.from_config(config)
    heads = tuple(scripts.get_heads())
    if len(heads) != 1:
        raise MaintenanceOperationError(
            "A release must contain exactly one Alembic head"
        )
    return config, scripts, heads[0]


def _database_engine(project_root: Path):
    config_path = project_root / "src" / "config.toml"
    try:
        document = parse_config_document(config_path.read_text(encoding="utf-8"))
        database = dict(document["database"])
        if database.get("type") == "sqlite":
            database_path = Path(database["file"])
            if database_path != Path(":memory:") and not database_path.is_absolute():
                database["file"] = str(project_root / "src" / database_path)
        return create_database_engine(database)
    except Exception as exc:
        raise MaintenanceOperationError(
            f"Unable to open the configured database: {exc}"
        ) from exc


def _current_revision(connection) -> str | None:
    heads = tuple(MigrationContext.configure(connection).get_current_heads())
    if len(heads) > 1:
        raise MaintenanceOperationError(
            "Database has multiple Alembic heads: " + ", ".join(heads)
        )
    return heads[0] if heads else None


def _is_ancestor(scripts: ScriptDirectory, lower: str, upper: str) -> bool:
    if lower == upper:
        return True
    try:
        revisions = tuple(scripts.iterate_revisions(upper, lower, inclusive=True))
        identifiers = {revision.revision for revision in revisions}
        return lower in identifiers and upper in identifiers
    except RangeNotAncestorError, ResolutionError:
        return False


def _upgrade_database(project_root: Path, source: _Release, target: _Release) -> None:
    engine = _database_engine(project_root)
    try:
        with engine.begin() as connection:
            target_config, target_scripts, target_head = _alembic(target, connection)
            _, _, source_head = _alembic(source)
            if not _is_ancestor(target_scripts, source_head, target_head):
                raise MaintenanceOperationError(
                    f"Target Alembic head {target_head} does not descend from {source_head}"
                )
            current = _current_revision(connection)
            if current is None:
                raise MaintenanceOperationError(
                    "Database has no Alembic revision; initialize it with "
                    "maintain database upgrade before switching releases"
                )
            if current != source_head:
                raise MaintenanceOperationError(
                    f"Database revision is {current}; active release expects {source_head}"
                )
            if source_head != target_head:
                command.upgrade(target_config, target_head)
            if _current_revision(connection) != target_head:
                raise MaintenanceOperationError(
                    f"Database did not reach target revision {target_head}"
                )
    except (CommandError, OSError, SQLAlchemyError) as exc:
        raise MaintenanceOperationError(f"Database upgrade failed: {exc}") from exc
    finally:
        engine.dispose()


def _downgrade_database(project_root: Path, source: _Release, target: _Release) -> None:
    engine = _database_engine(project_root)
    try:
        with engine.begin() as connection:
            source_config, source_scripts, source_head = _alembic(source, connection)
            _, _, target_head = _alembic(target)
            if not _is_ancestor(source_scripts, target_head, source_head):
                raise MaintenanceOperationError(
                    f"Target Alembic head {target_head} is not reachable from {source_head}"
                )
            current = _current_revision(connection)
            if current != source_head:
                raise MaintenanceOperationError(
                    f"Database revision is {current or 'unversioned'}; "
                    f"active release expects {source_head}"
                )
            if source_head != target_head:
                command.downgrade(source_config, target_head)
            if _current_revision(connection) != target_head:
                raise MaintenanceOperationError(
                    f"Database did not reach target revision {target_head}"
                )
    except (CommandError, OSError, SQLAlchemyError) as exc:
        raise MaintenanceOperationError(f"Database downgrade failed: {exc}") from exc
    finally:
        engine.dispose()


def _transaction_path(project_root: Path) -> Path:
    return _maintenance_root(project_root) / "transaction.json"


def _write_transaction(project_root: Path, data: dict[str, Any]) -> None:
    _atomic_write(
        _transaction_path(project_root),
        (json.dumps(data, indent=2, sort_keys=True) + "\n").encode(),
    )


def _load_transaction(project_root: Path) -> dict[str, Any]:
    path = _transaction_path(project_root)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MaintenanceOperationError(f"Unable to read {path}: {exc}") from exc
    if data.get("action") not in {"upgrade", "downgrade"}:
        raise MaintenanceOperationError(f"Invalid deployment transaction: {path}")
    return data


def _restore_active(
    project_root: Path,
    source: _Release,
    failed_release: _Release | None = None,
) -> None:
    try:
        current = _active_release(project_root)
    except MaintenanceOperationError:
        current = None
    if current is not None and current.release_id == source.release_id:
        return
    if current is not None and current.release_id != source.release_id:
        _remove_active_release(project_root, current)
    elif current is None and failed_release is not None:
        for relative_path, expected_digest in failed_release.manifest["files"].items():
            path = project_root / Path(relative_path)
            if path.is_file() and _hash_file(path) == expected_digest:
                path.unlink()
        (project_root / "release-manifest.json").unlink(missing_ok=True)
        for path in sorted(project_root.rglob("*"), reverse=True):
            if path.is_dir() and path != _maintenance_root(project_root):
                try:
                    path.rmdir()
                except OSError:
                    pass
    if not (project_root / "release-manifest.json").exists():
        _copy_release_to_active(project_root, source)
    state = _version_root(project_root, source.release_id) / "state"
    _atomic_write(
        project_root / "src" / "config.toml",
        (state / "config.toml").read_bytes(),
    )
    _copy_state_extensions(project_root, source)


def _activate_upgrade(
    project_root: Path,
    source: _Release,
    target: _Release,
    settings: DeploymentSettings,
) -> None:
    _archive_active(project_root, source)
    _copy_release_to_active(project_root, target)
    _copy_state_extensions(project_root, source)
    sync_config_template(
        project_root / "src" / "config.toml.sample",
        write=True,
    )
    _snapshot_state(project_root, target)
    _sync_environment(project_root, settings)


def upgrade_deployment(
    package: str | Path,
    deployment_root: str | Path,
    *,
    expected_sha256: str | None = None,
    checksums_path: str | Path | None = None,
    backup_confirmed: bool = False,
    extras: tuple[str, ...] | None = None,
    requirements_lock: str | Path | None = None,
) -> DeploymentResult:
    project_root = _project_root(deployment_root)
    transaction_path = _transaction_path(project_root)
    if transaction_path.exists():
        raise MaintenanceOperationError(
            f"Resume the unfinished deployment transaction first: {transaction_path}"
        )
    source = _active_release(project_root)
    try:
        lock = server_runtime_lock(project_root / "src").acquire()
    except RuntimeLockError as exc:
        raise MaintenanceOperationError(str(exc)) from exc
    stage = None
    database_started = False
    try:
        staged, package_digest, stage = _stage_release(
            package,
            project_root,
            expected_sha256=expected_sha256,
            checksums_path=checksums_path,
        )
        if staged.release_id == source.release_id:
            raise MaintenanceOperationError("The supplied release is already active")
        if Version(staged.version) < Version(source.version):
            raise MaintenanceOperationError(
                "Use deployment downgrade to activate an older stored release"
            )
        if not backup_confirmed:
            raise MaintenanceOperationError(
                "Confirm an external database checkpoint with --backup-confirmed"
            )

        settings = _load_settings(project_root)
        if extras is not None:
            settings = DeploymentSettings(1, tuple(sorted(set(extras))))
        maintenance_root = _maintenance_root(project_root)
        maintenance_root.mkdir(parents=True, exist_ok=True)
        if requirements_lock is not None:
            shutil.copy2(
                Path(requirements_lock).expanduser().resolve(),
                maintenance_root / "requirements.lock",
            )
        elif not (maintenance_root / "requirements.lock").exists():
            (maintenance_root / "requirements.lock").write_text("", encoding="utf-8")
        _write_settings(project_root, settings)

        snapshot = _snapshot_release(project_root, staged)
        target = _release_from_tree(snapshot, exact=True)
        _snapshot_release(project_root, source)
        _snapshot_state(project_root, source)
        _write_transaction(
            project_root,
            {
                "action": "upgrade",
                "from_release": source.release_id,
                "phase": "activation",
                "to_release": target.release_id,
            },
        )
        try:
            _activate_upgrade(project_root, source, target, settings)
        except Exception:
            _restore_active(project_root, source, target)
            _sync_environment(project_root, settings)
            transaction_path.unlink(missing_ok=True)
            raise
        _write_transaction(
            project_root,
            {
                "action": "upgrade",
                "from_release": source.release_id,
                "phase": "database-migration",
                "to_release": target.release_id,
            },
        )
        database_started = True
        _upgrade_database(project_root, source, target)
        _release_from_tree(project_root, exact=False)
        _discover(project_root)
        transaction_path.unlink()
        shutil.rmtree(stage, ignore_errors=True)
        return DeploymentResult(
            "upgrade",
            project_root,
            target.version,
            target.release_id,
            package_sha256=package_digest,
        )
    except Exception:
        if database_started and transaction_path.exists():
            data = _load_transaction(project_root)
            data["phase"] = "database-recovery-required"
            _write_transaction(project_root, data)
        elif stage is not None:
            shutil.rmtree(stage, ignore_errors=True)
        raise
    finally:
        lock.release()


def downgrade_deployment(
    release_id: str,
    deployment_root: str | Path,
    *,
    backup_confirmed: bool = False,
) -> DeploymentResult:
    project_root = _project_root(deployment_root)
    if _transaction_path(project_root).exists():
        raise MaintenanceOperationError("Resume the unfinished transaction first")
    source = _active_release(project_root)
    try:
        lock = server_runtime_lock(project_root / "src").acquire()
    except RuntimeLockError as exc:
        raise MaintenanceOperationError(str(exc)) from exc
    database_started = False
    try:
        target = _stored_release(project_root, release_id)
        if target.release_id == source.release_id:
            raise MaintenanceOperationError("The selected release is already active")
        if not backup_confirmed:
            raise MaintenanceOperationError(
                "Confirm an external database checkpoint with --backup-confirmed"
            )
        target_state = _version_root(project_root, target.release_id) / "state"
        if not (target_state / "config.toml").is_file():
            raise MaintenanceOperationError(
                f"Stored release has no compatible configuration snapshot: {target.release_id}"
            )
        _snapshot_release(project_root, source)
        _snapshot_state(project_root, source)
        _write_transaction(
            project_root,
            {
                "action": "downgrade",
                "from_release": source.release_id,
                "phase": "database-migration",
                "to_release": target.release_id,
            },
        )
        database_started = True
        _downgrade_database(project_root, source, target)
        _write_transaction(
            project_root,
            {
                "action": "downgrade",
                "from_release": source.release_id,
                "phase": "activation",
                "to_release": target.release_id,
            },
        )
        _archive_active(project_root, source)
        _copy_release_to_active(project_root, target)
        _atomic_write(
            project_root / "src" / "config.toml",
            (target_state / "config.toml").read_bytes(),
        )
        _copy_state_extensions(project_root, target)
        _sync_environment(project_root, _load_settings(project_root))
        _release_from_tree(project_root, exact=False)
        _discover(project_root)
        _transaction_path(project_root).unlink()
        return DeploymentResult(
            "downgrade", project_root, target.version, target.release_id
        )
    except Exception:
        if database_started and _transaction_path(project_root).exists():
            data = _load_transaction(project_root)
            data["phase"] = "database-recovery-required"
            _write_transaction(project_root, data)
        raise
    finally:
        lock.release()


def resume_deployment(
    deployment_root: str | Path,
    *,
    database_restored: bool = False,
) -> DeploymentResult:
    project_root = _project_root(deployment_root)
    try:
        lock = server_runtime_lock(
            project_root / "src",
            allow_unfinished_deployment=True,
        ).acquire()
    except RuntimeLockError as exc:
        raise MaintenanceOperationError(str(exc)) from exc
    try:
        transaction = _load_transaction(project_root)
        source = _stored_release(project_root, transaction["from_release"])
        target = _stored_release(project_root, transaction["to_release"])
        phase = transaction["phase"]
        if phase in {"database-migration", "database-recovery-required"} and (
            not database_restored
        ):
            raise MaintenanceOperationError(
                "Restore the external database checkpoint, then pass --database-restored"
            )
        if phase in {"activation", "database-migration", "database-recovery-required"}:
            engine = _database_engine(project_root)
            try:
                with engine.connect() as connection:
                    revision = _current_revision(connection)
                _, _, source_head = _alembic(source)
                _, _, target_head = _alembic(target)
            finally:
                engine.dispose()
            if revision == source_head:
                _restore_active(project_root, source, target)
                active = source
            elif revision == target_head:
                _restore_active(project_root, target, source)
                active = target
            else:
                raise MaintenanceOperationError(
                    f"Database revision {revision or 'unversioned'} matches "
                    "neither transaction endpoint"
                )
        else:
            raise MaintenanceOperationError(
                f"Unsupported deployment transaction phase: {phase!r}"
            )
        _sync_environment(project_root, _load_settings(project_root))
        _transaction_path(project_root).unlink()
        return DeploymentResult(
            "resume", project_root, active.version, active.release_id
        )
    finally:
        lock.release()


def inspect_deployment(deployment_root: str | Path) -> DeploymentResult:
    project_root = _project_root(deployment_root)
    active = _active_release(project_root)
    versions = []
    versions_root = _maintenance_root(project_root) / "versions"
    if versions_root.is_dir():
        for path in sorted(versions_root.iterdir()):
            if not path.is_dir() or _SHA256_PATTERN(path.name) is None:
                continue
            release = _release_from_tree(path / "release", exact=True)
            versions.append(
                DeploymentVersion(
                    release.release_id,
                    release.version,
                    release.release_id == active.release_id,
                )
            )
    if not any(version.active for version in versions):
        versions.append(DeploymentVersion(active.release_id, active.version, True))
    return DeploymentResult(
        "status",
        project_root,
        active.version,
        active.release_id,
        tuple(versions),
    )
