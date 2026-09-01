import datetime as dt
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import ssl
import stat
import subprocess
import tarfile
import tomllib
import zipfile
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from include.extensions.manager import ExtensionDiscoveryError, discover_extensions
from include.runtime_lock import RuntimeLockError, server_runtime_lock
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
    "src/deployment_launcher.py",
    "src/main.py",
}
_LEGACY_VERSION = "0.7.0"
_LEGACY_MANAGED_DIGEST = (
    "ac520e5e6b86b93a37df1d3989203e6e794ec0ee0059a1c730cdc919a986ea88"
)
_LEGACY_MANAGED_EXTENSIONS = {"brute_force_lockdown", "builtin", "oidc_sso"}
_LEGACY_SINGLE_FILES = (
    "CHANGELOG.md",
    "README.md",
    "SECURITY.md",
    "pyproject.toml",
    "uv.lock",
    "src/LICENSE",
    "src/alembic.ini",
    "src/config.toml.sample",
    "src/content/hello",
    "src/main.py",
)


@dataclass(frozen=True, slots=True)
class DeploymentState:
    format_version: int
    active_version: str
    extras: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class DeploymentResult:
    action: str
    deployment_root: Path
    active_version: str
    package_sha256: str | None = None
    backup_path: Path | None = None


def _hash_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(_COPY_CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
        if len(parts) != 2:
            continue
        digest, filename = parts
        if Path(filename.lstrip("* ")).name == package_path.name:
            matches.append(digest)
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
    normalized = name.removesuffix("/")
    parts = normalized.split("/")
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
            file_type = stat.S_IFMT(mode)
            expected_type = stat.S_IFDIR if info.is_dir() else stat.S_IFREG
            if file_type not in {0, expected_type}:
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


def _validate_release(target: Path, top_level: str) -> dict[str, Any]:
    manifest_path = target / "release-manifest.json"
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise MaintenanceOperationError(
            "Release package is missing a valid release-manifest.json"
        ) from exc
    version = manifest.get("version")
    if (
        manifest.get("format_version") != 1
        or manifest.get("product") != "cfms-on-websocket"
        or not isinstance(version, str)
        or _VERSION_PATTERN(version) is None
        or top_level != f"cfms-on-websocket-{version}"
    ):
        raise MaintenanceOperationError("Release manifest identity is invalid")
    minimum_version = manifest.get("minimum_upgrade_version")
    managed_extensions = manifest.get("managed_extensions")
    if (
        not isinstance(minimum_version, str)
        or _VERSION_PATTERN(minimum_version) is None
        or not isinstance(manifest.get("requires_python"), str)
        or not manifest["requires_python"]
        or not isinstance(manifest.get("alembic_head"), str)
        or not manifest["alembic_head"]
        or not isinstance(managed_extensions, list)
        or any(
            not isinstance(identifier, str)
            or _EXTENSION_IDENTIFIER_PATTERN(identifier) is None
            for identifier in managed_extensions
        )
        or len(managed_extensions) != len(set(managed_extensions))
    ):
        raise MaintenanceOperationError("Release manifest metadata is invalid")
    expected_files = manifest.get("files")
    if not isinstance(expected_files, dict):
        raise MaintenanceOperationError("Release manifest files table is invalid")
    actual_paths = {
        path.relative_to(target).as_posix()
        for path in target.rglob("*")
        if path.is_file() and path != manifest_path
    }
    missing_required = _REQUIRED_RELEASE_FILES - actual_paths
    if missing_required:
        raise MaintenanceOperationError(
            "Release package is missing required files: "
            + ", ".join(sorted(missing_required))
        )
    if actual_paths != set(expected_files):
        raise MaintenanceOperationError(
            "Release archive contents do not match its manifest"
        )
    for relative_path, expected in expected_files.items():
        if not isinstance(expected, str) or _SHA256_PATTERN(expected) is None:
            raise MaintenanceOperationError(
                f"Release manifest contains an invalid digest for {relative_path}"
            )
        if _hash_file(target / Path(relative_path)) != expected.lower():
            raise MaintenanceOperationError(
                f"Release file failed SHA-256 verification: {relative_path}"
            )
    return manifest


def _stage_release(
    package: str | Path,
    deployment_root: Path,
    *,
    expected_sha256: str | None,
    checksums_path: str | Path | None,
) -> tuple[Path, dict[str, Any], str]:
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

    releases_root = deployment_root / "releases"
    releases_root.mkdir(parents=True, exist_ok=True)
    stage = releases_root / f".cfms-release-stage-{secrets.token_hex(8)}"
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
        manifest = _validate_release(stage, top_level)
        return stage, manifest, actual
    except MaintenanceOperationError:
        shutil.rmtree(stage, ignore_errors=True)
        raise
    except (OSError, tarfile.TarError, zipfile.BadZipFile) as exc:
        shutil.rmtree(stage, ignore_errors=True)
        raise MaintenanceOperationError(
            f"Unable to extract release package {package_path}: {exc}"
        ) from exc


def _run(command: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> None:
    result = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        output = "\n".join(
            part.strip() for part in (result.stdout, result.stderr) if part.strip()
        )
        raise MaintenanceOperationError(
            f"Command failed with exit code {result.returncode}: {' '.join(command)}"
            + (f"\n{output}" if output else "")
        )


def _release_python(release_root: Path) -> Path:
    if os.name == "nt":
        return release_root / ".venv" / "Scripts" / "python.exe"
    return release_root / ".venv" / "bin" / "python"


def _sync_environment(
    release_root: Path,
    extras: tuple[str, ...],
    requirements_lock: Path,
) -> None:
    uv = shutil.which("uv")
    if uv is None:
        raise MaintenanceOperationError("uv is required to install a release")
    sync_command = [uv, "sync", "--project", str(release_root), "--locked", "--no-dev"]
    for extra in extras:
        sync_command.extend(("--extra", extra))
    _run(sync_command, cwd=release_root)
    python = _release_python(release_root)
    if requirements_lock.is_file() and requirements_lock.stat().st_size:
        _run(
            [
                uv,
                "pip",
                "install",
                "--python",
                str(python),
                "--requirements",
                str(requirements_lock),
                "--require-hashes",
                "--strict",
            ],
            cwd=release_root,
        )
        check_command = [
            uv,
            "sync",
            "--project",
            str(release_root),
            "--locked",
            "--no-dev",
            "--inexact",
            "--check",
        ]
        for extra in extras:
            check_command.extend(("--extra", extra))
        _run(check_command, cwd=release_root)


def _runtime_environment(shared_root: Path) -> dict[str, str]:
    environment = os.environ.copy()
    environment["CFMS_SERVER_ROOT"] = str(shared_root)
    return environment


def _run_maintenance(
    release_root: Path,
    shared_root: Path,
    arguments: list[str],
) -> None:
    _run(
        [str(_release_python(release_root)), "-m", "maintenance.cli", *arguments],
        cwd=shared_root,
        env=_runtime_environment(shared_root),
    )


def _atomic_write(path: Path, contents: bytes) -> None:
    temporary = path.with_name(f".{path.name}.tmp-{secrets.token_hex(8)}")
    try:
        with temporary.open("xb") as output:
            output.write(contents)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def _write_state(deployment_root: Path, state: DeploymentState) -> None:
    contents = (json.dumps(asdict(state), indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    _atomic_write(deployment_root / "deployment.json", contents)


def _load_state(deployment_root: Path) -> DeploymentState:
    state_path = deployment_root / "deployment.json"
    try:
        data = json.loads(state_path.read_text(encoding="utf-8"))
        state = DeploymentState(
            format_version=data["format_version"],
            active_version=data["active_version"],
            extras=tuple(data.get("extras", ())),
        )
    except (KeyError, TypeError, OSError, json.JSONDecodeError) as exc:
        raise MaintenanceOperationError(
            f"Unable to read deployment state {state_path}: {exc}"
        ) from exc
    if (
        state.format_version != 1
        or not isinstance(state.active_version, str)
        or _VERSION_PATTERN(state.active_version) is None
    ):
        raise MaintenanceOperationError("Deployment state is invalid")
    if any(not isinstance(extra, str) for extra in state.extras):
        raise MaintenanceOperationError("Deployment extras are invalid")
    return state


def _install_staged_release(
    stage: Path,
    manifest: dict[str, Any],
    deployment_root: Path,
    extras: tuple[str, ...],
) -> Path:
    version = manifest["version"]
    destination = deployment_root / "releases" / version
    if destination.exists():
        raise MaintenanceOperationError(
            f"Release version {version} is already installed"
        )
    os.replace(stage, destination)
    try:
        _sync_environment(
            destination,
            extras,
            deployment_root / "shared" / "requirements.lock",
        )
    except Exception:
        shutil.rmtree(destination, ignore_errors=True)
        raise
    return destination


def _copy_launcher(release_root: Path, deployment_root: Path) -> None:
    source = release_root / "src" / "deployment_launcher.py"
    if not source.is_file():
        raise MaintenanceOperationError(
            "Release package is missing src/deployment_launcher.py"
        )
    _atomic_write(deployment_root / "main.py", source.read_bytes())


def _sync_packaged_ca(release_root: Path, shared_root: Path) -> None:
    source_root = release_root / "src" / "content" / "ssl" / "client"
    target_root = shared_root / "content" / "ssl" / "client"
    target_root.mkdir(parents=True, exist_ok=True)
    if not source_root.is_dir():
        return
    for source in source_root.iterdir():
        if not source.is_file():
            continue
        target = target_root / source.name
        if target.exists() and target.read_bytes() != source.read_bytes():
            raise MaintenanceOperationError(
                f"Packaged client CA conflicts with an operator file: {target}"
            )
        if not target.exists():
            shutil.copy2(source, target)


def _prepare_shared_root(
    deployment_root: Path,
    release_root: Path,
    requirements_lock: str | Path | None,
) -> Path:
    shared_root = deployment_root / "shared"
    for relative in (
        "content/files",
        "content/logs",
        "content/ssl",
        "backups",
        "run",
    ):
        (shared_root / relative).mkdir(parents=True, exist_ok=True)
    config_path = shared_root / "config.toml"
    if not config_path.exists():
        shutil.copy2(release_root / "src" / "config.toml.sample", config_path)
    lock_target = shared_root / "requirements.lock"
    if requirements_lock is not None:
        shutil.copy2(Path(requirements_lock).expanduser().resolve(), lock_target)
    elif not lock_target.exists():
        lock_target.write_text("", encoding="utf-8")
    _sync_packaged_ca(release_root, shared_root)
    return shared_root


def _sqlite_backup(shared_root: Path, version: str) -> Path | None:
    config_path = shared_root / "config.toml"
    try:
        with config_path.open("rb") as config_file:
            database = tomllib.load(config_file)["database"]
    except (KeyError, OSError, tomllib.TOMLDecodeError) as exc:
        raise MaintenanceOperationError(
            f"Unable to read database settings for backup: {exc}"
        ) from exc
    if database.get("type") != "sqlite":
        return None
    source = Path(database["file"])
    if not source.is_absolute():
        source = shared_root / source
    if not source.is_file():
        raise MaintenanceOperationError(f"SQLite database not found: {source}")
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
    backup_path = shared_root / "backups" / f"pre-upgrade-{version}-{timestamp}.db"
    with (
        sqlite3.connect(source) as source_connection,
        sqlite3.connect(backup_path) as target_connection,
    ):
        source_connection.backup(target_connection)
    return backup_path


def _preflight_certificates(shared_root: Path) -> None:
    try:
        with (shared_root / "config.toml").open("rb") as config_file:
            server_config = tomllib.load(config_file)["server"]
        cert_path = Path(server_config["ssl_certfile"])
        key_path = Path(server_config["ssl_keyfile"])
    except (KeyError, OSError, TypeError, tomllib.TOMLDecodeError) as exc:
        raise MaintenanceOperationError(
            f"Unable to read TLS certificate settings: {exc}"
        ) from exc
    if not cert_path.is_absolute():
        cert_path = shared_root / cert_path
    if not key_path.is_absolute():
        key_path = shared_root / key_path
    try:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    except (OSError, ssl.SSLError) as exc:
        raise MaintenanceOperationError(
            f"Unable to load configured TLS certificate and key: {exc}"
        ) from exc


def _write_transaction(shared_root: Path, data: dict[str, Any]) -> Path:
    path = shared_root / "run" / "upgrade-transaction.json"
    _atomic_write(
        path,
        (json.dumps(data, indent=2, sort_keys=True) + "\n").encode("utf-8"),
    )
    return path


def _release_managed_extensions(release_root: Path) -> frozenset[str]:
    manifest_path = release_root / "release-manifest.json"
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        identifiers = data["managed_extensions"]
    except (KeyError, OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise MaintenanceOperationError(
            f"Unable to read managed extensions from {manifest_path}: {exc}"
        ) from exc
    if not isinstance(identifiers, list) or any(
        not isinstance(identifier, str)
        or _EXTENSION_IDENTIFIER_PATTERN(identifier) is None
        for identifier in identifiers
    ):
        raise MaintenanceOperationError(
            f"Release manifest has invalid managed_extensions: {manifest_path}"
        )
    return frozenset(identifiers)


def _copy_third_party_extensions(
    source_release: Path,
    target_release: Path,
    source_managed: frozenset[str],
    target_managed: frozenset[str],
) -> tuple[str, ...]:
    source_root = source_release / "src" / "include" / "extensions"
    target_root = target_release / "src" / "include" / "extensions"
    try:
        source_catalog = discover_extensions(source_root)
        target_catalog = discover_extensions(target_root)
    except ExtensionDiscoveryError as exc:
        raise MaintenanceOperationError(str(exc)) from exc

    copied = []
    for identifier, extension in source_catalog.items():
        if identifier in source_managed:
            continue
        if identifier in target_managed or identifier in target_catalog:
            raise MaintenanceOperationError(
                f"Third-party extension {identifier!r} conflicts with the new release"
            )
        target = target_root / extension.directory.name
        if target.exists():
            raise MaintenanceOperationError(
                f"Third-party extension directory conflicts with the new release: "
                f"{target}"
            )
        try:
            shutil.copytree(extension.directory, target)
        except OSError as exc:
            raise MaintenanceOperationError(
                f"Unable to copy third-party extension {identifier!r}: {exc}"
            ) from exc
        copied.append(identifier)

    try:
        discover_extensions(target_root)
    except ExtensionDiscoveryError as exc:
        raise MaintenanceOperationError(str(exc)) from exc
    return tuple(copied)


def _complete_pending_cleanup(
    deployment_root: Path,
    shared_root: Path,
    state: DeploymentState,
) -> None:
    transaction_path = shared_root / "run" / "upgrade-transaction.json"
    if not transaction_path.exists():
        return
    try:
        transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
        phase = transaction["phase"]
        from_version = transaction["from_version"]
        to_version = transaction["to_version"]
    except (KeyError, OSError, TypeError, json.JSONDecodeError) as exc:
        raise MaintenanceOperationError(
            f"Unfinished deployment transaction requires review: {transaction_path}"
        ) from exc
    if (
        phase not in {"activation", "cleanup-required"}
        or to_version != state.active_version
        or not isinstance(from_version, str)
        or _VERSION_PATTERN(from_version) is None
        or from_version == state.active_version
    ):
        raise MaintenanceOperationError(
            f"Unfinished deployment transaction requires review: {transaction_path}"
        )
    retired_release = deployment_root / "releases" / from_version
    try:
        if retired_release.exists():
            shutil.rmtree(retired_release)
        transaction_path.unlink()
    except OSError as exc:
        raise MaintenanceOperationError(
            f"Unable to remove inactive release {retired_release}: {exc}"
        ) from exc


def install_deployment(
    package: str | Path,
    deployment_root: str | Path,
    *,
    expected_sha256: str | None = None,
    checksums_path: str | Path | None = None,
    extras: tuple[str, ...] = (),
    requirements_lock: str | Path | None = None,
) -> DeploymentResult:
    root = Path(deployment_root).expanduser().resolve()
    if (root / "deployment.json").exists():
        raise MaintenanceOperationError(f"Deployment already exists at {root}")
    root.mkdir(parents=True, exist_ok=True)
    stage, manifest, digest = _stage_release(
        package,
        root,
        expected_sha256=expected_sha256,
        checksums_path=checksums_path,
    )
    release_root = _install_staged_release(
        stage, manifest, root, tuple(sorted(set(extras)))
    )
    shared_root = _prepare_shared_root(root, release_root, requirements_lock)
    try:
        _run_maintenance(release_root, shared_root, ["database", "upgrade", "--yes"])
        _run_maintenance(release_root, shared_root, ["extension", "list"])
        _copy_launcher(release_root, root)
        state = DeploymentState(1, manifest["version"], tuple(sorted(set(extras))))
        _write_state(root, state)
    except Exception:
        shutil.rmtree(release_root, ignore_errors=True)
        raise
    return DeploymentResult("install", root, state.active_version, digest)


def _legacy_managed_paths(legacy_root: Path) -> tuple[Path, ...]:
    paths = [legacy_root / relative for relative in _LEGACY_SINGLE_FILES]
    for relative in ("src/alembic", "src/maintenance"):
        paths.extend(
            path for path in (legacy_root / relative).rglob("*") if path.is_file()
        )
    include_root = legacy_root / "src" / "include"
    for path in include_root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(include_root)
        if len(relative.parts) >= 3 and relative.parts[0] == "extensions":
            candidate = relative.parts[1]
            if candidate not in _LEGACY_MANAGED_EXTENSIONS:
                continue
        paths.append(path)
    return tuple(
        sorted(
            {
                path
                for path in paths
                if path.is_file()
                and ".git" not in path.parts
                and "__pycache__" not in path.parts
                and path.suffix not in {".pyc", ".pyo"}
                and path.name != ".gitignore"
            },
            key=lambda path: path.relative_to(legacy_root).as_posix(),
        )
    )


def _validate_legacy_release(legacy_root: Path) -> None:
    try:
        with (legacy_root / "pyproject.toml").open("rb") as pyproject_file:
            version = tomllib.load(pyproject_file)["project"]["version"]
    except (KeyError, OSError, tomllib.TOMLDecodeError) as exc:
        raise MaintenanceOperationError(
            f"Unable to identify legacy deployment {legacy_root}: {exc}"
        ) from exc
    if version != _LEGACY_VERSION:
        raise MaintenanceOperationError(
            f"Legacy adoption supports only v{_LEGACY_VERSION}; found {version!r}"
        )
    digest = hashlib.sha256()
    paths = _legacy_managed_paths(legacy_root)
    for path in paths:
        relative = path.relative_to(legacy_root).as_posix()
        digest.update(
            relative.encode("utf-8") + b"\0" + bytes.fromhex(_hash_file(path))
        )
    if digest.hexdigest() != _LEGACY_MANAGED_DIGEST:
        raise MaintenanceOperationError(
            "Legacy v0.7.0 application files do not match the official release"
        )


def _move_legacy_state(
    legacy_root: Path,
    shared_root: Path,
) -> list[tuple[Path, Path]]:
    runtime_root = legacy_root / "src"
    moves: list[tuple[Path, Path]] = []
    candidates = []
    for name in ("config.toml", "init", "admin_password.txt"):
        candidates.append((runtime_root / name, shared_root / name))
    candidates.extend(
        (path, shared_root / path.name)
        for path in runtime_root.glob("config.toml.backup-*")
    )
    try:
        with (runtime_root / "config.toml").open("rb") as config_file:
            database = tomllib.load(config_file)["database"]
    except (KeyError, OSError, tomllib.TOMLDecodeError) as exc:
        raise MaintenanceOperationError(
            f"Unable to read legacy configuration: {exc}"
        ) from exc
    if database.get("type") == "sqlite":
        database_path = Path(database["file"])
        if not database_path.is_absolute():
            source = runtime_root / database_path
            target = shared_root / database_path
            candidates.append((source, target))
            for suffix in ("-wal", "-shm"):
                candidates.append(
                    (Path(f"{source}{suffix}"), Path(f"{target}{suffix}"))
                )
    content_root = runtime_root / "content"
    if content_root.is_dir():
        for child in content_root.iterdir():
            if child.name != "hello":
                candidates.append((child, shared_root / "content" / child.name))
    for source, target in candidates:
        if not source.exists():
            continue
        if target.exists():
            raise MaintenanceOperationError(
                f"Legacy state destination already exists: {target}"
            )
        target.parent.mkdir(parents=True, exist_ok=True)
        try:
            os.replace(source, target)
        except OSError as exc:
            for moved_source, moved_target in reversed(moves):
                os.replace(moved_target, moved_source)
            raise MaintenanceOperationError(
                "Legacy deployment and new shared root must be on the same "
                f"filesystem: {exc}"
            ) from exc
        moves.append((source, target))
    return moves


def adopt_deployment(
    package: str | Path,
    deployment_root: str | Path,
    legacy_root: str | Path,
    *,
    server_stopped: bool,
    expected_sha256: str | None = None,
    checksums_path: str | Path | None = None,
    extras: tuple[str, ...] = (),
    requirements_lock: str | Path | None = None,
) -> DeploymentResult:
    if not server_stopped:
        raise MaintenanceOperationError(
            "Legacy adoption requires --server-stopped confirmation"
        )
    root = Path(deployment_root).expanduser().resolve()
    legacy = Path(legacy_root).expanduser().resolve()
    if root == legacy or root.is_relative_to(legacy):
        raise MaintenanceOperationError(
            "Deployment root must be outside the legacy release directory"
        )
    if (root / "deployment.json").exists():
        raise MaintenanceOperationError(f"Deployment already exists at {root}")
    _validate_legacy_release(legacy)
    root.mkdir(parents=True, exist_ok=True)
    stage, manifest, digest = _stage_release(
        package,
        root,
        expected_sha256=expected_sha256,
        checksums_path=checksums_path,
    )
    normalized_extras = tuple(sorted(set(extras)))
    release_root = _install_staged_release(stage, manifest, root, normalized_extras)
    shared_root = root / "shared"
    for relative in ("content", "backups", "run"):
        (shared_root / relative).mkdir(parents=True, exist_ok=True)
    moved: list[tuple[Path, Path]] = []
    config_snapshot: Path | None = None
    migration_started = False
    transaction_path = None
    try:
        moved = _move_legacy_state(legacy, shared_root)
        _prepare_shared_root(root, release_root, requirements_lock)
        custom_extensions = _copy_third_party_extensions(
            legacy,
            release_root,
            frozenset(_LEGACY_MANAGED_EXTENSIONS),
            frozenset(manifest["managed_extensions"]),
        )
        if custom_extensions and not (shared_root / "requirements.lock").stat().st_size:
            raise MaintenanceOperationError(
                "Adopting third-party extensions requires a non-empty requirements.lock"
            )
        if custom_extensions:
            _sync_environment(
                release_root,
                normalized_extras,
                shared_root / "requirements.lock",
            )
        _preflight_certificates(shared_root)
        backup_path = _sqlite_backup(shared_root, _LEGACY_VERSION)
        timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        config_snapshot = (
            shared_root
            / "backups"
            / f"config-{_LEGACY_VERSION}-before-adopt-{manifest['version']}-{timestamp}.toml"
        )
        shutil.copy2(shared_root / "config.toml", config_snapshot)
        transaction = {
            "action": "adopt",
            "from_version": _LEGACY_VERSION,
            "phase": "configuration",
            "to_version": manifest["version"],
        }
        transaction_path = _write_transaction(shared_root, transaction)
        _run_maintenance(
            release_root,
            shared_root,
            [
                "config",
                "sync-template",
                "--template",
                str(release_root / "src" / "config.toml.sample"),
                "--yes",
            ],
        )
        _write_transaction(
            shared_root,
            {
                "action": "adopt",
                "from_version": _LEGACY_VERSION,
                "phase": "database-migration",
                "to_version": manifest["version"],
            },
        )
        migration_started = True
        _run_maintenance(release_root, shared_root, ["database", "upgrade", "--yes"])
        _run_maintenance(release_root, shared_root, ["extension", "list"])
        _copy_launcher(release_root, root)
        state = DeploymentState(1, manifest["version"], normalized_extras)
        _write_state(root, state)
        transaction_path.unlink()
    except Exception:
        if config_snapshot is not None and config_snapshot.exists():
            _atomic_write(shared_root / "config.toml", config_snapshot.read_bytes())
        if migration_started:
            if transaction_path is not None:
                _write_transaction(
                    shared_root,
                    {
                        "action": "adopt",
                        "from_version": _LEGACY_VERSION,
                        "phase": "recovery-required",
                        "to_version": manifest["version"],
                    },
                )
        else:
            for source, target in reversed(moved):
                os.replace(target, source)
            shutil.rmtree(release_root, ignore_errors=True)
        raise
    return DeploymentResult(
        "adopt",
        root,
        state.active_version,
        digest,
        backup_path,
    )


def upgrade_deployment(
    package: str | Path,
    deployment_root: str | Path,
    *,
    expected_sha256: str | None = None,
    checksums_path: str | Path | None = None,
    mysql_backup_confirmed: bool = False,
) -> DeploymentResult:
    root = Path(deployment_root).expanduser().resolve()
    state = _load_state(root)
    shared_root = root / "shared"
    transaction_path = shared_root / "run" / "upgrade-transaction.json"
    try:
        lock = server_runtime_lock(shared_root).acquire()
    except RuntimeLockError as exc:
        raise MaintenanceOperationError(str(exc)) from exc
    release_root = None
    config_backup = None
    migration_started = False
    backup_path = None
    activated = False
    transaction_started = False
    try:
        _complete_pending_cleanup(root, shared_root, state)
        current_release = root / "releases" / state.active_version
        current_managed = _release_managed_extensions(current_release)
        stage, manifest, digest = _stage_release(
            package,
            root,
            expected_sha256=expected_sha256,
            checksums_path=checksums_path,
        )
        version = manifest["version"]
        current_parts = tuple(int(part) for part in state.active_version.split("."))
        target_parts = tuple(int(part) for part in version.split("."))
        if target_parts <= current_parts:
            shutil.rmtree(stage, ignore_errors=True)
            raise MaintenanceOperationError(
                f"Upgrade version {version} must be newer than {state.active_version}"
            )
        minimum = manifest.get("minimum_upgrade_version")
        if not isinstance(minimum, str) or current_parts < tuple(
            int(part) for part in minimum.split(".")
        ):
            shutil.rmtree(stage, ignore_errors=True)
            raise MaintenanceOperationError(
                f"Release {version} cannot upgrade {state.active_version} directly"
            )
        _write_transaction(
            shared_root,
            {
                "action": "upgrade",
                "from_version": state.active_version,
                "phase": "staging",
                "to_version": version,
            },
        )
        transaction_started = True
        release_root = _install_staged_release(stage, manifest, root, state.extras)
        custom_extensions = _copy_third_party_extensions(
            current_release,
            release_root,
            current_managed,
            frozenset(manifest["managed_extensions"]),
        )
        if custom_extensions and not (shared_root / "requirements.lock").stat().st_size:
            raise MaintenanceOperationError(
                "Upgrading third-party extensions requires a non-empty requirements.lock"
            )
        _sync_packaged_ca(release_root, shared_root)
        _preflight_certificates(shared_root)
        _run_maintenance(release_root, shared_root, ["extension", "list"])
        backup_path = _sqlite_backup(shared_root, state.active_version)
        if backup_path is None and not mysql_backup_confirmed:
            raise MaintenanceOperationError(
                "MySQL upgrades require --mysql-backup-confirmed"
            )
        timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%SZ")
        config_backup = (
            shared_root
            / "backups"
            / f"config-{state.active_version}-before-{version}-{timestamp}.toml"
        )
        shutil.copy2(shared_root / "config.toml", config_backup)
        _run_maintenance(
            release_root,
            shared_root,
            [
                "config",
                "sync-template",
                "--template",
                str(release_root / "src" / "config.toml.sample"),
                "--yes",
            ],
        )
        _write_transaction(
            shared_root,
            {
                "action": "upgrade",
                "from_version": state.active_version,
                "phase": "database-migration",
                "to_version": version,
            },
        )
        migration_started = True
        _run_maintenance(release_root, shared_root, ["database", "upgrade", "--yes"])
        _run_maintenance(release_root, shared_root, ["extension", "list"])
        _write_transaction(
            shared_root,
            {
                "action": "upgrade",
                "from_version": state.active_version,
                "phase": "activation",
                "to_version": version,
            },
        )
        _copy_launcher(release_root, root)
        next_state = DeploymentState(1, version, state.extras)
        _write_state(root, next_state)
        activated = True
        _write_transaction(
            shared_root,
            {
                "action": "upgrade",
                "from_version": state.active_version,
                "phase": "cleanup-required",
                "to_version": version,
            },
        )
        if os.name != "nt":
            try:
                shutil.rmtree(current_release)
                transaction_path.unlink()
            except OSError as exc:
                raise MaintenanceOperationError(
                    f"Release {version} is active, but inactive release "
                    f"{current_release} could not be removed: {exc}"
                ) from exc
        return DeploymentResult(
            "upgrade",
            root,
            version,
            digest,
            backup_path,
        )
    except Exception:
        if activated:
            raise
        if config_backup is not None and config_backup.exists():
            _atomic_write(shared_root / "config.toml", config_backup.read_bytes())
        if migration_started:
            _write_transaction(
                shared_root,
                {
                    "action": "upgrade",
                    "from_version": state.active_version,
                    "phase": "recovery-required",
                    "to_version": release_root.name if release_root else None,
                },
            )
        else:
            if transaction_started and transaction_path.exists():
                transaction_path.unlink()
            if release_root is not None:
                shutil.rmtree(release_root, ignore_errors=True)
        raise
    finally:
        lock.release()


def inspect_deployment(deployment_root: str | Path) -> DeploymentResult:
    root = Path(deployment_root).expanduser().resolve()
    state = _load_state(root)
    return DeploymentResult("status", root, state.active_version)
