import datetime as dt
import hashlib
import io
import json
import shutil
import zipfile
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from typer.testing import CliRunner

from include.runtime_lock import RuntimeLock
from maintenance.cli import app
from maintenance.operations import deployment, deployment_online
from maintenance.operations.exceptions import MaintenanceOperationError

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _write_extension(
    root: Path,
    directory_name: str,
    identifier: str,
    marker: str,
) -> None:
    extension = root / "src" / "include" / "extensions" / directory_name
    extension.mkdir(parents=True, exist_ok=True)
    (extension / "manifest.toml").write_text(
        "\n".join(
            (
                "manifest_version = 2",
                "",
                "[extension]",
                f'identifier = "{identifier}"',
                f'name = "{identifier}"',
                'version = "1.0.0"',
                'authors = ["Test"]',
                'license = "MIT"',
                "",
            )
        ),
        encoding="utf-8",
    )
    (extension / "_extension.py").write_text(marker, encoding="utf-8")


def _write_release(
    root: Path,
    version: str,
    marker: str,
    *,
    managed_extensions: tuple[str, ...] = ("builtin",),
    with_migrations: bool = False,
    migration: tuple[str, str] | None = None,
) -> deployment._Release:
    files = {
        "pyproject.toml": (
            f'[project]\nname = "cfms-on-websocket"\nversion = "{version}"\n'
            'requires-python = ">=3.14"\n'
        ),
        "uv.lock": f"# {marker}\n",
        "src/alembic.ini": "[alembic]\nscript_location = alembic\n",
        "src/config.toml.sample": f"# {marker}\n",
        "src/content/hello": f"{marker}\n",
        "src/main.py": f"# {marker}\n",
    }
    for relative_path, contents in files.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
    if with_migrations:
        shutil.copy2(PROJECT_ROOT / "src" / "alembic.ini", root / "src")
        shutil.copytree(
            PROJECT_ROOT / "src" / "alembic",
            root / "src" / "alembic",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )
        shutil.copy2(
            PROJECT_ROOT / "src" / "config.toml.sample",
            root / "src" / "config.toml.sample",
        )
    if migration is not None:
        revision, down_revision = migration
        migration_path = root / "src" / "alembic" / "versions" / f"{revision}.py"
        migration_path.write_text(
            "\n".join(
                (
                    f'revision = "{revision}"',
                    f'down_revision = "{down_revision}"',
                    "branch_labels = None",
                    "depends_on = None",
                    "",
                    "def upgrade():",
                    "    pass",
                    "",
                    "def downgrade():",
                    "    pass",
                    "",
                )
            ),
            encoding="utf-8",
        )
    for identifier in managed_extensions:
        _write_extension(root, identifier, identifier, f"# {marker} {identifier}\n")

    release_files = {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
    manifest = {
        "files": release_files,
        "format_version": 1,
        "managed_extensions": list(managed_extensions),
        "product": "cfms-on-websocket",
        "requires_python": ">=3.14",
        "version": version,
    }
    (root / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return deployment._release_from_tree(root, exact=True)


def _prepare_deployment(root: Path) -> deployment._Release:
    release = _write_release(root, "1.0.0", "old")
    (root / "src" / "config.toml").write_text("old config\n", encoding="utf-8")
    _write_extension(root, "custom-dir", "custom", "# original custom\n")
    persistent = root / "src" / "content"
    (persistent / "files").mkdir()
    (persistent / "logs").mkdir()
    (persistent / "files" / "production.dat").write_text("data\n", encoding="utf-8")
    (persistent / "logs" / "server.log").write_text("log\n", encoding="utf-8")
    return release


class _HTTPResponse:
    def __init__(
        self,
        contents: bytes,
        url: str,
        *,
        content_length: int | None = None,
    ) -> None:
        self._stream = io.BytesIO(contents)
        self._url = url
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def geturl(self) -> str:
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        pass


def _online_release(
    version: str,
    package_contents: bytes = b"package",
    checksum_contents: bytes = b"checksums",
) -> deployment_online._OnlineRelease:
    package_name = f"cfms-on-websocket-{version}.zip"
    base_url = (
        f"https://github.com/cfms-dev/cfms_on_websocket/releases/download/v{version}"
    )
    return deployment_online._OnlineRelease(
        version,
        dt.datetime(2026, 9, 10, tzinfo=dt.UTC),
        f"https://github.com/cfms-dev/cfms_on_websocket/releases/tag/v{version}",
        deployment_online._ReleaseAsset(
            package_name,
            f"{base_url}/{package_name}",
            len(package_contents),
            hashlib.sha256(package_contents).hexdigest(),
        ),
        deployment_online._ReleaseAsset(
            "SHA256SUMS.txt",
            f"{base_url}/SHA256SUMS.txt",
            len(checksum_contents),
            hashlib.sha256(checksum_contents).hexdigest(),
        ),
    )


def _online_metadata(release: deployment_online._OnlineRelease) -> dict:
    return {
        "tag_name": f"v{release.version}",
        "draft": False,
        "prerelease": False,
        "published_at": release.published_at.isoformat().replace("+00:00", "Z"),
        "html_url": release.release_url,
        "assets": [
            {
                "name": asset.name,
                "state": "uploaded",
                "size": asset.size,
                "digest": f"sha256:{asset.digest}",
                "browser_download_url": asset.url,
            }
            for asset in (release.package, release.checksums)
        ],
    }


@pytest.mark.parametrize("git_metadata_kind", ["directory", "file"])
def test_repository_deployment_rejects_release_switching(
    tmp_path: Path,
    git_metadata_kind: str,
) -> None:
    root = tmp_path / "repository"
    (root / "src").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname = "cfms-on-websocket"\nversion = "0.7.0"\n',
        encoding="utf-8",
    )
    (root / "src" / "main.py").write_text("# repository checkout\n", encoding="utf-8")
    git_metadata = root / ".git"
    if git_metadata_kind == "directory":
        git_metadata.mkdir()
    else:
        git_metadata.write_text("gitdir: ../worktrees/repository\n", encoding="utf-8")

    with pytest.raises(MaintenanceOperationError, match="source repository checkouts"):
        deployment.upgrade_deployment(
            tmp_path / "release.zip",
            root / "src",
            expected_sha256="a" * 64,
        )
    with pytest.raises(MaintenanceOperationError, match="source repository checkouts"):
        deployment.downgrade_deployment(
            "stored-release",
            root / "src",
        )

    assert not (root / "src" / ".maintenance").exists()


@pytest.mark.parametrize("command", ["status", "upgrade", "downgrade"])
def test_manifestless_deployment_is_rejected_before_writes(
    tmp_path: Path,
    command: str,
) -> None:
    root = tmp_path / "deployment"
    (root / "src").mkdir(parents=True)
    (root / "pyproject.toml").write_text(
        '[project]\nname = "cfms-on-websocket"\nversion = "0.7.0"\n',
        encoding="utf-8",
    )
    main = root / "src" / "main.py"
    main.write_text("# pre-manifest release\n", encoding="utf-8")

    with pytest.raises(MaintenanceOperationError, match="release-manifest.json"):
        if command == "status":
            deployment.inspect_deployment(root)
        elif command == "upgrade":
            deployment.upgrade_deployment(
                tmp_path / "release.zip",
                root,
                expected_sha256="a" * 64,
            )
        else:
            deployment.downgrade_deployment(
                "stored-release",
                root,
            )

    assert main.read_text(encoding="utf-8") == "# pre-manifest release\n"
    assert not (root / "src" / ".maintenance").exists()


def test_release_id_is_manifest_digest_and_distinguishes_same_version(
    tmp_path: Path,
) -> None:
    first = _write_release(tmp_path / "first", "1.0.0", "first")
    second = _write_release(tmp_path / "second", "1.0.0", "second")

    assert first.release_id == hashlib.sha256(first.manifest_bytes).hexdigest()
    assert second.release_id == hashlib.sha256(second.manifest_bytes).hexdigest()
    assert first.release_id != second.release_id
    assert "alembic_head" not in first.manifest


@pytest.mark.parametrize(
    "operator_path",
    [
        "src/.maintenance/transaction.json",
        "src/content/files/production.dat",
        "src/content/logs/server.log",
    ],
)
def test_manifest_rejects_operator_owned_paths(
    tmp_path: Path,
    operator_path: str,
) -> None:
    release = _write_release(tmp_path / "release", "1.0.0", "release")
    manifest = dict(release.manifest)
    manifest["files"] = dict(manifest["files"])
    manifest["files"][operator_path] = "0" * 64

    with pytest.raises(MaintenanceOperationError, match="invalid path or digest"):
        deployment._parse_manifest(json.dumps(manifest).encode())


def test_stage_rejects_path_traversal_before_writing_outside_root(
    tmp_path: Path,
) -> None:
    package = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("cfms-on-websocket-1.0.0/../../escape", b"unsafe")

    with pytest.raises(MaintenanceOperationError, match="Unsafe release archive path"):
        deployment._stage_release(
            package,
            tmp_path / "deployment",
            expected_sha256=hashlib.sha256(package.read_bytes()).hexdigest(),
            checksums_path=None,
        )

    assert not (tmp_path / "escape").exists()


def test_stage_allows_missing_external_digest_but_still_checks_manifest(
    tmp_path: Path,
) -> None:
    release_root = tmp_path / "cfms-on-websocket-1.0.0"
    _write_release(release_root, "1.0.0", "release")
    package = tmp_path / "release.zip"
    with zipfile.ZipFile(package, "w") as archive:
        for path in release_root.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(tmp_path).as_posix())

    staged, package_digest, _ = deployment._stage_release(
        package,
        tmp_path / "deployment",
        expected_sha256=None,
        checksums_path=None,
    )

    assert staged.version == "1.0.0"
    assert package_digest == hashlib.sha256(package.read_bytes()).hexdigest()

    (release_root / "src" / "main.py").write_text("tampered\n", encoding="utf-8")
    tampered_package = tmp_path / "tampered.zip"
    with zipfile.ZipFile(tampered_package, "w") as archive:
        for path in release_root.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(tmp_path).as_posix())

    with pytest.raises(MaintenanceOperationError, match="failed SHA-256"):
        deployment._stage_release(
            tampered_package,
            tmp_path / "deployment",
            expected_sha256=None,
            checksums_path=None,
        )


def test_stage_rejects_multiple_external_digest_sources(tmp_path: Path) -> None:
    package = tmp_path / "release.zip"
    package.write_bytes(b"release")
    checksums = tmp_path / "SHA256SUMS.txt"
    checksums.write_text(f"{'a' * 64}  {package.name}\n", encoding="utf-8")

    with pytest.raises(MaintenanceOperationError, match="at most one"):
        deployment._stage_release(
            package,
            tmp_path / "deployment",
            expected_sha256="a" * 64,
            checksums_path=checksums,
        )


@pytest.mark.parametrize(
    ("current_version", "latest_version", "available"),
    [
        ("1.0.0", "1.1.0", True),
        ("1.0.0", "1.0.0", False),
        ("1.1.0", "1.0.0", False),
    ],
)
def test_online_check_compares_latest_release_version(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    current_version: str,
    latest_version: str,
    available: bool,
) -> None:
    root = tmp_path / "deployment"
    _write_release(root, current_version, "active")
    release = _online_release(latest_version)
    monkeypatch.setattr(
        deployment_online,
        "_read_url",
        lambda *args, **kwargs: json.dumps(_online_metadata(release)).encode(),
    )

    status = deployment_online.inspect_online_deployment(root)

    assert status.current_version == current_version
    assert status.latest_version == latest_version
    assert status.update_available is available
    assert status.release_url == release.release_url


@pytest.mark.parametrize(
    "invalid_part",
    [
        "tag",
        "draft",
        "prerelease",
        "release-url",
        "missing-package",
        "duplicate-package",
        "pending-package",
        "oversized-package",
        "missing-digest",
        "foreign-url",
    ],
)
def test_online_release_metadata_is_fail_closed(
    monkeypatch: pytest.MonkeyPatch,
    invalid_part: str,
) -> None:
    release = _online_release("1.1.0")
    metadata = _online_metadata(release)
    if invalid_part == "tag":
        metadata["tag_name"] = "latest"
    elif invalid_part == "draft":
        metadata["draft"] = True
    elif invalid_part == "prerelease":
        metadata["prerelease"] = True
    elif invalid_part == "release-url":
        metadata["html_url"] = "https://example.com/release"
    elif invalid_part == "missing-package":
        metadata["assets"] = metadata["assets"][1:]
    elif invalid_part == "duplicate-package":
        metadata["assets"].append(dict(metadata["assets"][0]))
    elif invalid_part == "pending-package":
        metadata["assets"][0]["state"] = "new"
    elif invalid_part == "oversized-package":
        metadata["assets"][0]["size"] = deployment.MAX_PACKAGE_BYTES + 1
    elif invalid_part == "missing-digest":
        metadata["assets"][0]["digest"] = None
    else:
        metadata["assets"][0]["browser_download_url"] = (
            "https://example.com/cfms-on-websocket-1.1.0.zip"
        )
    monkeypatch.setattr(
        deployment_online,
        "_read_url",
        lambda *args, **kwargs: json.dumps(metadata).encode(),
    )

    with pytest.raises(MaintenanceOperationError, match="GitHub release"):
        deployment_online._fetch_latest_release()


@pytest.mark.parametrize(
    ("contents", "content_length", "maximum", "message"),
    [
        (b"abc", 4, 10, "truncated"),
        (b"abc", 3, 2, "size limit"),
    ],
)
def test_online_response_enforces_declared_and_actual_size(
    contents: bytes,
    content_length: int,
    maximum: int,
    message: str,
) -> None:
    response = _HTTPResponse(
        contents,
        deployment_online.GITHUB_LATEST_RELEASE_URL,
        content_length=content_length,
    )

    with pytest.raises(MaintenanceOperationError, match=message):
        deployment_online._read_response(
            response,
            maximum=maximum,
            label="release metadata",
        )


def test_online_response_enforces_actual_size_without_content_length() -> None:
    response = _HTTPResponse(
        b"abc",
        deployment_online.GITHUB_LATEST_RELEASE_URL,
    )

    with pytest.raises(MaintenanceOperationError, match="size limit"):
        deployment_online._read_response(
            response,
            maximum=2,
            label="release metadata",
        )


def test_online_read_timeout_is_a_maintenance_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TimeoutResponse(_HTTPResponse):
        def read(self, size: int = -1) -> bytes:
            raise TimeoutError("network stalled")

    monkeypatch.setattr(
        deployment_online._URL_OPENER,
        "open",
        lambda request, timeout: TimeoutResponse(b"", request.full_url),
    )

    with pytest.raises(MaintenanceOperationError, match="Unable to download GitHub"):
        deployment_online._read_url(
            deployment_online.GITHUB_LATEST_RELEASE_URL,
            maximum=deployment_online.MAX_METADATA_BYTES,
            timeout=deployment_online.METADATA_TIMEOUT_SECONDS,
            label="release metadata",
            api=True,
        )


def test_online_asset_download_checks_metadata_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contents = b"downloaded release"
    release = _online_release("1.1.0", contents)
    invalid_asset = deployment_online._ReleaseAsset(
        release.package.name,
        release.package.url,
        release.package.size,
        "0" * 64,
    )
    monkeypatch.setattr(
        deployment_online._URL_OPENER,
        "open",
        lambda request, timeout: _HTTPResponse(
            contents,
            request.full_url,
            content_length=len(contents),
        ),
    )

    with pytest.raises(MaintenanceOperationError, match="release metadata"):
        deployment_online._download_asset(
            invalid_asset,
            tmp_path / invalid_asset.name,
            maximum=deployment.MAX_PACKAGE_BYTES,
        )


def test_online_update_downloads_verified_release_and_reuses_upgrade_transaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deployment"
    _prepare_deployment(root)
    release_root = tmp_path / "cfms-on-websocket-1.1.0"
    _write_release(release_root, "1.1.0", "online")
    package = tmp_path / "release.zip"
    with zipfile.ZipFile(package, "w") as archive:
        for path in release_root.rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(tmp_path).as_posix())
    package_contents = package.read_bytes()
    package_digest = hashlib.sha256(package_contents).hexdigest()
    package_name = "cfms-on-websocket-1.1.0.zip"
    checksum_contents = f"{package_digest}  {package_name}\n".encode()
    release = _online_release("1.1.0", package_contents, checksum_contents)
    requirements_lock = tmp_path / "requirements.lock"
    requirements_lock.write_text("", encoding="utf-8")

    monkeypatch.setattr(deployment_online, "_fetch_latest_release", lambda: release)

    def download(asset, target: Path, *, maximum: int) -> str:
        contents = package_contents if asset.name == package_name else checksum_contents
        target.write_bytes(contents)
        return hashlib.sha256(contents).hexdigest()

    monkeypatch.setattr(deployment_online, "_download_asset", download)
    monkeypatch.setattr(deployment, "_preflight_upgrade_database", lambda *args: None)
    monkeypatch.setattr(deployment, "_upgrade_database", lambda *args: None)
    monkeypatch.setattr(deployment, "_sync_environment", lambda *args: None)
    monkeypatch.setattr(
        deployment, "sync_config_template", lambda *args, **kwargs: None
    )

    result = deployment_online.update_online_deployment(
        root,
        extras=("cluster",),
        requirements_lock=requirements_lock,
    )

    assert result.status.update_available is True
    assert result.deployment is not None
    assert result.deployment.action == "upgrade"
    assert result.deployment.active_version == "1.1.0"
    assert (root / "src" / "main.py").read_text(encoding="utf-8") == "# online\n"
    assert (root / "src" / "content" / "files" / "production.dat").is_file()
    settings = json.loads(
        (root / "src" / ".maintenance" / "settings.json").read_text(encoding="utf-8")
    )
    assert settings["extras"] == ["cluster"]
    assert (root / "src" / ".maintenance" / "requirements.lock").is_file()
    assert not any((root / "src" / ".maintenance" / "staging").iterdir())


def test_online_update_is_noop_when_latest_is_not_newer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deployment"
    active = _prepare_deployment(root)
    monkeypatch.setattr(
        deployment_online,
        "_fetch_latest_release",
        lambda: _online_release(active.version),
    )
    monkeypatch.setattr(
        deployment_online,
        "_download_asset",
        lambda *args, **kwargs: pytest.fail("a no-op update must not download assets"),
    )

    result = deployment_online.update_online_deployment(root)

    assert result.deployment is None
    assert result.status.update_available is False
    assert not (root / "src" / ".maintenance").exists()


def test_online_update_cleans_downloads_after_checksum_mismatch(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deployment"
    _prepare_deployment(root)
    package_contents = b"release"
    checksum_contents = f"{'0' * 64}  cfms-on-websocket-1.1.0.zip\n".encode()
    release = _online_release("1.1.0", package_contents, checksum_contents)
    monkeypatch.setattr(deployment_online, "_fetch_latest_release", lambda: release)

    def download(asset, target: Path, *, maximum: int) -> str:
        contents = (
            package_contents
            if asset.name == release.package.name
            else checksum_contents
        )
        target.write_bytes(contents)
        return hashlib.sha256(contents).hexdigest()

    monkeypatch.setattr(deployment_online, "_download_asset", download)

    with pytest.raises(MaintenanceOperationError, match="SHA256SUMS.txt"):
        deployment_online.update_online_deployment(root)

    assert not any((root / "src" / ".maintenance" / "staging").iterdir())
    assert deployment._active_release(root).version == "1.0.0"


def test_online_update_rejects_running_server_and_cleans_downloads(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deployment"
    _prepare_deployment(root)
    package_contents = b"release"
    package_digest = hashlib.sha256(package_contents).hexdigest()
    package_name = "cfms-on-websocket-1.1.0.zip"
    checksum_contents = f"{package_digest}  {package_name}\n".encode()
    release = _online_release("1.1.0", package_contents, checksum_contents)
    monkeypatch.setattr(deployment_online, "_fetch_latest_release", lambda: release)

    def download(asset, target: Path, *, maximum: int) -> str:
        contents = package_contents if asset.name == package_name else checksum_contents
        target.write_bytes(contents)
        return hashlib.sha256(contents).hexdigest()

    monkeypatch.setattr(deployment_online, "_download_asset", download)

    with (
        RuntimeLock(root / "src" / ".maintenance" / "server.lock"),
        pytest.raises(MaintenanceOperationError, match="already using runtime root"),
    ):
        deployment_online.update_online_deployment(root)

    assert not any((root / "src" / ".maintenance" / "staging").iterdir())
    assert deployment._active_release(root).version == "1.0.0"


def test_upgrade_rejects_incompatible_python_before_database_preflight(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deployment"
    _prepare_deployment(root)
    target_root = tmp_path / "target"
    target = _write_release(target_root, "1.1.0", "new")
    target.manifest["requires_python"] = ">=99"
    stage = root / "src" / ".maintenance" / "staging" / "stage"
    stage.mkdir(parents=True)
    package = tmp_path / "release.zip"
    package.write_bytes(b"release")
    preflight_called = False

    monkeypatch.setattr(
        deployment,
        "_stage_release",
        lambda *args, **kwargs: (target, hashlib.sha256(b"release").hexdigest(), stage),
    )

    def preflight(*args) -> None:
        nonlocal preflight_called
        preflight_called = True

    monkeypatch.setattr(deployment, "_preflight_upgrade_database", preflight)

    with pytest.raises(MaintenanceOperationError, match="requires Python"):
        deployment.upgrade_deployment(package, root)

    assert preflight_called is False
    assert deployment._active_release(root).version == "1.0.0"


def test_deployment_check_cli_displays_online_status(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deployment"
    status = deployment_online.OnlineDeploymentStatus(
        root,
        "1.0.0",
        "1.1.0",
        True,
        dt.datetime(2026, 9, 10, tzinfo=dt.UTC),
        "https://github.com/cfms-dev/cfms_on_websocket/releases/tag/v1.1.0",
    )
    monkeypatch.setattr(
        "maintenance.cli.operations.inspect_online_deployment",
        lambda deployment_root: status,
    )

    result = CliRunner().invoke(
        app,
        ["deployment", "check", "--deployment-root", str(root)],
    )

    assert result.exit_code == 0
    assert "CFMS Online Update" in result.output
    assert "1.0.0" in result.output
    assert "1.1.0" in result.output
    assert "Available" in result.output


def test_deployment_update_cli_reports_noop_and_honors_confirmation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deployment"
    status = deployment_online.OnlineDeploymentStatus(
        root,
        "1.0.0",
        "1.0.0",
        False,
        dt.datetime(2026, 9, 10, tzinfo=dt.UTC),
        "https://github.com/cfms-dev/cfms_on_websocket/releases/tag/v1.0.0",
    )
    calls = 0

    def update(*args, **kwargs):
        nonlocal calls
        calls += 1
        return deployment_online.OnlineDeploymentUpdateResult(status, None)

    monkeypatch.setattr(
        "maintenance.cli.operations.update_online_deployment",
        update,
    )
    runner = CliRunner()
    args = ["deployment", "update", "--deployment-root", str(root)]

    aborted = runner.invoke(app, args, input="n\n")
    updated = runner.invoke(app, [*args, "--yes"])

    assert aborted.exit_code == 1
    assert "Aborted" in aborted.output
    assert updated.exit_code == 0
    assert "Up to date" in updated.output
    assert calls == 1


def test_upgrade_and_downgrade_preserve_flat_persistent_state(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deployment"
    source = _prepare_deployment(root)
    target_tree = tmp_path / "target"
    staged_target = _write_release(target_tree, "1.1.0", "new")
    stage = root / "src" / ".maintenance" / "staging" / "stage"
    stage.mkdir(parents=True)
    package = tmp_path / "release.zip"
    package.write_bytes(b"release")

    monkeypatch.setattr(
        deployment,
        "_stage_release",
        lambda *args, **kwargs: (staged_target, "a" * 64, stage),
    )
    monkeypatch.setattr(deployment, "_sync_environment", lambda *args: None)
    monkeypatch.setattr(deployment, "_preflight_upgrade_database", lambda *args: None)
    monkeypatch.setattr(deployment, "_preflight_downgrade_database", lambda *args: None)
    monkeypatch.setattr(deployment, "_upgrade_database", lambda *args: None)
    monkeypatch.setattr(deployment, "_downgrade_database", lambda *args: None)
    monkeypatch.setattr(
        deployment, "sync_config_template", lambda *args, **kwargs: None
    )

    upgraded = deployment.upgrade_deployment(
        package,
        root,
        expected_sha256="a" * 64,
    )

    assert upgraded.active_version == "1.1.0"
    assert upgraded.active_release_id == staged_target.release_id
    assert (root / "src" / "main.py").read_text(encoding="utf-8") == "# new\n"
    assert (
        root / "src" / "include" / "extensions" / "builtin" / "_extension.py"
    ).read_text(encoding="utf-8") == "# new builtin\n"
    assert (root / "src" / "include" / "extensions" / "custom-dir").is_dir()
    assert (root / "src" / "content" / "files" / "production.dat").is_file()
    assert (root / "src" / "content" / "logs" / "server.log").is_file()
    assert not (root / "shared").exists()
    assert not (root / "releases").exists()
    assert (
        root
        / "src"
        / ".maintenance"
        / "versions"
        / source.release_id
        / "release"
        / "src"
        / "main.py"
    ).is_file()

    (root / "src" / "config.toml").write_text("new config\n", encoding="utf-8")
    _write_extension(root, "later-dir", "later", "# installed after upgrade\n")

    downgraded = deployment.downgrade_deployment(
        source.release_id[:12],
        root,
    )

    assert downgraded.active_release_id == source.release_id
    assert (root / "src" / "main.py").read_text(encoding="utf-8") == "# old\n"
    assert (root / "src" / "config.toml").read_text(encoding="utf-8") == "old config\n"
    assert (root / "src" / "include" / "extensions" / "custom-dir").is_dir()
    assert not (root / "src" / "include" / "extensions" / "later-dir").exists()
    assert (root / "src" / "content" / "files" / "production.dat").is_file()

    status = deployment.inspect_deployment(root)
    assert status.active_release_id == source.release_id
    assert {item.release_id for item in status.versions} == {
        source.release_id,
        staged_target.release_id,
    }


def test_upgrade_allows_missing_external_package_digest(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deployment"
    _prepare_deployment(root)
    staged_target = _write_release(tmp_path / "target", "1.1.0", "new")
    stage = root / "src" / ".maintenance" / "staging" / "stage"
    stage.mkdir(parents=True)
    monkeypatch.setattr(
        deployment,
        "_stage_release",
        lambda *args, **kwargs: (staged_target, "a" * 64, stage),
    )
    monkeypatch.setattr(deployment, "_preflight_upgrade_database", lambda *args: None)
    monkeypatch.setattr(deployment, "_sync_environment", lambda *args: None)
    monkeypatch.setattr(deployment, "_upgrade_database", lambda *args: None)
    monkeypatch.setattr(
        deployment, "sync_config_template", lambda *args, **kwargs: None
    )

    result = deployment.upgrade_deployment(tmp_path / "release.zip", root)

    assert result.active_release_id == staged_target.release_id
    assert result.package_sha256 == "a" * 64


def test_upgrade_preflight_rejects_unversioned_database_before_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deployment"
    source = _write_release(root, "1.0.0", "old", with_migrations=True)
    shutil.copy2(
        PROJECT_ROOT / "src" / "config.toml.sample",
        root / "src" / "config.toml",
    )
    engine = deployment._database_engine(root)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql("CREATE TABLE legacy_state (id INTEGER)")
    finally:
        engine.dispose()

    staged_target = _write_release(
        tmp_path / "target",
        "1.1.0",
        "new",
        with_migrations=True,
    )
    stage = root / "src" / ".maintenance" / "staging" / "stage"
    stage.mkdir(parents=True)
    monkeypatch.setattr(
        deployment,
        "_stage_release",
        lambda *args, **kwargs: (staged_target, "a" * 64, stage),
    )
    original_manifest = (root / "release-manifest.json").read_bytes()

    with pytest.raises(
        MaintenanceOperationError,
        match="verify that its schema matches the active release",
    ):
        deployment.upgrade_deployment(tmp_path / "release.zip", root)

    assert deployment._active_release(root).release_id == source.release_id
    assert (root / "release-manifest.json").read_bytes() == original_manifest
    assert (root / "src" / "main.py").read_text(encoding="utf-8") == "# old\n"
    assert not (root / "src" / ".maintenance" / "transaction.json").exists()
    assert not (root / "src" / ".maintenance" / "settings.json").exists()
    assert not (root / "src" / ".maintenance" / "versions").exists()
    assert not stage.exists()


def test_upgrade_uses_stored_source_scripts_after_activating_target(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deployment"
    source = _write_release(root, "1.0.0", "old", with_migrations=True)
    shutil.copy2(
        PROJECT_ROOT / "src" / "config.toml.sample",
        root / "src" / "config.toml",
    )
    engine = deployment._database_engine(root)
    try:
        with deployment._suppress_bytecode_writes(), engine.begin() as connection:
            _, source_scripts, source_head = deployment._alembic(source)
            MigrationContext.configure(connection).stamp(source_scripts, source_head)
    finally:
        engine.dispose()

    target_revision = "deployment_full_upgrade_head"
    staged_target = _write_release(
        tmp_path / "target",
        "1.1.0",
        "new",
        with_migrations=True,
        migration=(target_revision, source_head),
    )
    stage = root / "src" / ".maintenance" / "staging" / "stage"
    stage.mkdir(parents=True)
    monkeypatch.setattr(
        deployment,
        "_stage_release",
        lambda *args, **kwargs: (staged_target, "a" * 64, stage),
    )
    monkeypatch.setattr(deployment, "_sync_environment", lambda *args: None)
    monkeypatch.setattr(
        deployment, "sync_config_template", lambda *args, **kwargs: None
    )

    result = deployment.upgrade_deployment(tmp_path / "release.zip", root)

    assert result.active_release_id == staged_target.release_id
    engine = deployment._database_engine(root)
    try:
        with engine.connect() as connection:
            assert deployment._current_revision(connection) == target_revision
    finally:
        engine.dispose()
    versions_root = root / "src" / ".maintenance" / "versions"
    assert not tuple(versions_root.rglob("*.pyc"))
    assert (
        deployment.inspect_deployment(root).active_release_id
        == result.active_release_id
    )


def test_failed_migration_resume_reconciles_to_restored_database_revision(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deployment"
    source = _prepare_deployment(root)
    staged_target = _write_release(tmp_path / "target", "1.1.0", "new")
    stage = root / "src" / ".maintenance" / "staging" / "stage"
    stage.mkdir(parents=True)
    monkeypatch.setattr(
        deployment,
        "_stage_release",
        lambda *args, **kwargs: (staged_target, "a" * 64, stage),
    )
    monkeypatch.setattr(deployment, "_sync_environment", lambda *args: None)
    monkeypatch.setattr(deployment, "_preflight_upgrade_database", lambda *args: None)
    monkeypatch.setattr(
        deployment, "sync_config_template", lambda *args, **kwargs: None
    )

    def fail_database(*_args) -> None:
        raise MaintenanceOperationError("migration failed")

    monkeypatch.setattr(deployment, "_upgrade_database", fail_database)

    with pytest.raises(MaintenanceOperationError, match="migration failed"):
        deployment.upgrade_deployment(
            tmp_path / "release.zip",
            root,
            expected_sha256="a" * 64,
        )

    transaction_path = root / "src" / ".maintenance" / "transaction.json"
    assert json.loads(transaction_path.read_text(encoding="utf-8"))["phase"] == (
        "database-recovery-required"
    )

    class _ConnectionContext:
        def __enter__(self):
            return object()

        def __exit__(self, *args):
            return False

    class _Engine:
        def connect(self):
            return _ConnectionContext()

        def dispose(self):
            pass

    monkeypatch.setattr(deployment, "_database_engine", lambda *args: _Engine())
    monkeypatch.setattr(
        deployment,
        "_alembic",
        lambda release, *args: (
            None,
            None,
            "source-head" if release.release_id == source.release_id else "target-head",
        ),
    )
    monkeypatch.setattr(deployment, "_current_revision", lambda *args: "other-head")

    with pytest.raises(MaintenanceOperationError, match="matches neither"):
        deployment.resume_deployment(root)

    assert transaction_path.exists()

    monkeypatch.setattr(deployment, "_current_revision", lambda *args: "source-head")

    resumed = deployment.resume_deployment(root)

    assert resumed.active_release_id == source.release_id
    assert not transaction_path.exists()
    assert (root / "src" / "main.py").read_text(encoding="utf-8") == "# old\n"


def test_status_removes_stored_bytecode_but_rejects_other_extra_files(
    tmp_path: Path,
) -> None:
    root = tmp_path / "deployment"
    active = _prepare_deployment(root)
    snapshot = deployment._snapshot_release(root, active)
    cache = snapshot / "src" / "alembic" / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "env.cpython-314.pyc").write_bytes(b"generated")

    status = deployment.inspect_deployment(root)

    assert status.active_release_id == active.release_id
    assert not cache.exists()

    (snapshot / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
    with pytest.raises(MaintenanceOperationError, match="do not match its manifest"):
        deployment.inspect_deployment(root)


def test_prune_removes_only_inactive_stored_releases(tmp_path: Path) -> None:
    root = tmp_path / "deployment"
    active = _prepare_deployment(root)
    inactive = (
        _write_release(tmp_path / "release-1", "0.8.0", "first old release"),
        _write_release(tmp_path / "release-2", "0.9.0", "second old release"),
    )
    for release in (active, *inactive):
        deployment._snapshot_release(root, release)
        state = (
            root / "src" / ".maintenance" / "versions" / release.release_id / "state"
        )
        state.mkdir()
        (state / "config.toml").write_text(
            f"{release.version} config\n", encoding="utf-8"
        )
    maintenance_root = root / "src" / ".maintenance"
    (maintenance_root / "settings.json").write_text("settings\n", encoding="utf-8")
    (maintenance_root / "requirements.lock").write_text(
        "requirements\n", encoding="utf-8"
    )
    unknown = maintenance_root / "versions" / "operator-note"
    unknown.mkdir()
    (unknown / "README.txt").write_text("keep me\n", encoding="utf-8")

    result = deployment.prune_deployment(
        root,
        expected_release_ids=tuple(release.release_id for release in inactive),
    )

    assert result.active_release_id == active.release_id
    assert result.active_version == active.version
    assert {release.release_id for release in result.removed_versions} == {
        release.release_id for release in inactive
    }
    versions_root = maintenance_root / "versions"
    assert (versions_root / active.release_id).is_dir()
    assert all(
        not (versions_root / release.release_id).exists() for release in inactive
    )
    assert (root / "src" / "main.py").read_text(encoding="utf-8") == "# old\n"
    assert (root / "src" / "config.toml").read_text(encoding="utf-8") == (
        "old config\n"
    )
    assert (root / "src" / "content" / "files" / "production.dat").is_file()
    assert (maintenance_root / "settings.json").read_text(encoding="utf-8") == (
        "settings\n"
    )
    assert (maintenance_root / "requirements.lock").read_text(encoding="utf-8") == (
        "requirements\n"
    )
    assert (unknown / "README.txt").read_text(encoding="utf-8") == "keep me\n"
    status = deployment.inspect_deployment(root)
    assert [(version.release_id, version.active) for version in status.versions] == [
        (active.release_id, True)
    ]


def test_prune_is_idempotent_without_inactive_releases(tmp_path: Path) -> None:
    root = tmp_path / "deployment"
    active = _prepare_deployment(root)

    first = deployment.prune_deployment(root, expected_release_ids=())
    second = deployment.prune_deployment(root, expected_release_ids=())

    assert first.active_release_id == active.release_id
    assert first.removed_versions == ()
    assert second.removed_versions == ()
    assert deployment.inspect_deployment(root).versions == (
        deployment.DeploymentVersion(active.release_id, active.version, True),
    )


def test_prune_rejects_changed_candidates_before_deletion(tmp_path: Path) -> None:
    root = tmp_path / "deployment"
    _prepare_deployment(root)
    inactive = _write_release(tmp_path / "inactive", "0.9.0", "inactive")
    snapshot = deployment._snapshot_release(root, inactive).parent

    with pytest.raises(
        MaintenanceOperationError, match="changed after the prune preview"
    ):
        deployment.prune_deployment(root, expected_release_ids=())

    assert snapshot.is_dir()


def test_prune_requires_full_ids_and_never_accepts_the_active_release(
    tmp_path: Path,
) -> None:
    root = tmp_path / "deployment"
    active = _prepare_deployment(root)
    inactive = _write_release(tmp_path / "inactive", "0.9.0", "inactive")
    inactive_root = deployment._snapshot_release(root, inactive).parent

    with pytest.raises(MaintenanceOperationError, match="full SHA-256"):
        deployment.prune_deployment(
            root,
            expected_release_ids=(inactive.release_id[:12],),
        )
    with pytest.raises(MaintenanceOperationError, match="active release cannot"):
        deployment.prune_deployment(
            root,
            expected_release_ids=(active.release_id,),
        )

    assert inactive_root.is_dir()


def test_prune_rejects_unfinished_transaction_and_runtime_owner(
    tmp_path: Path,
) -> None:
    root = tmp_path / "deployment"
    _prepare_deployment(root)
    inactive = _write_release(tmp_path / "inactive", "0.9.0", "inactive")
    snapshot = deployment._snapshot_release(root, inactive).parent
    maintenance_root = root / "src" / ".maintenance"
    transaction_path = maintenance_root / "transaction.json"
    transaction_path.write_text("{}", encoding="utf-8")

    with pytest.raises(MaintenanceOperationError, match="unfinished deployment"):
        deployment.prune_deployment(
            root,
            expected_release_ids=(inactive.release_id,),
        )
    assert snapshot.is_dir()

    transaction_path.unlink()
    with (
        RuntimeLock(maintenance_root / "server.lock"),
        pytest.raises(MaintenanceOperationError, match="already using runtime root"),
    ):
        deployment.prune_deployment(
            root,
            expected_release_ids=(inactive.release_id,),
        )
    assert snapshot.is_dir()


def test_prune_rechecks_transaction_after_acquiring_the_runtime_lock(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deployment"
    _prepare_deployment(root)
    inactive = _write_release(tmp_path / "inactive", "0.9.0", "inactive")
    inactive_root = deployment._snapshot_release(root, inactive).parent
    transaction_path = root / "src" / ".maintenance" / "transaction.json"

    class _Lock:
        released = False

        def acquire(self):
            transaction_path.write_text("{}", encoding="utf-8")
            return self

        def release(self):
            self.released = True

    lock = _Lock()
    monkeypatch.setattr(deployment, "server_runtime_lock", lambda *args: lock)

    with pytest.raises(MaintenanceOperationError, match="unfinished deployment"):
        deployment.prune_deployment(
            root,
            expected_release_ids=(inactive.release_id,),
        )

    assert lock.released is True
    assert inactive_root.is_dir()


def test_prune_validates_every_stored_release_before_deletion(tmp_path: Path) -> None:
    root = tmp_path / "deployment"
    _prepare_deployment(root)
    valid = _write_release(tmp_path / "valid", "0.8.0", "valid")
    corrupt = _write_release(tmp_path / "corrupt", "0.9.0", "corrupt")
    valid_root = deployment._snapshot_release(root, valid).parent
    corrupt_root = deployment._snapshot_release(root, corrupt).parent
    mismatched_root = corrupt_root.with_name("f" * 64)
    corrupt_root.rename(mismatched_root)

    with pytest.raises(MaintenanceOperationError, match="does not match its directory"):
        deployment.prune_deployment(
            root,
            expected_release_ids=(valid.release_id, corrupt.release_id),
        )

    assert valid_root.is_dir()
    assert mismatched_root.is_dir()


def test_prune_rejects_hash_named_non_directory_entries(tmp_path: Path) -> None:
    root = tmp_path / "deployment"
    _prepare_deployment(root)
    invalid = root / "src" / ".maintenance" / "versions" / ("a" * 64)
    invalid.parent.mkdir(parents=True)
    invalid.write_text("not a release directory\n", encoding="utf-8")

    with pytest.raises(MaintenanceOperationError, match="not a regular directory"):
        deployment.prune_deployment(root, expected_release_ids=())

    assert invalid.is_file()


def test_prune_reports_partial_filesystem_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deployment"
    active = _prepare_deployment(root)
    inactive = (
        _write_release(tmp_path / "release-1", "0.8.0", "first old release"),
        _write_release(tmp_path / "release-2", "0.9.0", "second old release"),
    )
    version_roots = sorted(
        deployment._snapshot_release(root, release).parent for release in inactive
    )
    real_rmtree = shutil.rmtree
    removals = []

    def fail_second_removal(path: Path, *args, **kwargs) -> None:
        removals.append(path)
        if len(removals) == 2:
            raise OSError("storage unavailable")
        real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(deployment.shutil, "rmtree", fail_second_removal)

    with pytest.raises(
        MaintenanceOperationError, match=r"after pruning 1 release\(s\)"
    ):
        deployment.prune_deployment(
            root,
            expected_release_ids=tuple(release.release_id for release in inactive),
        )

    assert not version_roots[0].exists()
    assert version_roots[1].is_dir()
    assert deployment._active_release(root).release_id == active.release_id


def test_deployment_prune_cli_dry_run_abort_and_yes(tmp_path: Path) -> None:
    root = tmp_path / "deployment"
    _prepare_deployment(root)
    inactive = _write_release(tmp_path / "inactive", "0.9.0", "inactive")
    inactive_root = deployment._snapshot_release(root, inactive).parent
    runner = CliRunner()
    args = ["deployment", "prune", "--deployment-root", str(root)]

    dry_run = runner.invoke(app, [*args, "--dry-run"])

    assert dry_run.exit_code == 0
    assert "Stored Releases to Prune" in dry_run.output
    assert inactive.version in dry_run.output
    assert inactive_root.is_dir()

    aborted = runner.invoke(app, args, input="n\n")

    assert aborted.exit_code == 1
    assert "Aborted" in aborted.output
    assert inactive_root.is_dir()

    pruned = runner.invoke(app, [*args, "--yes"])

    assert pruned.exit_code == 0
    assert "Removed releases" in pruned.output
    assert "Pruned Releases" in pruned.output
    assert not inactive_root.exists()


def test_resume_rejects_concurrent_runtime_owner(tmp_path: Path) -> None:
    root = tmp_path / "deployment"
    transaction_path = root / "src" / ".maintenance" / "transaction.json"
    transaction_path.parent.mkdir(parents=True)
    transaction_path.write_text("{}", encoding="utf-8")
    (root / "pyproject.toml").write_text("", encoding="utf-8")

    with (
        RuntimeLock(transaction_path.with_name("server.lock")),
        pytest.raises(MaintenanceOperationError, match="already using runtime root"),
    ):
        deployment.resume_deployment(root)

    assert transaction_path.is_file()


def _prepare_database_releases(
    tmp_path: Path,
) -> tuple[Path, deployment._Release, deployment._Release, str, str]:
    project_root = tmp_path / "deployment"
    source_root = tmp_path / "source"
    target_root = tmp_path / "target"
    for release_root in (source_root, target_root):
        (release_root / "src").mkdir(parents=True)
        shutil.copy2(PROJECT_ROOT / "src" / "alembic.ini", release_root / "src")
        shutil.copytree(
            PROJECT_ROOT / "src" / "alembic",
            release_root / "src" / "alembic",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )

    source_scripts = ScriptDirectory(str(source_root / "src" / "alembic"))
    source_head = source_scripts.get_current_head()
    target_revision = "deployment_test_head"
    (target_root / "src" / "alembic" / "versions" / f"{target_revision}.py").write_text(
        "\n".join(
            (
                '"""deployment test revision"""',
                f'revision = "{target_revision}"',
                f'down_revision = "{source_head}"',
                "branch_labels = None",
                "depends_on = None",
                "",
                "def upgrade():",
                "    pass",
                "",
                "def downgrade():",
                "    pass",
                "",
            )
        ),
        encoding="utf-8",
    )
    source = deployment._Release(source_root, {}, b"source", "1" * 64)
    target = deployment._Release(target_root, {}, b"target", "2" * 64)
    (project_root / "src").mkdir(parents=True)
    sample = (PROJECT_ROOT / "src" / "config.toml.sample").read_text(encoding="utf-8")
    (project_root / "src" / "config.toml").write_text(sample, encoding="utf-8")
    return project_root, source, target, source_head, target_revision


def test_database_upgrade_rejects_unversioned_database_without_stamping(
    tmp_path: Path,
) -> None:
    project_root, source, target, _, _ = _prepare_database_releases(tmp_path)

    with pytest.raises(MaintenanceOperationError, match="no Alembic revision"):
        deployment._upgrade_database(project_root, source, target)

    engine = deployment._database_engine(project_root)
    try:
        with engine.connect() as connection:
            assert MigrationContext.configure(connection).get_current_revision() is None
    finally:
        engine.dispose()


def test_database_upgrade_and_downgrade_require_versioned_database(
    tmp_path: Path,
) -> None:
    project_root, source, target, source_head, target_revision = (
        _prepare_database_releases(tmp_path)
    )
    source_scripts = ScriptDirectory(str(source.root / "src" / "alembic"))
    engine = deployment._database_engine(project_root)
    try:
        with engine.begin() as connection:
            MigrationContext.configure(connection).stamp(source_scripts, source_head)
    finally:
        engine.dispose()

    deployment._preflight_upgrade_database(project_root, source, target)
    deployment._upgrade_database(project_root, source, target)
    assert not tuple(target.root.rglob("*.pyc"))
    engine = deployment._database_engine(project_root)
    try:
        with engine.connect() as connection:
            assert (
                MigrationContext.configure(connection).get_current_revision()
                == target_revision
            )
    finally:
        engine.dispose()

    for cache in source.root.rglob("__pycache__"):
        shutil.rmtree(cache)
    deployment._preflight_downgrade_database(project_root, target, source)
    deployment._downgrade_database(project_root, target, source)
    assert not tuple(source.root.rglob("*.pyc"))
    assert not tuple(target.root.rglob("*.pyc"))
    engine = deployment._database_engine(project_root)
    try:
        with engine.connect() as connection:
            assert (
                MigrationContext.configure(connection).get_current_revision()
                == source_head
            )
    finally:
        engine.dispose()
