import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from include.runtime_lock import RuntimeLock
from maintenance.operations.deployment import (
    lifecycle as deployment_lifecycle,
)
from maintenance.operations.deployment import (
    online as deployment_online,
)
from maintenance.operations.deployment import (
    repository as deployment_repository,
)
from maintenance.operations.deployment.constants import MAX_PACKAGE_BYTES
from maintenance.operations.exceptions import MaintenanceOperationError

from .support import (
    _HTTPResponse,
    _online_metadata,
    _online_release,
    _prepare_deployment,
    _write_release,
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
        metadata["assets"][0]["size"] = MAX_PACKAGE_BYTES + 1
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
            maximum=MAX_PACKAGE_BYTES,
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
    monkeypatch.setattr(
        deployment_lifecycle, "_preflight_upgrade_database", lambda *args: None
    )
    monkeypatch.setattr(deployment_lifecycle, "_upgrade_database", lambda *args: None)
    monkeypatch.setattr(deployment_lifecycle, "_sync_environment", lambda *args: None)
    monkeypatch.setattr(
        deployment_lifecycle, "sync_config_template", lambda *args, **kwargs: None
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
    assert deployment_repository._active_release(root).version == "1.0.0"


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
    assert deployment_repository._active_release(root).version == "1.0.0"
