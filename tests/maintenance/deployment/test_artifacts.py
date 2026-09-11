import hashlib
import json
import zipfile
from pathlib import Path

import pytest

import maintenance.operations.deployment as deployment
from maintenance.operations.deployment import (
    artifacts as deployment_artifacts,
)
from maintenance.operations.deployment import (
    repository as deployment_repository,
)
from maintenance.operations.exceptions import MaintenanceOperationError

from .support import _write_release


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
        deployment_repository._parse_manifest(json.dumps(manifest).encode())


def test_stage_rejects_path_traversal_before_writing_outside_root(
    tmp_path: Path,
) -> None:
    package = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("cfms-on-websocket-1.0.0/../../escape", b"unsafe")

    with pytest.raises(MaintenanceOperationError, match="Unsafe release archive path"):
        deployment_artifacts._stage_release(
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

    staged, package_digest, _ = deployment_artifacts._stage_release(
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
        deployment_artifacts._stage_release(
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
        deployment_artifacts._stage_release(
            package,
            tmp_path / "deployment",
            expected_sha256="a" * 64,
            checksums_path=checksums,
        )
