import hashlib
import json
import zipfile
from pathlib import Path

import pytest

from maintenance.operations import deployment
from maintenance.operations.exceptions import MaintenanceOperationError
from tools.build_release import build_release

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_DATE_EPOCH = 1_788_000_000


def _release(tmp_path: Path) -> tuple[Path, str]:
    package, _, _ = build_release(
        PROJECT_ROOT,
        tmp_path / "artifacts",
        "0.7.0",
        SOURCE_DATE_EPOCH,
    )
    return package, hashlib.sha256(package.read_bytes()).hexdigest()


def _write_extension(
    release_root: Path,
    directory_name: str,
    identifier: str,
    *,
    marker: str,
) -> Path:
    extension = release_root / "src" / "include" / "extensions" / directory_name
    extension.mkdir(parents=True)
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
    return extension


def _prepare_mock_upgrade(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[Path, Path, Path]:
    root = tmp_path / "deployment"
    shared = root / "shared"
    (shared / "run").mkdir(parents=True)
    (shared / "backups").mkdir()
    (shared / "config.toml").write_text("config\n", encoding="utf-8")
    (shared / "requirements.lock").write_text("", encoding="utf-8")
    (root / "deployment.json").write_text(
        json.dumps(
            {
                "active_version": "0.7.0",
                "extras": [],
                "format_version": 1,
            }
        ),
        encoding="utf-8",
    )
    current = root / "releases" / "0.7.0"
    current.mkdir(parents=True)
    stage = root / "releases" / ".stage"
    stage.mkdir()
    target = root / "releases" / "0.8.0"

    monkeypatch.setattr(
        deployment,
        "_stage_release",
        lambda *args, **kwargs: (
            stage,
            {
                "managed_extensions": [],
                "minimum_upgrade_version": "0.7.0",
                "version": "0.8.0",
            },
            "a" * 64,
        ),
    )

    def install_release(*args, **kwargs):
        launcher = target / "src" / "deployment_launcher.py"
        launcher.parent.mkdir(parents=True)
        launcher.write_text("launcher\n", encoding="utf-8")
        return target

    monkeypatch.setattr(deployment, "_install_staged_release", install_release)
    monkeypatch.setattr(
        deployment, "_release_managed_extensions", lambda *args: frozenset()
    )
    monkeypatch.setattr(deployment, "_copy_third_party_extensions", lambda *args: ())
    monkeypatch.setattr(deployment, "_sync_packaged_ca", lambda *args: None)
    monkeypatch.setattr(deployment, "_preflight_certificates", lambda *args: None)
    monkeypatch.setattr(deployment, "_run_maintenance", lambda *args: None)
    monkeypatch.setattr(
        deployment, "_sqlite_backup", lambda *args: tmp_path / "backup.db"
    )
    return root, current, target


def test_install_creates_versioned_state_without_activating_early(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, digest = _release(tmp_path)
    monkeypatch.setattr(deployment, "_sync_environment", lambda *args: None)
    monkeypatch.setattr(deployment, "_run_maintenance", lambda *args: None)
    root = tmp_path / "deployment"

    result = deployment.install_deployment(
        package,
        root,
        expected_sha256=digest,
    )

    state = json.loads((root / "deployment.json").read_text(encoding="utf-8"))
    assert result.active_version == "0.7.0"
    assert state == {
        "active_version": "0.7.0",
        "extras": [],
        "format_version": 1,
    }
    release_root = root / "releases" / "0.7.0"
    assert (release_root / "release-manifest.json").is_file()
    assert (release_root / "src" / "include" / "extensions").is_dir()
    assert (root / "shared" / "config.toml").is_file()
    assert not (root / "shared" / "extensions").exists()
    assert (root / "main.py").read_bytes() == (
        release_root / "src" / "deployment_launcher.py"
    ).read_bytes()
    assert (root / "main.py").read_bytes() != (
        release_root / "src" / "main.py"
    ).read_bytes()


def test_install_rejects_archive_changed_after_manifest_generation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    package, _ = _release(tmp_path)
    tampered = tmp_path / "tampered.zip"
    with (
        zipfile.ZipFile(package) as source,
        zipfile.ZipFile(tampered, "w", compression=zipfile.ZIP_DEFLATED) as target,
    ):
        for info in source.infolist():
            contents = source.read(info)
            if info.filename.endswith("/README.md"):
                contents = b"changed\n"
            target.writestr(info, contents)
    digest = hashlib.sha256(tampered.read_bytes()).hexdigest()
    monkeypatch.setattr(deployment, "_sync_environment", lambda *args: None)

    with pytest.raises(MaintenanceOperationError, match="failed SHA-256"):
        deployment.install_deployment(
            tampered,
            tmp_path / "deployment",
            expected_sha256=digest,
        )


def test_install_rejects_path_traversal_before_writing_outside_root(
    tmp_path: Path,
) -> None:
    package = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr("cfms-on-websocket-0.8.0/../../escape", b"unsafe")
    digest = hashlib.sha256(package.read_bytes()).hexdigest()

    with pytest.raises(MaintenanceOperationError, match="Unsafe release archive path"):
        deployment.install_deployment(
            package,
            tmp_path / "deployment",
            expected_sha256=digest,
        )

    assert not (tmp_path / "escape").exists()


def test_release_validation_requires_separate_launcher(tmp_path: Path) -> None:
    target = tmp_path / "release"
    server_main = target / "src" / "main.py"
    server_main.parent.mkdir(parents=True)
    server_main.write_text("pass\n", encoding="utf-8")
    (target / "release-manifest.json").write_text(
        json.dumps(
            {
                "alembic_head": "head",
                "files": {
                    "src/main.py": hashlib.sha256(server_main.read_bytes()).hexdigest()
                },
                "format_version": 1,
                "managed_extensions": [],
                "minimum_upgrade_version": "0.7.0",
                "product": "cfms-on-websocket",
                "requires_python": ">=3.14",
                "version": "0.7.0",
            }
        ),
        encoding="utf-8",
    )

    with pytest.raises(
        MaintenanceOperationError,
        match="src/deployment_launcher.py",
    ):
        deployment._validate_release(target, "cfms-on-websocket-0.7.0")


def test_copy_third_party_extensions_keeps_new_packaged_versions(
    tmp_path: Path,
) -> None:
    current = tmp_path / "current"
    target = tmp_path / "target"
    _write_extension(current, "official", "official", marker="old official\n")
    custom = _write_extension(current, "custom-dir", "custom", marker="custom\n")
    packaged = _write_extension(target, "official", "official", marker="new official\n")

    copied = deployment._copy_third_party_extensions(
        current,
        target,
        frozenset({"official"}),
        frozenset({"official"}),
    )

    assert copied == ("custom",)
    assert (packaged / "_extension.py").read_text(encoding="utf-8") == "new official\n"
    assert (
        target / "src" / "include" / "extensions" / custom.name / "_extension.py"
    ).read_text(encoding="utf-8") == "custom\n"


def test_copy_third_party_extensions_rejects_new_packaged_identifier(
    tmp_path: Path,
) -> None:
    current = tmp_path / "current"
    target = tmp_path / "target"
    _write_extension(current, "custom-dir", "claimed", marker="custom\n")
    _write_extension(target, "official", "claimed", marker="official\n")

    with pytest.raises(
        MaintenanceOperationError, match="conflicts with the new release"
    ):
        deployment._copy_third_party_extensions(
            current,
            target,
            frozenset(),
            frozenset({"claimed"}),
        )


def test_pending_cleanup_removes_inactive_release(tmp_path: Path) -> None:
    root = tmp_path / "deployment"
    shared = root / "shared"
    transaction_path = shared / "run" / "upgrade-transaction.json"
    transaction_path.parent.mkdir(parents=True)
    retired = root / "releases" / "0.7.0"
    retired.mkdir(parents=True)
    transaction_path.write_text(
        json.dumps(
            {
                "action": "upgrade",
                "from_version": "0.7.0",
                "phase": "cleanup-required",
                "to_version": "0.8.0",
            }
        ),
        encoding="utf-8",
    )

    deployment._complete_pending_cleanup(
        root,
        shared,
        deployment.DeploymentState(1, "0.8.0", ()),
    )

    assert not retired.exists()
    assert not transaction_path.exists()


def test_upgrade_activates_new_release_and_commits_cleanup(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, current, target = _prepare_mock_upgrade(tmp_path, monkeypatch)

    result = deployment.upgrade_deployment(
        tmp_path / "release.zip",
        root,
        expected_sha256="a" * 64,
    )

    assert result.active_version == "0.8.0"
    assert target.is_dir()
    transaction_path = root / "shared" / "run" / "upgrade-transaction.json"
    if deployment.os.name == "nt":
        assert current.is_dir()
        transaction = json.loads(transaction_path.read_text(encoding="utf-8"))
        assert transaction["phase"] == "cleanup-required"
    else:
        assert not current.exists()
        assert not transaction_path.exists()
    assert json.loads((root / "deployment.json").read_text(encoding="utf-8")) == {
        "active_version": "0.8.0",
        "extras": [],
        "format_version": 1,
    }


def test_cleanup_failure_keeps_new_release_active(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root, current, target = _prepare_mock_upgrade(tmp_path, monkeypatch)
    real_rmtree = deployment.shutil.rmtree
    target.mkdir(parents=True)
    state = deployment.DeploymentState(1, "0.8.0", ())
    deployment._write_state(root, state)
    deployment._write_transaction(
        root / "shared",
        {
            "action": "upgrade",
            "from_version": "0.7.0",
            "phase": "cleanup-required",
            "to_version": "0.8.0",
        },
    )

    def fail_old_release_cleanup(path, *args, **kwargs):
        if Path(path) == current:
            raise OSError("simulated cleanup failure")
        return real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(deployment.shutil, "rmtree", fail_old_release_cleanup)

    with pytest.raises(MaintenanceOperationError, match="Unable to remove"):
        deployment._complete_pending_cleanup(root, root / "shared", state)

    state = json.loads((root / "deployment.json").read_text(encoding="utf-8"))
    transaction = json.loads(
        (root / "shared" / "run" / "upgrade-transaction.json").read_text(
            encoding="utf-8"
        )
    )
    assert state["active_version"] == "0.8.0"
    assert transaction["phase"] == "cleanup-required"
    assert target.is_dir()
    assert current.is_dir()


def test_upgrade_migration_failure_restores_config_and_keeps_old_pointer(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "deployment"
    shared = root / "shared"
    (shared / "run").mkdir(parents=True)
    (shared / "backups").mkdir()
    config = shared / "config.toml"
    config.write_text("old\n", encoding="utf-8")
    (root / "deployment.json").write_text(
        json.dumps(
            {
                "active_version": "0.7.0",
                "extras": [],
                "format_version": 1,
            }
        ),
        encoding="utf-8",
    )
    stage = root / "releases" / ".stage"
    stage.mkdir(parents=True)
    release = root / "releases" / "0.8.0"

    monkeypatch.setattr(
        deployment,
        "_stage_release",
        lambda *args, **kwargs: (
            stage,
            {
                "managed_extensions": [],
                "minimum_upgrade_version": "0.7.0",
                "version": "0.8.0",
            },
            "a" * 64,
        ),
    )

    def install_release(*args, **kwargs):
        release.mkdir()
        return release

    monkeypatch.setattr(deployment, "_install_staged_release", install_release)
    monkeypatch.setattr(
        deployment, "_release_managed_extensions", lambda *args: frozenset()
    )
    monkeypatch.setattr(deployment, "_copy_third_party_extensions", lambda *args: ())
    monkeypatch.setattr(deployment, "_sync_packaged_ca", lambda *args: None)
    monkeypatch.setattr(deployment, "_preflight_certificates", lambda *args: None)
    monkeypatch.setattr(
        deployment, "_sqlite_backup", lambda *args: tmp_path / "backup.db"
    )

    def run_maintenance(release_root, shared_root, arguments):
        if arguments[:2] == ["config", "sync-template"]:
            config.write_text("new\n", encoding="utf-8")
        if arguments[:2] == ["database", "upgrade"]:
            raise MaintenanceOperationError("migration failed")

    monkeypatch.setattr(deployment, "_run_maintenance", run_maintenance)

    with pytest.raises(MaintenanceOperationError, match="migration failed"):
        deployment.upgrade_deployment(
            tmp_path / "release.zip",
            root,
            expected_sha256="a" * 64,
        )

    state = json.loads((root / "deployment.json").read_text(encoding="utf-8"))
    transaction = json.loads(
        (shared / "run" / "upgrade-transaction.json").read_text(encoding="utf-8")
    )
    assert state["active_version"] == "0.7.0"
    assert config.read_text(encoding="utf-8") == "old\n"
    assert transaction["phase"] == "recovery-required"
    assert release.is_dir()
