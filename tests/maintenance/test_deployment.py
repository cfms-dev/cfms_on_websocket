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
    assert state["active_version"] == "0.7.0"
    assert state["previous_version"] is None
    release_root = root / "releases" / "0.7.0"
    assert (release_root / "release-manifest.json").is_file()
    assert (root / "shared" / "config.toml").is_file()
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


def test_rollback_restores_pointer_and_configuration(tmp_path: Path) -> None:
    root = tmp_path / "deployment"
    shared = root / "shared"
    (shared / "run").mkdir(parents=True)
    (shared / "config.toml").write_text("new\n", encoding="utf-8")
    snapshot = shared / "backups" / "old.toml"
    snapshot.parent.mkdir()
    snapshot.write_text("old\n", encoding="utf-8")
    previous = root / "releases" / "0.7.0" / ".venv"
    interpreter = (
        previous / "Scripts" / "python.exe"
        if deployment.os.name == "nt"
        else previous / "bin" / "python"
    )
    interpreter.parent.mkdir(parents=True)
    interpreter.write_bytes(b"")
    launcher = previous.parent / "src" / "deployment_launcher.py"
    launcher.parent.mkdir()
    launcher.write_text("old launcher\n", encoding="utf-8")
    (root / "main.py").write_text("new launcher\n", encoding="utf-8")
    (root / "deployment.json").write_text(
        json.dumps(
            {
                "active_version": "0.8.0",
                "extras": [],
                "format_version": 1,
                "previous_version": "0.7.0",
                "rollback_config": "shared/backups/old.toml",
            }
        ),
        encoding="utf-8",
    )

    result = deployment.rollback_deployment(root)

    assert result.active_version == "0.7.0"
    assert (shared / "config.toml").read_text(encoding="utf-8") == "old\n"
    assert (root / "main.py").read_text(encoding="utf-8") == "old launcher\n"
    state = json.loads((root / "deployment.json").read_text(encoding="utf-8"))
    assert state["active_version"] == "0.7.0"
    assert state["previous_version"] == "0.8.0"


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
                "previous_version": None,
                "rollback_config": None,
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
            {"minimum_upgrade_version": "0.7.0", "version": "0.8.0"},
            "a" * 64,
        ),
    )

    def install_release(*args, **kwargs):
        release.mkdir()
        return release

    monkeypatch.setattr(deployment, "_install_staged_release", install_release)
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
