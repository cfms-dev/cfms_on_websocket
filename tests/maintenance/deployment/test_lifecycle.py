import datetime as dt
import hashlib
import json
import shutil
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from typer.testing import CliRunner

import maintenance.operations.deployment as deployment
from maintenance.cli import app
from maintenance.operations.deployment import (
    database as deployment_database,
)
from maintenance.operations.deployment import (
    lifecycle as deployment_lifecycle,
)
from maintenance.operations.deployment import (
    online as deployment_online,
)
from maintenance.operations.deployment import (
    repository as deployment_repository,
)
from maintenance.operations.exceptions import MaintenanceOperationError

from .support import (
    PROJECT_ROOT,
    _prepare_deployment,
    _write_extension,
    _write_release,
)


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
        deployment_lifecycle,
        "_stage_release",
        lambda *args, **kwargs: (target, hashlib.sha256(b"release").hexdigest(), stage),
    )

    def preflight(*args) -> None:
        nonlocal preflight_called
        preflight_called = True

    monkeypatch.setattr(deployment_lifecycle, "_preflight_upgrade_database", preflight)

    with pytest.raises(MaintenanceOperationError, match="requires Python"):
        deployment.upgrade_deployment(package, root)

    assert preflight_called is False
    assert deployment_repository._active_release(root).version == "1.0.0"


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
        "maintenance.cli.deployment.operations.inspect_online_deployment",
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
        "maintenance.cli.deployment.operations.update_online_deployment",
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
        deployment_lifecycle,
        "_stage_release",
        lambda *args, **kwargs: (staged_target, "a" * 64, stage),
    )
    monkeypatch.setattr(deployment_lifecycle, "_sync_environment", lambda *args: None)
    monkeypatch.setattr(
        deployment_lifecycle, "_preflight_upgrade_database", lambda *args: None
    )
    monkeypatch.setattr(
        deployment_lifecycle, "_preflight_downgrade_database", lambda *args: None
    )
    monkeypatch.setattr(deployment_lifecycle, "_upgrade_database", lambda *args: None)
    monkeypatch.setattr(deployment_lifecycle, "_downgrade_database", lambda *args: None)
    monkeypatch.setattr(
        deployment_lifecycle, "sync_config_template", lambda *args, **kwargs: None
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
        deployment_lifecycle,
        "_stage_release",
        lambda *args, **kwargs: (staged_target, "a" * 64, stage),
    )
    monkeypatch.setattr(
        deployment_lifecycle, "_preflight_upgrade_database", lambda *args: None
    )
    monkeypatch.setattr(deployment_lifecycle, "_sync_environment", lambda *args: None)
    monkeypatch.setattr(deployment_lifecycle, "_upgrade_database", lambda *args: None)
    monkeypatch.setattr(
        deployment_lifecycle, "sync_config_template", lambda *args, **kwargs: None
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
    engine = deployment_database._database_engine(root)
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
        deployment_lifecycle,
        "_stage_release",
        lambda *args, **kwargs: (staged_target, "a" * 64, stage),
    )
    original_manifest = (root / "release-manifest.json").read_bytes()

    with pytest.raises(
        MaintenanceOperationError,
        match="verify that its schema matches the active release",
    ):
        deployment.upgrade_deployment(tmp_path / "release.zip", root)

    assert deployment_repository._active_release(root).release_id == source.release_id
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
    engine = deployment_database._database_engine(root)
    try:
        with (
            deployment_database._suppress_bytecode_writes(),
            engine.begin() as connection,
        ):
            _, source_scripts, source_head = deployment_database._alembic(source)
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
        deployment_lifecycle,
        "_stage_release",
        lambda *args, **kwargs: (staged_target, "a" * 64, stage),
    )
    monkeypatch.setattr(deployment_lifecycle, "_sync_environment", lambda *args: None)
    monkeypatch.setattr(
        deployment_lifecycle, "sync_config_template", lambda *args, **kwargs: None
    )

    result = deployment.upgrade_deployment(tmp_path / "release.zip", root)

    assert result.active_release_id == staged_target.release_id
    engine = deployment_database._database_engine(root)
    try:
        with engine.connect() as connection:
            assert deployment_database._current_revision(connection) == target_revision
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
        deployment_lifecycle,
        "_stage_release",
        lambda *args, **kwargs: (staged_target, "a" * 64, stage),
    )
    monkeypatch.setattr(deployment_lifecycle, "_sync_environment", lambda *args: None)
    monkeypatch.setattr(
        deployment_lifecycle, "_preflight_upgrade_database", lambda *args: None
    )
    monkeypatch.setattr(
        deployment_lifecycle, "sync_config_template", lambda *args, **kwargs: None
    )

    def fail_database(*_args) -> None:
        raise MaintenanceOperationError("migration failed")

    monkeypatch.setattr(deployment_lifecycle, "_upgrade_database", fail_database)

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

    monkeypatch.setattr(
        deployment_lifecycle, "_database_engine", lambda *args: _Engine()
    )
    monkeypatch.setattr(
        deployment_lifecycle,
        "_alembic",
        lambda release, *args: (
            None,
            None,
            "source-head" if release.release_id == source.release_id else "target-head",
        ),
    )
    monkeypatch.setattr(
        deployment_lifecycle, "_current_revision", lambda *args: "other-head"
    )

    with pytest.raises(MaintenanceOperationError, match="matches neither"):
        deployment.resume_deployment(root)

    assert transaction_path.exists()

    monkeypatch.setattr(
        deployment_lifecycle, "_current_revision", lambda *args: "source-head"
    )

    resumed = deployment.resume_deployment(root)

    assert resumed.active_release_id == source.release_id
    assert not transaction_path.exists()
    assert (root / "src" / "main.py").read_text(encoding="utf-8") == "# old\n"


def test_status_removes_stored_bytecode_but_rejects_other_extra_files(
    tmp_path: Path,
) -> None:
    root = tmp_path / "deployment"
    active = _prepare_deployment(root)
    snapshot = deployment_repository._snapshot_release(root, active)
    cache = snapshot / "src" / "alembic" / "__pycache__"
    cache.mkdir(parents=True)
    (cache / "env.cpython-314.pyc").write_bytes(b"generated")

    status = deployment.inspect_deployment(root)

    assert status.active_release_id == active.release_id
    assert not cache.exists()

    (snapshot / "unexpected.txt").write_text("unexpected\n", encoding="utf-8")
    with pytest.raises(MaintenanceOperationError, match="do not match its manifest"):
        deployment.inspect_deployment(root)
