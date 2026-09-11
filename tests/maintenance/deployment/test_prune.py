import shutil
from pathlib import Path

import pytest
from typer.testing import CliRunner

import maintenance.operations.deployment as deployment
from include.runtime_lock import RuntimeLock
from maintenance.cli import app
from maintenance.operations.deployment import (
    lifecycle as deployment_lifecycle,
)
from maintenance.operations.deployment import (
    repository as deployment_repository,
)
from maintenance.operations.exceptions import MaintenanceOperationError

from .support import _prepare_deployment, _write_release


def test_prune_removes_only_inactive_stored_releases(tmp_path: Path) -> None:
    root = tmp_path / "deployment"
    active = _prepare_deployment(root)
    inactive = (
        _write_release(tmp_path / "release-1", "0.8.0", "first old release"),
        _write_release(tmp_path / "release-2", "0.9.0", "second old release"),
    )
    for release in (active, *inactive):
        deployment_repository._snapshot_release(root, release)
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
    snapshot = deployment_repository._snapshot_release(root, inactive).parent

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
    inactive_root = deployment_repository._snapshot_release(root, inactive).parent

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
    snapshot = deployment_repository._snapshot_release(root, inactive).parent
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
    inactive_root = deployment_repository._snapshot_release(root, inactive).parent
    transaction_path = root / "src" / ".maintenance" / "transaction.json"

    class _Lock:
        released = False

        def acquire(self):
            transaction_path.write_text("{}", encoding="utf-8")
            return self

        def release(self):
            self.released = True

    lock = _Lock()
    monkeypatch.setattr(deployment_lifecycle, "server_runtime_lock", lambda *args: lock)

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
    valid_root = deployment_repository._snapshot_release(root, valid).parent
    corrupt_root = deployment_repository._snapshot_release(root, corrupt).parent
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
        deployment_repository._snapshot_release(root, release).parent
        for release in inactive
    )
    real_rmtree = shutil.rmtree
    removals = []

    def fail_second_removal(path: Path, *args, **kwargs) -> None:
        removals.append(path)
        if len(removals) == 2:
            raise OSError("storage unavailable")
        real_rmtree(path, *args, **kwargs)

    monkeypatch.setattr(deployment_lifecycle.shutil, "rmtree", fail_second_removal)

    with pytest.raises(
        MaintenanceOperationError, match=r"after pruning 1 release\(s\)"
    ):
        deployment.prune_deployment(
            root,
            expected_release_ids=tuple(release.release_id for release in inactive),
        )

    assert not version_roots[0].exists()
    assert version_roots[1].is_dir()
    assert deployment_repository._active_release(root).release_id == active.release_id


def test_deployment_prune_cli_dry_run_abort_and_yes(tmp_path: Path) -> None:
    root = tmp_path / "deployment"
    _prepare_deployment(root)
    inactive = _write_release(tmp_path / "inactive", "0.9.0", "inactive")
    inactive_root = deployment_repository._snapshot_release(root, inactive).parent
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
