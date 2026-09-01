import hashlib
import json
import shutil
import zipfile
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory

from maintenance.operations import deployment
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
        "minimum_upgrade_version": "1.0.0",
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
    monkeypatch.setattr(deployment, "_upgrade_database", lambda *args: None)
    monkeypatch.setattr(deployment, "_downgrade_database", lambda *args: None)
    monkeypatch.setattr(
        deployment, "sync_config_template", lambda *args, **kwargs: None
    )

    upgraded = deployment.upgrade_deployment(
        package,
        root,
        expected_sha256="a" * 64,
        backup_confirmed=True,
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
        backup_confirmed=True,
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


def test_upgrade_requires_operator_backup_confirmation(
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

    with pytest.raises(MaintenanceOperationError, match="--backup-confirmed"):
        deployment.upgrade_deployment(
            tmp_path / "release.zip",
            root,
            expected_sha256="a" * 64,
        )


def test_failed_migration_requires_database_restore_before_resume(
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
            backup_confirmed=True,
        )

    transaction_path = root / "src" / ".maintenance" / "transaction.json"
    assert json.loads(transaction_path.read_text(encoding="utf-8"))["phase"] == (
        "database-recovery-required"
    )
    with pytest.raises(MaintenanceOperationError, match="--database-restored"):
        deployment.resume_deployment(root)

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
    monkeypatch.setattr(deployment, "_current_revision", lambda *args: "source-head")
    monkeypatch.setattr(
        deployment,
        "_alembic",
        lambda release, *args: (
            None,
            None,
            "source-head" if release.release_id == source.release_id else "target-head",
        ),
    )

    resumed = deployment.resume_deployment(root, database_restored=True)

    assert resumed.active_release_id == source.release_id
    assert not transaction_path.exists()
    assert (root / "src" / "main.py").read_text(encoding="utf-8") == "# old\n"


def test_database_upgrade_stamps_unversioned_database_and_can_downgrade(
    tmp_path: Path,
) -> None:
    project_root = tmp_path / "deployment"
    source_root = tmp_path / "source"
    target_root = tmp_path / "target"
    for release_root in (source_root, target_root):
        (release_root / "src").mkdir(parents=True)
        shutil.copy2(PROJECT_ROOT / "src" / "alembic.ini", release_root / "src")
        shutil.copytree(
            PROJECT_ROOT / "src" / "alembic", release_root / "src" / "alembic"
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

    deployment._upgrade_database(project_root, source, target)
    engine = deployment._database_engine(project_root)
    try:
        with engine.connect() as connection:
            assert (
                MigrationContext.configure(connection).get_current_revision()
                == target_revision
            )
    finally:
        engine.dispose()

    deployment._downgrade_database(project_root, target, source)
    engine = deployment._database_engine(project_root)
    try:
        with engine.connect() as connection:
            assert (
                MigrationContext.configure(connection).get_current_revision()
                == source_head
            )
    finally:
        engine.dispose()
