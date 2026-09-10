import hashlib
import json
import shutil
import zipfile
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory

from include.runtime_lock import RuntimeLock
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
