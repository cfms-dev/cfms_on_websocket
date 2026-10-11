import shutil
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import text

from maintenance.operations.deployment import (
    database as deployment_database,
)
from maintenance.operations.exceptions import MaintenanceOperationError

from .support import PROJECT_ROOT, _prepare_database_releases

pytestmark = pytest.mark.component


def _prepare_synthetic_database_releases(
    tmp_path: Path,
) -> tuple[
    Path, deployment_database._Release, deployment_database._Release, str, str, str
]:
    project_root = tmp_path / "deployment"
    source_root = tmp_path / "source"
    target_root = tmp_path / "target"
    for release_root in (source_root, target_root):
        (release_root / "src" / "alembic" / "versions").mkdir(parents=True)
        shutil.copy2(PROJECT_ROOT / "src" / "alembic.ini", release_root / "src")
        (release_root / "src" / "alembic" / "env.py").write_text(
            (PROJECT_ROOT / "src" / "alembic" / "env.py").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (release_root / "src" / "alembic" / "script.py.mako").write_text(
            (PROJECT_ROOT / "src" / "alembic" / "script.py.mako").read_text(
                encoding="utf-8"
            ),
            encoding="utf-8",
        )

    base_revision = "rev_base"
    source_head = "rev_source_head"
    target_revision = "rev_target_head"

    def _write_rev(root: Path, rev: str, down: str | None) -> None:
        down_str = f'"{down}"' if down else "None"
        (root / "src" / "alembic" / "versions" / f"{rev}.py").write_text(
            f'revision = "{rev}"\ndown_revision = {down_str}\nbranch_labels = None\n'
            "depends_on = None\n\ndef upgrade():\n    pass\n\ndef downgrade():\n    pass\n",
            encoding="utf-8",
        )

    _write_rev(source_root, base_revision, None)
    _write_rev(source_root, source_head, base_revision)

    _write_rev(target_root, base_revision, None)
    _write_rev(target_root, source_head, base_revision)
    _write_rev(target_root, target_revision, source_head)

    source = deployment_database._Release(source_root, {}, b"source", "1" * 64)
    target = deployment_database._Release(target_root, {}, b"target", "2" * 64)
    (project_root / "src").mkdir(parents=True)
    sample = (PROJECT_ROOT / "src" / "config.toml.sample").read_text(encoding="utf-8")
    (project_root / "src" / "config.toml").write_text(sample, encoding="utf-8")
    return project_root, source, target, base_revision, source_head, target_revision


def test_database_upgrade_rejects_unversioned_database_without_stamping(
    tmp_path: Path,
) -> None:
    project_root, source, target, _, _ = _prepare_database_releases(tmp_path)

    with pytest.raises(MaintenanceOperationError, match="no Alembic revision"):
        deployment_database._upgrade_database(project_root, source, target)

    engine = deployment_database._database_engine(project_root)
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
    engine = deployment_database._database_engine(project_root)
    try:
        with engine.begin() as connection:
            MigrationContext.configure(connection).stamp(source_scripts, source_head)
    finally:
        engine.dispose()

    deployment_database._preflight_upgrade_database(project_root, source, target)
    deployment_database._upgrade_database(project_root, source, target)
    assert not tuple(target.root.rglob("*.pyc"))
    engine = deployment_database._database_engine(project_root)
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
    deployment_database._preflight_downgrade_database(project_root, target, source)
    deployment_database._downgrade_database(project_root, target, source)
    assert not tuple(source.root.rglob("*.pyc"))
    assert not tuple(target.root.rglob("*.pyc"))
    engine = deployment_database._database_engine(project_root)
    try:
        with engine.connect() as connection:
            assert (
                MigrationContext.configure(connection).get_current_revision()
                == source_head
            )
    finally:
        engine.dispose()


def test_database_upgrade_succeeds_from_ancestor_revision_before_source_head(
    tmp_path: Path,
) -> None:
    (
        project_root,
        source,
        target,
        base_revision,
        _,  # source_head,
        target_revision,
    ) = _prepare_synthetic_database_releases(tmp_path)
    source_scripts = ScriptDirectory(str(source.root / "src" / "alembic"))
    engine = deployment_database._database_engine(project_root)
    try:
        with engine.begin() as connection:
            MigrationContext.configure(connection).stamp(source_scripts, base_revision)
    finally:
        engine.dispose()

    deployment_database._preflight_upgrade_database(project_root, source, target)
    deployment_database._upgrade_database(project_root, source, target)
    engine = deployment_database._database_engine(project_root)
    try:
        with engine.connect() as connection:
            assert (
                MigrationContext.configure(connection).get_current_revision()
                == target_revision
            )
    finally:
        engine.dispose()


def test_database_upgrade_succeeds_when_source_and_target_heads_match_but_database_is_at_ancestor(
    tmp_path: Path,
) -> None:
    (
        project_root,
        source,
        _,
        base_revision,
        source_head,
        _,
    ) = _prepare_synthetic_database_releases(tmp_path)
    source_scripts = ScriptDirectory(str(source.root / "src" / "alembic"))
    engine = deployment_database._database_engine(project_root)
    try:
        with engine.begin() as connection:
            MigrationContext.configure(connection).stamp(source_scripts, base_revision)
    finally:
        engine.dispose()

    deployment_database._preflight_upgrade_database(project_root, source, source)
    deployment_database._upgrade_database(project_root, source, source)
    engine = deployment_database._database_engine(project_root)
    try:
        with engine.connect() as connection:
            assert (
                MigrationContext.configure(connection).get_current_revision()
                == source_head
            )
    finally:
        engine.dispose()


def test_database_upgrade_and_downgrade_reject_incompatible_revisions(
    tmp_path: Path,
) -> None:
    (
        project_root,
        source,
        target,
        base_revision,
        _,
        _,
    ) = _prepare_synthetic_database_releases(tmp_path)
    source_scripts = ScriptDirectory(str(source.root / "src" / "alembic"))
    engine = deployment_database._database_engine(project_root)
    try:
        with engine.begin() as connection:
            MigrationContext.configure(connection).stamp(source_scripts, base_revision)
            connection.execute(
                text("UPDATE alembic_version SET version_num = 'incompatible_revision'")
            )
    finally:
        engine.dispose()

    with pytest.raises(
        MaintenanceOperationError, match="target release expects an ancestor"
    ):
        deployment_database._preflight_upgrade_database(project_root, source, target)

    with pytest.raises(
        MaintenanceOperationError, match="target release expects an ancestor"
    ):
        deployment_database._upgrade_database(project_root, source, target)

    with pytest.raises(
        MaintenanceOperationError, match="active release expects a descendant"
    ):
        deployment_database._preflight_downgrade_database(project_root, target, source)

    with pytest.raises(
        MaintenanceOperationError, match="active release expects a descendant"
    ):
        deployment_database._downgrade_database(project_root, target, source)
