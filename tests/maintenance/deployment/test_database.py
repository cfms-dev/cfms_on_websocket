import shutil
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory

from maintenance.operations.deployment import (
    database as deployment_database,
)
from maintenance.operations.exceptions import MaintenanceOperationError

from .support import _prepare_database_releases


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
