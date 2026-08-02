import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import (
    Boolean,
    Column,
    Float,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    select,
)


def _load_migration():
    path = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "alembic"
        / "versions"
        / "55c97f57db3a_grant_document_creation_rate_limit_.py"
    )
    spec = importlib.util.spec_from_file_location(
        "document_creation_rate_limit_permission_migration", path
    )
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _schema(metadata):
    return {
        "user_groups": Table(
            "user_groups",
            metadata,
            Column("group_name", String(255), primary_key=True),
        ),
        "group_permissions": Table(
            "group_permissions",
            metadata,
            Column("id", Integer, primary_key=True, autoincrement=True),
            Column("group_name", String(255), nullable=False),
            Column("permission", String(255), nullable=False),
            Column("granted", Boolean, nullable=False),
            Column("start_time", Float, nullable=False),
            Column("end_time", Float),
        ),
    }


def _run(connection, migration, operation):
    context = MigrationContext.configure(connection)
    operations = Operations(context)
    with operations.context(context):
        getattr(migration, operation)()


def test_upgrade_grants_existing_sysop_once_and_downgrade_removes_grant(tmp_path):
    migration = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path / 'permission.db'}")
    metadata = MetaData()
    tables = _schema(metadata)
    metadata.create_all(engine)

    with engine.begin() as connection:
        connection.execute(tables["user_groups"].insert(), {"group_name": "sysop"})
        _run(connection, migration, "upgrade")
        _run(connection, migration, "upgrade")

        rows = connection.execute(select(tables["group_permissions"])).mappings().all()
        assert len(rows) == 1
        assert rows[0]["permission"] == migration._PERMISSION
        assert rows[0]["granted"] is True
        assert rows[0]["start_time"] == 0.0

        _run(connection, migration, "downgrade")
        assert connection.execute(select(tables["group_permissions"])).all() == []

    engine.dispose()


def test_upgrade_does_not_create_missing_sysop_group(tmp_path):
    migration = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path / 'permission.db'}")
    metadata = MetaData()
    tables = _schema(metadata)
    metadata.create_all(engine)

    with engine.begin() as connection:
        _run(connection, migration, "upgrade")
        assert connection.execute(select(tables["group_permissions"])).all() == []

    engine.dispose()
