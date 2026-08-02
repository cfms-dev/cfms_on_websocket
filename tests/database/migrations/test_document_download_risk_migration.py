import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import (
    Boolean,
    Column,
    Float,
    ForeignKey,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    inspect,
    select,
)


def _load_migration():
    path = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "alembic"
        / "versions"
        / "c93cef4aa664_add_document_download_risk_control.py"
    )
    spec = importlib.util.spec_from_file_location("download_risk_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(connection, migration, operation):
    context = MigrationContext.configure(
        connection,
        opts={
            "render_as_batch": True,
            "target_metadata": MetaData(
                naming_convention={
                    "ix": "ix_%(column_0_label)s",
                    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
                    "pk": "pk_%(table_name)s",
                }
            ),
        },
    )
    operations = Operations(context)
    with operations.context(context):
        getattr(migration, operation)()


def _legacy_schema(metadata):
    users = Table("users", metadata, Column("username", String(256), primary_key=True))
    files = Table("files", metadata, Column("id", String(255), primary_key=True))
    tasks = Table(
        "file_tasks",
        metadata,
        Column("id", String(255), primary_key=True),
        Column("file_id", ForeignKey(files.c.id, ondelete="CASCADE"), nullable=False),
        Column("status", Integer, nullable=False),
        Column("mode", Integer, nullable=False),
        Column("start_time", Float, nullable=False),
        Column("end_time", Float),
        Column("encryption_key", String(256)),
    )
    groups = Table(
        "user_groups", metadata, Column("group_name", String(255), primary_key=True)
    )
    permissions = Table(
        "group_permissions",
        metadata,
        Column("group_name", String(255), primary_key=True),
        Column("permission", String(255), primary_key=True),
        Column("granted", Boolean, nullable=False),
        Column("start_time", Float, nullable=False),
        Column("end_time", Float),
    )
    return users, files, tasks, groups, permissions


def test_download_risk_migration_adds_attribution_index_and_permission(tmp_path):
    migration = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path / 'download-risk.db'}")
    metadata = MetaData()
    users, files, tasks, groups, permissions = _legacy_schema(metadata)
    metadata.create_all(engine)

    with engine.begin() as connection:
        connection.execute(users.insert(), {"username": "alice"})
        connection.execute(files.insert(), {"id": "file"})
        connection.execute(
            tasks.insert(),
            {
                "id": "task",
                "file_id": "file",
                "status": 0,
                "mode": 0,
                "start_time": 1.0,
                "end_time": 2.0,
                "encryption_key": None,
            },
        )
        connection.execute(groups.insert(), {"group_name": "sysop"})

        _run(connection, migration, "upgrade")

        inspector = inspect(connection)
        assert "issued_by_username" in {
            column["name"] for column in inspector.get_columns("file_tasks")
        }
        assert "ix_file_tasks_mode_status_end_time" in {
            index["name"] for index in inspector.get_indexes("file_tasks")
        }
        task_row = (
            connection.execute(
                select(Table("file_tasks", MetaData(), autoload_with=connection))
            )
            .mappings()
            .one()
        )
        assert task_row["issued_by_username"] is None
        grant = connection.execute(
            select(permissions.c.permission).where(permissions.c.group_name == "sysop")
        ).scalar_one()
        assert grant == "bypass_document_download_rate_limit"

        _run(connection, migration, "downgrade")

        inspector = inspect(connection)
        assert "issued_by_username" not in {
            column["name"] for column in inspector.get_columns("file_tasks")
        }
        assert connection.execute(select(permissions.c.permission)).all() == []

    engine.dispose()
