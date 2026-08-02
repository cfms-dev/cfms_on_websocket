import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import (
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
        / "8be3cdd47846_persist_download_chunk_size.py"
    )
    spec = importlib.util.spec_from_file_location("download_chunk_size_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(connection, migration, operation):
    context = MigrationContext.configure(connection, opts={"render_as_batch": True})
    operations = Operations(context)
    with operations.context(context):
        getattr(migration, operation)()


def test_download_chunk_size_migration_preserves_existing_tasks(tmp_path):
    migration = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path / 'download-chunk-size.db'}")
    metadata = MetaData()
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
    metadata.create_all(engine)

    with engine.begin() as connection:
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

        _run(connection, migration, "upgrade")
        upgraded = Table("file_tasks", MetaData(), autoload_with=connection)
        row = connection.execute(select(upgraded)).mappings().one()
        assert row["id"] == "task"
        assert row["download_chunk_size"] is None

        _run(connection, migration, "downgrade")
        assert "download_chunk_size" not in {
            column["name"] for column in inspect(connection).get_columns("file_tasks")
        }

    engine.dispose()
