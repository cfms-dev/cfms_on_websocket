import importlib.util
from pathlib import Path

import pytest
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
    update,
)


def _load_migration():
    path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "alembic"
        / "versions"
        / "3c0666dd9068_unify_file_task_chunk_size_for_.py"
    )
    spec = importlib.util.spec_from_file_location("file_task_chunk_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(connection, migration, operation):
    context = MigrationContext.configure(connection, opts={"render_as_batch": True})
    operations = Operations(context)
    with operations.context(context):
        getattr(migration, operation)()


def test_file_task_chunk_migration_preserves_download_state(tmp_path):
    migration = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path / 'file-task-chunk.db'}")
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
        Column("download_chunk_size", Integer),
    )
    metadata.create_all(engine)

    with engine.begin() as connection:
        connection.execute(files.insert(), [{"id": "download"}, {"id": "upload"}])
        connection.execute(
            tasks.insert(),
            [
                {
                    "id": "download-task",
                    "file_id": "download",
                    "status": 0,
                    "mode": 0,
                    "start_time": 1.0,
                    "download_chunk_size": 65536,
                },
                {
                    "id": "upload-task",
                    "file_id": "upload",
                    "status": 0,
                    "mode": 1,
                    "start_time": 1.0,
                    "download_chunk_size": None,
                },
            ],
        )

        _run(connection, migration, "upgrade")
        upgraded = Table("file_tasks", MetaData(), autoload_with=connection)
        rows = {
            row["id"]: row
            for row in connection.execute(select(upgraded)).mappings().all()
        }
        assert rows["download-task"]["chunk_size"] == 65536
        assert rows["upload-task"]["chunk_size"] is None
        assert rows["upload-task"]["upload_file_size"] is None
        assert rows["upload-task"]["upload_sha256"] is None

        connection.execute(
            update(upgraded)
            .where(upgraded.c.id == "upload-task")
            .values(
                chunk_size=512,
                upload_file_size=1024,
                upload_sha256="a" * 64,
                upload_session_id="active-session",
                upload_checkpoint_size=5 * 1024 * 1024,
            )
        )
        with pytest.raises(RuntimeError, match="resumable S3 upload sessions remain"):
            _run(connection, migration, "downgrade")

        connection.execute(
            update(upgraded)
            .where(upgraded.c.id == "upload-task")
            .values(upload_session_id=None)
        )
        _run(connection, migration, "downgrade")
        downgraded = Table("file_tasks", MetaData(), autoload_with=connection)
        rows = {
            row["id"]: row
            for row in connection.execute(select(downgraded)).mappings().all()
        }
        assert rows["download-task"]["download_chunk_size"] == 65536
        assert rows["upload-task"]["download_chunk_size"] is None
        assert "chunk_size" not in {
            column["name"] for column in inspect(connection).get_columns("file_tasks")
        }

    engine.dispose()
