import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import (
    Column,
    Integer,
    MetaData,
    String,
    Table,
    Text,
    create_engine,
    inspect,
)


def _load_migration():
    path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "alembic"
        / "versions"
        / "7e576d23d5f9_persist_resumable_upload_checkpoint_data.py"
    )
    spec = importlib.util.spec_from_file_location("upload_checkpoint_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(connection, migration, operation):
    context = MigrationContext.configure(connection, opts={"render_as_batch": True})
    operations = Operations(context)
    with operations.context(context):
        getattr(migration, operation)()


def test_upload_checkpoint_migration_preserves_file_tasks(tmp_path):
    migration = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path / 'upload-checkpoint.db'}")
    metadata = MetaData()
    tasks = Table(
        "file_tasks",
        metadata,
        Column("id", String(255), primary_key=True),
        Column("status", Integer, nullable=False),
        Column("upload_session_id", Text),
    )
    metadata.create_all(engine)

    with engine.begin() as connection:
        connection.execute(
            tasks.insert(),
            {"id": "upload-task", "status": 0, "upload_session_id": "session"},
        )

        _run(connection, migration, "upgrade")
        upgraded = Table("file_tasks", MetaData(), autoload_with=connection)
        row = connection.execute(upgraded.select()).mappings().one()
        assert row["id"] == "upload-task"
        assert row["upload_checkpoint_data"] is None

        _run(connection, migration, "downgrade")
        assert "upload_checkpoint_data" not in {
            column["name"] for column in inspect(connection).get_columns("file_tasks")
        }

    engine.dispose()
