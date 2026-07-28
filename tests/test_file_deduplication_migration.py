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
)


def _load_migration():
    path = (
        Path(__file__).resolve().parents[1]
        / "src"
        / "alembic"
        / "versions"
        / "31ab3daf4d6f_durable_file_deduplication_queue.py"
    )
    spec = importlib.util.spec_from_file_location("file_deduplication_migration", path)
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
                    "pk": "pk_%(table_name)s",
                    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
                }
            ),
        },
    )
    operations = Operations(context)
    with operations.context(context):
        getattr(migration, operation)()


def _create_previous_schema(engine):
    metadata = MetaData()
    files = Table(
        "files",
        metadata,
        Column("id", String(255), primary_key=True),
        Column("sha256", String(64)),
        Column("active", Boolean, nullable=False),
        Column("created_time", Float, nullable=False),
    )
    Table(
        "document_revisions",
        metadata,
        Column("id", String(64), primary_key=True),
        Column("file_id", String(255), ForeignKey("files.id"), nullable=False),
    )
    Table(
        "file_tasks",
        metadata,
        Column("id", String(255), primary_key=True),
        Column("file_id", String(255), ForeignKey("files.id"), nullable=False),
        Column("mode", Integer, nullable=False),
        Column("status", Integer, nullable=False),
    )
    Table(
        "users",
        metadata,
        Column("username", String(256), primary_key=True),
        Column("avatar_id", String(255), ForeignKey("files.id")),
    )
    metadata.create_all(engine)
    return files


def test_file_deduplication_queue_migration_round_trips(tmp_path):
    migration = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path / 'deduplication.db'}")
    files = _create_previous_schema(engine)

    with engine.begin() as connection:
        connection.execute(
            files.insert(),
            {"id": "existing", "sha256": "a" * 64, "active": True, "created_time": 1.0},
        )
        _run(connection, migration, "upgrade")

        inspector = inspect(connection)
        assert "file_deduplication_tasks" in inspector.get_table_names()
        assert (
            connection.exec_driver_sql(
                "SELECT COUNT(*) FROM file_deduplication_tasks"
            ).scalar_one()
            == 0
        )
        assert {
            "file_id",
            "phase",
            "available_at",
            "lease_owner",
            "lease_expires_at",
            "attempts",
            "last_error",
            "created_time",
        } == {
            column["name"]
            for column in inspector.get_columns("file_deduplication_tasks")
        }
        assert {"ix_file_deduplication_tasks_available_lease"} <= {
            index["name"] for index in inspector.get_indexes("file_deduplication_tasks")
        }
        assert {"ix_files_sha256_active_created_time_id"} <= {
            index["name"] for index in inspector.get_indexes("files")
        }
        assert {"ix_file_tasks_file_id_mode_status"} <= {
            index["name"] for index in inspector.get_indexes("file_tasks")
        }
        assert {"ix_document_revisions_file_id"} <= {
            index["name"] for index in inspector.get_indexes("document_revisions")
        }
        assert {"ix_users_avatar_id"} <= {
            index["name"] for index in inspector.get_indexes("users")
        }

        _run(connection, migration, "downgrade")
        inspector = inspect(connection)
        assert "file_deduplication_tasks" not in inspector.get_table_names()
        assert (
            connection.exec_driver_sql(
                "SELECT COUNT(*) FROM files WHERE id = 'existing'"
            ).scalar_one()
            == 1
        )
        assert inspector.get_indexes("files") == []
        assert inspector.get_indexes("file_tasks") == []
        assert inspector.get_indexes("document_revisions") == []
        assert inspector.get_indexes("users") == []

    engine.dispose()
