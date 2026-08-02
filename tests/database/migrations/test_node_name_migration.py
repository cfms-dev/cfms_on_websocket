import importlib.util
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import (
    Boolean,
    Column,
    Float,
    ForeignKey,
    Index,
    Integer,
    MetaData,
    String,
    Table,
    create_engine,
    inspect,
)


def _load_migration():
    path = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "alembic"
        / "versions"
        / "fe8863687aa4_enforce_node_name_uniqueness.py"
    )
    spec = importlib.util.spec_from_file_location("node_name_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _old_schema(metadata: MetaData) -> dict[str, Table]:
    nodes = Table(
        "nodes",
        metadata,
        Column("id", String(255), primary_key=True),
        Column("type", String(16), nullable=False),
        Column("inherit", Boolean, nullable=False),
        Column("status", Integer, nullable=False),
        Column("status_operation_id", String(255)),
        Column("access_rule_set_id", String(32)),
    )
    folders = Table(
        "folders",
        metadata,
        Column("id", String(255), ForeignKey("nodes.id"), primary_key=True),
        Column("name", String(255), nullable=False),
        Column("created_time", Float, nullable=False),
        Column(
            "parent_id",
            String(255),
            ForeignKey(
                "folders.id",
                name="fk_folders_parent_id_folders",
                ondelete="CASCADE",
            ),
        ),
    )
    documents = Table(
        "documents",
        metadata,
        Column("id", String(255), ForeignKey("nodes.id"), primary_key=True),
        Column("title", String(255), nullable=False),
        Column("created_time", Float, nullable=False),
        Column("current_revision_id", String(255)),
        Column(
            "folder_id",
            String(255),
            ForeignKey(
                "folders.id",
                name="fk_documents_folder_id_folders",
                ondelete="CASCADE",
            ),
        ),
    )
    Index("ix_folders_name", folders.c.name)
    Index("ix_documents_title", documents.c.title)
    return {"nodes": nodes, "folders": folders, "documents": documents}


def _run(connection, migration, operation: str) -> None:
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


def _seed_valid(connection, tables: dict[str, Table]) -> None:
    connection.execute(
        tables["nodes"].insert(),
        [
            {"id": "/", "type": "directory", "inherit": True, "status": 0},
            {"id": "folder", "type": "directory", "inherit": True, "status": 0},
            {"id": "doc", "type": "document", "inherit": True, "status": 0},
        ],
    )
    connection.execute(
        tables["folders"].insert(),
        [
            {"id": "/", "name": "/", "created_time": 1.0, "parent_id": None},
            {
                "id": "folder",
                "name": "Folder",
                "created_time": 2.0,
                "parent_id": "/",
            },
        ],
    )
    connection.execute(
        tables["documents"].insert(),
        {
            "id": "doc",
            "title": "Report",
            "created_time": 3.0,
            "folder_id": "folder",
        },
    )


def test_node_name_migration_round_trip(tmp_path) -> None:
    migration = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path / 'migration.db'}")
    metadata = MetaData()
    tables = _old_schema(metadata)
    metadata.create_all(engine)

    with engine.begin() as connection:
        _seed_valid(connection, tables)
        _run(connection, migration, "upgrade")

        upgraded = inspect(connection)
        assert {"name", "parent_id", "active_parent_id"} <= {
            column["name"] for column in upgraded.get_columns("nodes")
        }
        assert "name" not in {
            column["name"] for column in upgraded.get_columns("folders")
        }
        assert "title" not in {
            column["name"] for column in upgraded.get_columns("documents")
        }
        assert connection.exec_driver_sql(
            "SELECT name, parent_id FROM nodes WHERE id = ?", ("doc",)
        ).one() == ("Report", "folder")

        _run(connection, migration, "downgrade")

        downgraded = inspect(connection)
        assert "name" not in {
            column["name"] for column in downgraded.get_columns("nodes")
        }
        assert connection.exec_driver_sql(
            "SELECT title, folder_id FROM documents WHERE id = ?", ("doc",)
        ).one() == ("Report", "folder")

    engine.dispose()


def test_duplicate_preflight_stops_before_ddl(tmp_path) -> None:
    migration = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path / 'duplicate.db'}")
    metadata = MetaData()
    tables = _old_schema(metadata)
    metadata.create_all(engine)

    with engine.begin() as connection:
        _seed_valid(connection, tables)
        connection.execute(
            tables["nodes"].insert(),
            {"id": "same-folder", "type": "directory", "inherit": True, "status": 0},
        )
        connection.execute(
            tables["folders"].insert(),
            {
                "id": "same-folder",
                "name": "Report",
                "created_time": 4.0,
                "parent_id": "folder",
            },
        )

        with pytest.raises(RuntimeError, match="directory:same-folder.*document:doc"):
            _run(connection, migration, "upgrade")

        assert "name" not in {
            column["name"] for column in inspect(connection).get_columns("nodes")
        }

    engine.dispose()


@pytest.mark.parametrize("parent_id", [None, "missing-folder"])
def test_missing_parent_preflight_stops_before_ddl(tmp_path, parent_id) -> None:
    migration = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path / f'missing-{parent_id}.db'}")
    metadata = MetaData()
    tables = _old_schema(metadata)
    metadata.create_all(engine)

    with engine.begin() as connection:
        connection.execute(
            tables["nodes"].insert(),
            [
                {"id": "/", "type": "directory", "inherit": True, "status": 0},
                {"id": "orphan", "type": "document", "inherit": True, "status": 0},
            ],
        )
        connection.execute(
            tables["folders"].insert(),
            {"id": "/", "name": "/", "created_time": 1.0},
        )
        connection.execute(
            tables["documents"].insert(),
            {
                "id": "orphan",
                "title": "Orphan",
                "created_time": 2.0,
                "folder_id": parent_id,
            },
        )

        with pytest.raises(RuntimeError, match="non-root nodes without a parent"):
            _run(connection, migration, "upgrade")

        assert "name" not in {
            column["name"] for column in inspect(connection).get_columns("nodes")
        }

    engine.dispose()
