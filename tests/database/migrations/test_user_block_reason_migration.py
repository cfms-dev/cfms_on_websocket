import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import (
    BigInteger,
    Column,
    Float,
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
        / "76f1c7621e23_add_user_block_reasons.py"
    )
    spec = importlib.util.spec_from_file_location("user_block_reason_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(connection, migration, operation: str) -> None:
    context = MigrationContext.configure(
        connection,
        opts={
            "render_as_batch": True,
            "target_metadata": MetaData(
                naming_convention={
                    "fk": (
                        "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"
                    ),
                    "pk": "pk_%(table_name)s",
                }
            ),
        },
    )
    operations = Operations(context)
    with operations.context(context):
        getattr(migration, operation)()


def test_user_block_reason_migration_preserves_rows_and_round_trips(tmp_path) -> None:
    migration = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path / 'migration.db'}")
    metadata = MetaData()
    Table("users", metadata, Column("username", String(256), primary_key=True))
    Table(
        "comments",
        metadata,
        Column(
            "comment_id",
            BigInteger().with_variant(Integer, "sqlite"),
            primary_key=True,
        ),
    )
    user_blocks = Table(
        "userblock_entries",
        metadata,
        Column("block_id", String(32), primary_key=True),
        Column("username", String(256), nullable=False),
        Column("timestamp", Float, nullable=False),
        Column("not_before", Float, nullable=False),
        Column("not_after", Float, nullable=False),
        Column("target_type", String(32), nullable=False),
        Column("target_id", String(255)),
    )
    metadata.create_all(engine)

    with engine.begin() as connection:
        connection.execute(
            user_blocks.insert(),
            {
                "block_id": "block-1",
                "username": "alice",
                "timestamp": 1.0,
                "not_before": 0.0,
                "not_after": -1.0,
                "target_type": "all",
                "target_id": None,
            },
        )

        _run(connection, migration, "upgrade")

        upgraded = MetaData()
        upgraded.reflect(connection)
        row = (
            connection.execute(select(upgraded.tables["userblock_entries"]))
            .mappings()
            .one()
        )
        assert row["block_id"] == "block-1"
        assert row["reason_comment_id"] is None
        foreign_keys = inspect(connection).get_foreign_keys("userblock_entries")
        reason_foreign_key = next(
            key
            for key in foreign_keys
            if key["constrained_columns"] == ["reason_comment_id"]
        )
        assert reason_foreign_key["referred_table"] == "comments"
        assert reason_foreign_key["options"] == {"ondelete": "SET NULL"}

        _run(connection, migration, "downgrade")

        columns = {
            column["name"]
            for column in inspect(connection).get_columns("userblock_entries")
        }
        assert "reason_comment_id" not in columns
        assert (
            connection.scalar(select(upgraded.tables["userblock_entries"].c.block_id))
            == "block-1"
        )

    engine.dispose()
