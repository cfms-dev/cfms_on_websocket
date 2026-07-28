import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import (
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
        Path(__file__).resolve().parents[1]
        / "src"
        / "alembic"
        / "versions"
        / "697123ea4145_adaptive_document_creation_risk_control.py"
    )
    spec = importlib.util.spec_from_file_location(
        "document_creation_risk_migration", path
    )
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
                }
            ),
        },
    )
    operations = Operations(context)
    with operations.context(context):
        getattr(migration, operation)()


def test_risk_state_migration_resets_transient_counters_and_round_trips(tmp_path):
    migration = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path / 'risk.db'}")
    metadata = MetaData()
    old_table = Table(
        "document_creation_throttles",
        metadata,
        Column("scope", String(16), primary_key=True),
        Column("identity", String(256), primary_key=True),
        Column("window_started_at", Float, nullable=False),
        Column("attempts", Integer, nullable=False),
        Column("last_attempt", Float, nullable=False, index=True),
    )
    metadata.create_all(engine)

    with engine.begin() as connection:
        connection.execute(
            old_table.insert(),
            {
                "scope": "account",
                "identity": "alice",
                "window_started_at": 1.0,
                "attempts": 5,
                "last_attempt": 2.0,
            },
        )
        _run(connection, migration, "upgrade")

        table_names = set(inspect(connection).get_table_names())
        assert "document_creation_throttles" not in table_names
        assert "document_creation_rate_buckets" in table_names
        assert "document_creation_ip_accounts" in table_names
        upgraded = MetaData()
        upgraded.reflect(connection)
        assert (
            connection.execute(
                select(upgraded.tables["document_creation_rate_buckets"])
            ).all()
            == []
        )

        _run(connection, migration, "downgrade")
        table_names = set(inspect(connection).get_table_names())
        assert "document_creation_throttles" in table_names
        assert "document_creation_rate_buckets" not in table_names
        assert "document_creation_ip_accounts" not in table_names
        downgraded = MetaData()
        downgraded.reflect(connection)
        assert (
            connection.execute(
                select(downgraded.tables["document_creation_throttles"])
            ).all()
            == []
        )

    engine.dispose()
