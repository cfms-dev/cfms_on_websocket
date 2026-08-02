import importlib.util
from pathlib import Path

from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import Column, Float, Integer, MetaData, String, Table, create_engine


def _load_migration():
    path = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "alembic"
        / "versions"
        / "af95e9bae5fc_unify_persistent_rate_limit_state.py"
    )
    spec = importlib.util.spec_from_file_location("shared_rate_limit_migration", path)
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


def _legacy_tables(metadata):
    buckets = Table(
        "document_creation_rate_buckets",
        metadata,
        Column("scope", String(16), primary_key=True),
        Column("identity", String(256), primary_key=True),
        Column("tokens", Float, nullable=False),
        Column("last_refill_at", Float, nullable=False),
        Column("denial_count", Integer, nullable=False),
        Column("last_denied_at", Float),
        Column("last_attempt", Float, nullable=False, index=True),
    )
    accounts = Table(
        "document_creation_ip_accounts",
        metadata,
        Column("ip_address", String(45), primary_key=True),
        Column("username", String(256), primary_key=True),
        Column("last_attempt", Float, nullable=False, index=True),
    )
    return buckets, accounts


def test_shared_rate_limit_migration_preserves_creation_state(tmp_path):
    migration = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path / 'rate-limit.db'}")
    metadata = MetaData()
    buckets, accounts = _legacy_tables(metadata)
    metadata.create_all(engine)

    with engine.begin() as connection:
        connection.execute(
            buckets.insert(),
            {
                "scope": "account",
                "identity": "alice",
                "tokens": 4.5,
                "last_refill_at": 10.0,
                "denial_count": 2,
                "last_denied_at": 11.0,
                "last_attempt": 12.0,
            },
        )
        connection.execute(
            accounts.insert(),
            {
                "ip_address": "203.0.113.1",
                "username": "alice",
                "last_attempt": 12.0,
            },
        )
        _run(connection, migration, "upgrade")

        upgraded = MetaData()
        upgraded.reflect(connection)
        bucket_row = (
            connection.execute(upgraded.tables["rate_limit_buckets"].select())
            .mappings()
            .one()
        )
        account_row = (
            connection.execute(upgraded.tables["risk_ip_accounts"].select())
            .mappings()
            .one()
        )
        assert bucket_row["namespace"] == "document_creation"
        assert bucket_row["tokens"] == 4.5
        assert bucket_row["denial_count"] == 2
        assert account_row["namespace"] == "document_creation"
        assert account_row["username"] == "alice"

        connection.execute(
            upgraded.tables["rate_limit_buckets"].insert(),
            {
                "namespace": "download_issue",
                "scope": "account",
                "identity": "bob",
                "tokens": 1.0,
                "last_refill_at": 20.0,
                "denial_count": 0,
                "last_denied_at": None,
                "last_attempt": 20.0,
            },
        )
        _run(connection, migration, "downgrade")

        downgraded = MetaData()
        downgraded.reflect(connection)
        rows = (
            connection.execute(
                downgraded.tables["document_creation_rate_buckets"].select()
            )
            .mappings()
            .all()
        )
        assert len(rows) == 1
        assert rows[0]["identity"] == "alice"
        assert "rate_limit_buckets" not in downgraded.tables
        assert "risk_ip_accounts" not in downgraded.tables

    engine.dispose()
