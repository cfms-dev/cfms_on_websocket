import datetime as dt
import importlib.util
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
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
        / "052c13c19603_administer_security_blocks.py"
    )
    spec = importlib.util.spec_from_file_location("security_admin_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _old_schema(metadata: MetaData) -> dict[str, Table]:
    tables = {
        "banned_subnets": Table(
            "banned_subnets",
            metadata,
            Column("subnet", String(128), primary_key=True),
            Column("reason", String(255)),
            Column("created_at", DateTime, nullable=False),
        ),
        "account_throttles": Table(
            "account_throttles",
            metadata,
            Column("username", String(64), primary_key=True),
            Column("factor", String(16), primary_key=True),
            Column("failed_attempts", Integer, nullable=False),
            Column("last_attempt", DateTime, nullable=False, index=True),
            Column("locked_until", DateTime),
        ),
        "login_throttles": Table(
            "login_throttles",
            metadata,
            Column("username", String(255), primary_key=True),
            Column("ip_address", String(45), primary_key=True),
            Column("failed_attempts", Integer, nullable=False),
            Column("window_started_at", DateTime, nullable=False),
            Column("last_attempt", DateTime, nullable=False, index=True),
            Column("locked_until", DateTime),
        ),
        "traffic_throttles": Table(
            "traffic_throttles",
            metadata,
            Column("ip_address", String(45), primary_key=True),
            Column("failed_attempts", Integer, nullable=False),
            Column("window_started_at", DateTime, nullable=False),
            Column("last_attempt", DateTime, nullable=False, index=True),
            Column("locked_until", DateTime),
        ),
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
    return tables


def _run(connection, migration, operation: str) -> None:
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


def test_security_time_migration_round_trip(tmp_path) -> None:
    migration = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path / 'migration.db'}")
    metadata = MetaData()
    tables = _old_schema(metadata)
    metadata.create_all(engine)
    now = dt.datetime(2026, 7, 24, 12, 30, tzinfo=dt.UTC).replace(tzinfo=None)
    locked_until = now + dt.timedelta(minutes=15)

    with engine.begin() as connection:
        connection.execute(tables["user_groups"].insert(), {"group_name": "sysop"})
        connection.execute(
            tables["banned_subnets"].insert(),
            {"subnet": "192.0.2.0/24", "reason": "test", "created_at": now},
        )
        connection.execute(
            tables["account_throttles"].insert(),
            {
                "username": "alice",
                "factor": "password",
                "failed_attempts": 5,
                "last_attempt": now,
                "locked_until": locked_until,
            },
        )
        for table_name, values in (
            (
                "login_throttles",
                {"username": "alice", "ip_address": "198.51.100.1"},
            ),
            ("traffic_throttles", {"ip_address": "198.51.100.1"}),
        ):
            connection.execute(
                tables[table_name].insert(),
                {
                    **values,
                    "failed_attempts": 5,
                    "window_started_at": now,
                    "last_attempt": now,
                    "locked_until": locked_until,
                },
            )

        _run(connection, migration, "upgrade")

        upgraded = MetaData()
        upgraded.reflect(connection)
        subnet = (
            connection.execute(select(upgraded.tables["banned_subnets"]))
            .mappings()
            .one()
        )
        assert subnet["created_at"] == pytest.approx(
            now.replace(tzinfo=dt.UTC).timestamp()
        )
        assert subnet["starts_at"] == subnet["created_at"]
        assert subnet["expires_at"] is None
        account = (
            connection.execute(select(upgraded.tables["account_throttles"]))
            .mappings()
            .one()
        )
        assert account["locked_until"] == pytest.approx(
            locked_until.replace(tzinfo=dt.UTC).timestamp()
        )
        permissions = connection.execute(
            select(upgraded.tables["group_permissions"].c.permission)
        ).scalars()
        assert set(permissions) == set(migration._PERMISSIONS)
        assert {
            column["name"]
            for column in inspect(connection).get_columns("banned_subnets")
        } >= {
            "starts_at",
            "expires_at",
        }

        _run(connection, migration, "downgrade")

        downgraded = MetaData()
        downgraded.reflect(connection)
        subnet = (
            connection.execute(select(downgraded.tables["banned_subnets"]))
            .mappings()
            .one()
        )
        assert subnet["created_at"] == now
        assert "starts_at" not in subnet
        account = (
            connection.execute(select(downgraded.tables["account_throttles"]))
            .mappings()
            .one()
        )
        assert account["locked_until"] == locked_until
        assert (
            connection.execute(select(downgraded.tables["group_permissions"])).all()
            == []
        )

    engine.dispose()
