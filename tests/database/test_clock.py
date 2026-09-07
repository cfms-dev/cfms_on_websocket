import datetime as dt

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.dialects import mysql, postgresql, sqlite
from sqlalchemy.orm import sessionmaker

from include.database.clock import _database_time_expression, database_now


@pytest.mark.parametrize(
    ("dialect_name", "dialect", "expected_clause"),
    (
        (
            "sqlite",
            sqlite.dialect(),
            "(julianday('now') - 2440587.5) * 86400.0",
        ),
        (
            "postgresql",
            postgresql.dialect(),
            "EXTRACT(epoch FROM clock_timestamp())",
        ),
        (
            "mysql",
            mysql.dialect(),
            "unix_timestamp(CURRENT_TIMESTAMP(6))",
        ),
    ),
)
def test_database_time_expression_uses_supported_dialect_clock(
    dialect_name,
    dialect,
    expected_clause,
):
    statement = select(_database_time_expression(dialect_name))

    sql = str(
        statement.compile(dialect=dialect, compile_kwargs={"literal_binds": True})
    )

    assert expected_clause in sql


def test_database_time_expression_rejects_unsupported_dialect():
    with pytest.raises(ValueError, match="Unsupported database dialect: oracle"):
        _database_time_expression("oracle")


def test_database_now_returns_sqlite_utc_unix_seconds():
    database = create_engine("sqlite://")
    factory = sessionmaker(bind=database)
    before = dt.datetime.now(dt.UTC).timestamp()

    with factory() as session:
        current = database_now(session)

    after = dt.datetime.now(dt.UTC).timestamp()
    assert before - 1 <= current <= after + 1
