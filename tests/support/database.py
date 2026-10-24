import os
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
lazy from mysql.connector import MySQLConnection

from include.database.engine import create_database_engine


@pytest.fixture
def mysql_pure_engine():
    database_url = os.environ.get("CFMS_TEST_MYSQL_URL")
    if database_url is None:
        pytest.skip("CFMS_TEST_MYSQL_URL is required")

    engine = create_engine(database_url, connect_args={"use_pure": True})
    try:
        with engine.connect() as connection:
            assert isinstance(connection.connection.driver_connection, MySQLConnection)
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def sqlite_engine_factory(request: pytest.FixtureRequest):
    def create(path: str | Path = ":memory:", *, timeout_seconds: float | None = None):
        engine = create_database_engine({"type": "sqlite", "file": str(path)})
        request.addfinalizer(engine.dispose)
        if timeout_seconds is not None:

            @event.listens_for(engine, "connect")
            def configure_timeout(connection, _record):
                connection.execute(f"PRAGMA busy_timeout={int(timeout_seconds * 1000)}")

        return engine

    return create
