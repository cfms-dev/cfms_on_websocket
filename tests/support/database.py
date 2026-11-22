import os
from collections.abc import Generator
from pathlib import Path
from typing import Protocol

import pytest
from sqlalchemy import Engine, MetaData, create_engine, event
lazy from mysql.connector import MySQLConnection

from include.database.engine import create_database_engine
from include.database.session import Base


class SqliteEngineFactory(Protocol):
    def __call__(
        self,
        path: str | Path = ":memory:",
        *,
        timeout_seconds: float | None = None,
    ) -> Engine: ...


@pytest.fixture
def isolated_metadata() -> MetaData:
    metadata = MetaData(naming_convention=Base.metadata.naming_convention)
    for table in Base.metadata.tables.values():
        table.to_metadata(metadata)
    return metadata


@pytest.fixture
def mysql_pure_engine() -> Generator[Engine]:
    database_url = os.environ.get("CFMS_TEST_MYSQL_URL")
    if database_url is None:
        pytest.skip("CFMS_TEST_MYSQL_URL is required")

    engine = create_engine(
        database_url,
        connect_args={"use_pure": True},
        execution_options={"preserve_rowcount": True},
    )
    try:
        with engine.connect() as connection:
            assert isinstance(connection.connection.driver_connection, MySQLConnection)
        yield engine
    finally:
        engine.dispose()


@pytest.fixture
def sqlite_engine_factory(request: pytest.FixtureRequest) -> SqliteEngineFactory:
    def create(
        path: str | Path = ":memory:", *, timeout_seconds: float | None = None
    ) -> Engine:
        engine = create_database_engine({"type": "sqlite", "file": str(path)})
        request.addfinalizer(engine.dispose)
        if timeout_seconds is not None:

            @event.listens_for(engine, "connect")
            def configure_timeout(connection, _record) -> None:
                connection.execute(f"PRAGMA busy_timeout={int(timeout_seconds * 1000)}")

        return engine

    return create
