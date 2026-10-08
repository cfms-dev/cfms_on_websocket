from pathlib import Path

import pytest
from sqlalchemy import event

from include.database.engine import create_database_engine


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
