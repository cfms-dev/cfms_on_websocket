from pathlib import Path

import pytest
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect

import include.database.models  # noqa: F401
from include.config.paths import EXECUTABLE_ABSPATH
from include.database.initialization import initialize_database_schema
from include.database.session import Base

pytestmark = pytest.mark.component


def test_fresh_database_is_initialized_and_stamped(
    tmp_path: Path, sqlite_engine_factory
) -> None:
    engine = sqlite_engine_factory(tmp_path / "fresh.db")

    initialize_database_schema(engine, Base.metadata)

    scripts = ScriptDirectory.from_config(Config(EXECUTABLE_ABSPATH / "alembic.ini"))
    with engine.connect() as connection:
        assert "users" in inspect(connection).get_table_names()
        assert (
            MigrationContext.configure(connection).get_current_revision()
            == scripts.get_current_head()
        )
