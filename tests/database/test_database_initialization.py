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


def test_fresh_database_is_initialized_and_stamped(tmp_path, sqlite_engine_factory):
    engine = sqlite_engine_factory(tmp_path / "fresh.db")

    initialize_database_schema(engine, Base.metadata)
    initialize_database_schema(engine, Base.metadata)

    scripts = ScriptDirectory.from_config(Config(EXECUTABLE_ABSPATH / "alembic.ini"))
    with engine.connect() as connection:
        assert "users" in inspect(connection).get_table_names()
        assert (
            MigrationContext.configure(connection).get_current_revision()
            == scripts.get_current_head()
        )


def test_existing_old_database_is_not_modified_before_upgrade(
    tmp_path, sqlite_engine_factory
):
    engine = sqlite_engine_factory(tmp_path / "old.db")
    scripts = ScriptDirectory.from_config(Config(EXECUTABLE_ABSPATH / "alembic.ini"))
    head = scripts.get_current_head()
    assert head is not None
    revision = scripts.get_revision(head)
    assert revision is not None
    assert isinstance(revision.down_revision, str)
    with engine.begin() as connection:
        connection.exec_driver_sql("CREATE TABLE legacy_data (id INTEGER PRIMARY KEY)")
        MigrationContext.configure(connection).stamp(scripts, revision.down_revision)
    with pytest.raises(RuntimeError):
        initialize_database_schema(engine, Base.metadata)
    with engine.connect() as connection:
        assert set(inspect(connection).get_table_names()) == {
            "legacy_data",
            "alembic_version",
        }
