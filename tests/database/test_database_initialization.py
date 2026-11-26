import pytest
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from sqlalchemy.dialects import mysql
from sqlalchemy.sql import ddl

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


def test_isolated_metadata_mysql_ddl_preserves_sqlite_use_alter_foreign_keys(
    isolated_metadata, sqlite_engine_factory
):
    mysql_dialect = mysql.dialect()

    class _CompilingConnection:
        dialect = mysql_dialect

        def schema_for_object(self, obj):
            return obj.schema

        def execute(self, statement, *_args, **_kwargs):
            str(statement.compile(dialect=self.dialect))

        def _run_ddl_visitor(self, visitorcallable, element, **kwargs):
            visitorcallable(self.dialect, self, **kwargs).traverse_single(element)

    ddl.SchemaGenerator(
        mysql_dialect, _CompilingConnection(), checkfirst=False
    ).traverse_single(isolated_metadata)

    sqlite_engine = sqlite_engine_factory(":memory:")
    Base.metadata.create_all(sqlite_engine)
    inspector = inspect(sqlite_engine)
    assert "fk_documents_current_revision_id_document_revisions" in {
        fk["name"] for fk in inspector.get_foreign_keys("documents")
    }
    assert "fk_nodes_parent_id_folders" in {
        fk["name"] for fk in inspector.get_foreign_keys("nodes")
    }
    assert "fk_users_preference_dek_id" in {
        fk["name"] for fk in inspector.get_foreign_keys("users")
    }
