import os

import pytest
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, insert, inspect, text

from include.database.engine import create_database_engine
from maintenance.database_migration import migrate_database
from maintenance.database_schema import DatabaseSchemaError, upgrade_database_schema
from maintenance.database_tables import APPLICATION_TABLE_NAMES
from tests.maintenance.test_backup_format_compatibility import _seed_source
from tests.maintenance.test_database_migration import (
    _script_directory,
    _seed_runtime_tables,
)

pytestmark = pytest.mark.skipif(
    "CFMS_TEST_MYSQL_URL" not in os.environ,
    reason="CFMS_TEST_MYSQL_URL is required for MySQL migration integration tests",
)


def test_unversioned_mysql_schema_is_rejected_without_stamping(backup_context) -> None:
    mysql_engine = create_engine(os.environ["CFMS_TEST_MYSQL_URL"])
    _clear_mysql_database(mysql_engine)
    try:
        backup_context.Base.metadata.create_all(mysql_engine)

        with pytest.raises(DatabaseSchemaError, match="Non-empty unversioned"):
            upgrade_database_schema(mysql_engine, backup_context.Base.metadata)

        with mysql_engine.connect() as connection:
            assert "users" in inspect(connection).get_table_names()
            assert MigrationContext.configure(connection).get_current_revision() is None
    finally:
        _clear_mysql_database(mysql_engine)
        mysql_engine.dispose()


@pytest.mark.parametrize("direction", ["sqlite-to-mysql", "mysql-to-sqlite"])
def test_database_migration_round_trip_with_supported_mysql_lts(
    backup_context,
    tmp_path,
    direction,
) -> None:
    base = backup_context.Base
    mysql_engine = create_engine(os.environ["CFMS_TEST_MYSQL_URL"])
    _clear_mysql_database(mysql_engine)
    sqlite_engine = create_database_engine(
        {"type": "sqlite", "file": str(tmp_path / "migration.db")}
    )
    scripts = _script_directory()
    head = scripts.get_current_head()
    assert head is not None

    if direction == "sqlite-to-mysql":
        source_engine, target_engine = sqlite_engine, mysql_engine
        base.metadata.create_all(source_engine)
    else:
        source_engine, target_engine = mysql_engine, sqlite_engine
        base.metadata.create_all(source_engine)

    storage_root = tmp_path / "storage"
    storage_root.mkdir()
    try:
        _seed_source(base, source_engine, storage_root)
        _seed_runtime_tables(base, source_engine)
        with source_engine.begin() as connection:
            MigrationContext.configure(connection).stamp(scripts, head)

        result = migrate_database(
            source_engine,
            target_engine,
            base.metadata,
            scripts,
        )

        expected_dialects = (
            ("sqlite", "mysql")
            if direction == "sqlite-to-mysql"
            else ("mysql", "sqlite")
        )
        assert (result.source_dialect, result.target_dialect) == expected_dialects
        assert tuple(table.name for table in result.tables) == APPLICATION_TABLE_NAMES
        with target_engine.begin() as connection:
            comments = base.metadata.tables["comments"]
            inserted = connection.execute(
                insert(comments).values(
                    digest_version=1,
                    content_digest=bytes.fromhex("11" * 32),
                    comment_text="post-migration sequence check",
                    comment_data={"verified": True},
                )
            )
            assert inserted.inserted_primary_key[0] > 3
            assert MigrationContext.configure(connection).get_current_heads() == (head,)
    finally:
        sqlite_engine.dispose()
        _clear_mysql_database(mysql_engine)
        mysql_engine.dispose()


def _clear_mysql_database(mysql_engine) -> None:
    with mysql_engine.connect() as connection:
        connection.execute(text("SET FOREIGN_KEY_CHECKS=0"))
        for table_name in inspect(connection).get_table_names():
            quoted_name = connection.dialect.identifier_preparer.quote(table_name)
            connection.execute(text(f"DROP TABLE {quoted_name}"))
        connection.execute(text("SET FOREIGN_KEY_CHECKS=1"))
        connection.commit()
