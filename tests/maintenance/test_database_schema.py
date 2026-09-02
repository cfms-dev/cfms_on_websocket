from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect, text

import include.database.models  # noqa: F401
from include.database.session import Base
from maintenance.database_schema import (
    DatabaseSchemaError,
    upgrade_database_schema,
)


def test_empty_database_is_created_and_stamped(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'empty.db'}")

    result = upgrade_database_schema(engine, Base.metadata)

    assert result.bootstrapped is True
    with engine.connect() as connection:
        assert "users" in inspect(connection).get_table_names()
        assert (
            MigrationContext.configure(connection).get_current_revision()
            == result.current_revision
        )


def test_versioned_database_at_head_is_accepted(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'versioned.db'}")
    initialized = upgrade_database_schema(engine, Base.metadata)

    result = upgrade_database_schema(engine, Base.metadata)

    assert result.previous_revision == initialized.current_revision
    assert result.current_revision == initialized.current_revision
    assert result.bootstrapped is False


def test_unversioned_application_schema_is_rejected_without_changes(
    tmp_path: Path,
) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'unversioned.db'}")
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        original_tables = set(inspect(connection).get_table_names())

    with pytest.raises(DatabaseSchemaError, match="Non-empty unversioned"):
        upgrade_database_schema(engine, Base.metadata)

    with engine.connect() as connection:
        assert set(inspect(connection).get_table_names()) == original_tables
        assert MigrationContext.configure(connection).get_current_revision() is None


def test_unknown_unversioned_schema_is_rejected_without_changes(
    tmp_path: Path,
) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'unknown.db'}")
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE local_table (id INTEGER PRIMARY KEY)"))

    with pytest.raises(DatabaseSchemaError, match="refusing to guess"):
        upgrade_database_schema(engine, Base.metadata)

    with engine.connect() as connection:
        assert inspect(connection).get_table_names() == ["local_table"]
