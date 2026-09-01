from pathlib import Path

import pytest
from sqlalchemy import create_engine, inspect, text

import include.database.models  # noqa: F401
from include.database.schema import (
    LEGACY_V0_7_REVISION,
    DatabaseSchemaError,
    upgrade_database_schema,
    verify_database_schema,
)
from include.database.session import Base


def test_empty_database_is_created_and_stamped(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'empty.db'}")

    result = upgrade_database_schema(engine, Base.metadata)

    assert result.bootstrapped is True
    assert result.adopted_legacy is False
    assert verify_database_schema(engine) == result.current_revision
    with engine.connect() as connection:
        assert "users" in inspect(connection).get_table_names()


def test_unversioned_v070_schema_is_adopted(tmp_path: Path) -> None:
    engine = create_engine(f"sqlite:///{tmp_path / 'legacy.db'}")
    Base.metadata.create_all(engine)

    result = upgrade_database_schema(engine, Base.metadata)

    assert result.previous_revision == LEGACY_V0_7_REVISION
    assert result.adopted_legacy is True
    assert verify_database_schema(engine) == result.current_revision


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
