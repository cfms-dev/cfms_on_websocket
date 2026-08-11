import importlib.util
from pathlib import Path

import pytest
from alembic.migration import MigrationContext
from alembic.operations import Operations
from sqlalchemy import MetaData, create_engine, inspect
from sqlalchemy.exc import IntegrityError


def _load_migration():
    path = (
        Path(__file__).resolve().parents[3]
        / "src"
        / "alembic"
        / "versions"
        / "bb835a9f2cf4_add_generic_system_state_storage.py"
    )
    spec = importlib.util.spec_from_file_location("system_state_migration", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _run(connection, migration, operation):
    context = MigrationContext.configure(
        connection,
        opts={
            "render_as_batch": True,
            "target_metadata": MetaData(naming_convention={"pk": "pk_%(table_name)s"}),
        },
    )
    operations = Operations(context)
    with operations.context(context):
        getattr(migration, operation)()


def test_system_state_migration_round_trips(tmp_path) -> None:
    migration = _load_migration()
    engine = create_engine(f"sqlite:///{tmp_path / 'system-state-migration.db'}")

    with engine.begin() as connection:
        _run(connection, migration, "upgrade")
        inspector = inspect(connection)
        assert "system_states" in inspector.get_table_names()
        assert {
            "owner",
            "state_key",
            "schema_version",
            "revision",
            "payload",
            "updated_at",
        } == {column["name"] for column in inspector.get_columns("system_states")}
        assert inspector.get_pk_constraint("system_states")["constrained_columns"] == [
            "owner",
            "state_key",
        ]
        check_names = {
            constraint["name"]
            for constraint in inspector.get_check_constraints("system_states")
        }
        assert check_names == {
            "ck_system_states_revision_positive",
            "ck_system_states_schema_version_positive",
        }

        connection.exec_driver_sql(
            "INSERT INTO system_states "
            "(owner, state_key, schema_version, revision, payload, updated_at) "
            "VALUES ('core', 'lockdown', 1, 1, '{}', 1.0)"
        )
        with pytest.raises(IntegrityError):
            with connection.begin_nested():
                connection.exec_driver_sql(
                    "INSERT INTO system_states "
                    "(owner, state_key, schema_version, revision, payload, updated_at) "
                    "VALUES ('sample_ext', 'invalid', 0, 1, '{}', 1.0)"
                )

        _run(connection, migration, "downgrade")
        assert "system_states" not in inspect(connection).get_table_names()

    engine.dispose()
