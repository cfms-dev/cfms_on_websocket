from pathlib import Path

import pytest
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import inspect

import include.database.models  # noqa: F401
from alembic import command
from include.database.session import Base

pytestmark = pytest.mark.component
_ALEMBIC_INI = Path(__file__).resolve().parents[3] / "src/alembic.ini"


def test_options_migration_round_trip_and_nonempty_downgrade_protection(
    sqlite_engine_factory,
):
    engine = sqlite_engine_factory()
    config = Config(_ALEMBIC_INI)
    with engine.begin() as connection:
        Base.metadata.create_all(connection)
        config.attributes["connection"] = connection
        command.stamp(config, "16c86712512a")
        connection.exec_driver_sql(
            "INSERT INTO system_states VALUES ('core', 'options_revision.server', 1, 1, '{}', 1.0)"
        )
        connection.exec_driver_sql(
            "INSERT INTO system_states VALUES ('core', 'optionsxrevision.server', 1, 1, '{}', 1.0)"
        )
        command.downgrade(config, "03197fed3401")
        assert connection.exec_driver_sql(
            "SELECT state_key FROM system_states"
        ).scalars().all() == ["optionsxrevision.server"]
        assert "options" not in inspect(connection).get_table_names()
        command.upgrade(config, "16c86712512a")
        columns = {
            column["name"] for column in inspect(connection).get_columns("options")
        }
        assert "payload" not in columns
        assert {"option_value", "value_type"} <= columns
        connection.exec_driver_sql(
            "INSERT INTO options VALUES ('server', 'core', 'name', 1, 1, 'str', 'Saved', 1.0)"
        )
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        with pytest.raises(RuntimeError):
            command.downgrade(config, "03197fed3401")
        assert (
            MigrationContext.configure(connection).get_current_revision()
            == "16c86712512a"
        )
        assert (
            connection.exec_driver_sql("SELECT option_value FROM options").scalar_one()
            == "Saved"
        )
