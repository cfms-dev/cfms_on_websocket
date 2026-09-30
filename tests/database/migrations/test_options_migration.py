from pathlib import Path

import pytest
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, inspect

from alembic import command
from include.database.session import Base


def test_options_migration_round_trip_and_nonempty_downgrade_protection(tmp_path):
    root = Path(__file__).resolve().parents[3] / "src"
    engine = create_engine(f"sqlite:///{tmp_path / 'migration.db'}")
    config = Config(root / "alembic.ini")
    with engine.begin() as connection:
        Base.metadata.create_all(connection)
        config.attributes["connection"] = connection
        command.stamp(config, "2a32581dc561")
        command.downgrade(config, "0460356a5ba6")
        assert "options" not in inspect(connection).get_table_names()
        command.upgrade(config, "2a32581dc561")
        connection.exec_driver_sql(
            "INSERT INTO options VALUES ('core', 'server', 1, 1, '{\"name\":\"Saved\"}', 1.0)"
        )
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        with pytest.raises(RuntimeError, match="persistent configuration"):
            command.downgrade(config, "0460356a5ba6")
        assert (
            MigrationContext.configure(connection).get_current_revision()
            == "2a32581dc561"
        )
        assert (
            connection.exec_driver_sql("SELECT payload FROM options").scalar_one()
            == '{"name":"Saved"}'
        )
    engine.dispose()
