"""MySQL integration test for CACL Alembic migration a66108639ed7."""

from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.config import Config
from sqlalchemy import Engine, MetaData

import include.database.models  # noqa: F401
from alembic import command
from tests.database.migrations.test_cacl_migration import run_cacl_migration_round_trip

pytestmark = pytest.mark.integration
_ROOT = Path(__file__).resolve().parents[3]


def _drop_all_mysql_tables(engine: Engine) -> None:
    with engine.connect() as conn:
        table_names = sa.inspect(conn).get_table_names()
        if not table_names:
            return
        conn.execute(sa.text("SET FOREIGN_KEY_CHECKS = 0"))
        try:
            for table_name in table_names:
                quoted = table_name.replace("`", "``")
                conn.execute(sa.text(f"DROP TABLE IF EXISTS `{quoted}`"))
        finally:
            conn.execute(sa.text("SET FOREIGN_KEY_CHECKS = 1"))
        conn.commit()


def test_mysql_cacl_migration_upgrade_and_downgrade_round_trip(
    isolated_metadata: MetaData,
    mysql_pure_engine: Engine,
):
    _drop_all_mysql_tables(mysql_pure_engine)
    try:
        isolated_metadata.create_all(mysql_pure_engine)
        with mysql_pure_engine.connect() as connection:
            config = Config(_ROOT / "src/alembic.ini")
            config.attributes["connection"] = connection
            command.stamp(config, "head")
            run_cacl_migration_round_trip(connection, config)
    finally:
        _drop_all_mysql_tables(mysql_pure_engine)
