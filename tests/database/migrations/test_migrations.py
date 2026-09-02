from pathlib import Path
from shutil import copyfile

import pytest
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect, select

from alembic import command
from tests.support.config import reserve_local_port, write_test_config


def test_retained_revision_chain_round_trips_to_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src_dir = Path(__file__).resolve().parents[3] / "src"
    copyfile(src_dir / "config.toml.sample", tmp_path / "config.toml")
    write_test_config(tmp_path, reserve_local_port())
    monkeypatch.chdir(tmp_path)

    from include.database import models as database_models

    config = Config(src_dir / "alembic.ini")
    database_url = f"sqlite:///{(tmp_path / 'migrations.db').as_posix()}"
    config.set_main_option("sqlalchemy.url", database_url)

    scripts = ScriptDirectory.from_config(config)
    assert scripts.get_base() == "fe8863687aa4"
    expected_heads = tuple(scripts.get_heads())
    engine = create_engine(database_url)
    try:
        database_models.User.metadata.create_all(engine)
        command.stamp(config, "head")
        command.downgrade(config, "76f1c7621e23")
        with engine.connect() as connection:
            assert (
                MigrationContext.configure(connection).get_current_heads()
                != expected_heads
            )
            assert "ix_user_permissions_end_time_id" not in {
                index["name"]
                for index in inspect(connection).get_indexes("user_permissions")
            }
            assert "ix_group_permissions_end_time_id" not in {
                index["name"]
                for index in inspect(connection).get_indexes("group_permissions")
            }
            node_columns = {
                column["name"] for column in inspect(connection).get_columns("nodes")
            }
            assert "active_parent_id" in node_columns
            assert "active_name" not in node_columns

        command.upgrade(config, "head")
        with engine.connect() as connection:
            assert MigrationContext.configure(connection).get_current_heads() == (
                expected_heads
            )
            assert "ix_user_permissions_end_time_id" in {
                index["name"]
                for index in inspect(connection).get_indexes("user_permissions")
            }
            assert "ix_group_permissions_end_time_id" in {
                index["name"]
                for index in inspect(connection).get_indexes("group_permissions")
            }
            node_columns = {
                column["name"] for column in inspect(connection).get_columns("nodes")
            }
            assert "active_name" in node_columns
            assert "active_parent_id" not in node_columns
    finally:
        engine.dispose()


def test_scheduling_permission_downgrade_preserves_preexisting_grants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src_dir = Path(__file__).resolve().parents[3] / "src"
    copyfile(src_dir / "config.toml.sample", tmp_path / "config.toml")
    write_test_config(tmp_path, reserve_local_port())
    monkeypatch.chdir(tmp_path)

    from include.database import models as database_models

    config = Config(src_dir / "alembic.ini")
    database_url = f"sqlite:///{(tmp_path / 'permissions.db').as_posix()}"
    config.set_main_option("sqlalchemy.url", database_url)
    engine = create_engine(database_url)
    tables = database_models.User.metadata.tables
    try:
        database_models.User.metadata.create_all(engine)
        with engine.begin() as connection:
            connection.execute(
                tables["user_groups"].insert(),
                {"group_name": "sysop", "group_display_name": "System operators"},
            )
            connection.execute(
                tables["group_permissions"].insert(),
                {
                    "group_name": "sysop",
                    "permission": "view_schedules",
                    "granted": True,
                    "start_time": 0.0,
                    "end_time": None,
                },
            )
        command.stamp(config, "ab7efda19079")
        command.upgrade(config, "head")
        command.downgrade(config, "ab7efda19079")

        with engine.connect() as connection:
            permissions = set(
                connection.scalars(
                    select(tables["group_permissions"].c.permission).where(
                        tables["group_permissions"].c.group_name == "sysop"
                    )
                )
            )
            assert "view_schedules" in permissions
            assert "manage_schedules" not in permissions
    finally:
        engine.dispose()
