from pathlib import Path
from shutil import copyfile

import pytest
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, inspect

from alembic import command
from tests.support.config import reserve_local_port, write_test_config


def test_upgrade_to_head_succeeds(
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

    expected_heads = tuple(ScriptDirectory.from_config(config).get_heads())
    engine = create_engine(database_url)
    try:
        database_models.User.metadata.create_all(engine)
        command.stamp(config, "head")
        command.downgrade(config, "-1")
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
    finally:
        engine.dispose()
