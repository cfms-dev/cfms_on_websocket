from contextlib import ExitStack
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import create_engine, select

from alembic import command
from include.database.models.identity import User

pytestmark = pytest.mark.component


@pytest.mark.parametrize("preexisting", [False, True])
def test_setting_permission_migration_preserves_independent_grants(
    tmp_path, preexisting
):
    config = Config(Path(__file__).resolve().parents[3] / "src/alembic.ini")
    engine = create_engine(f"sqlite:///{(tmp_path / 'permissions.db').as_posix()}")
    tables = User.metadata.tables
    permissions = tables["group_permissions"]
    states = tables["system_states"]
    with ExitStack() as resources:
        resources.callback(engine.dispose)
        config.attributes["connection"] = resources.enter_context(engine.connect())
        User.metadata.create_all(engine)
        command.stamp(config, "16c86712512a")
        with engine.begin() as connection:
            connection.execute(
                tables["user_groups"].insert(),
                {"group_name": "sysop", "group_display_name": "System operators"},
            )
            if preexisting:
                connection.execute(
                    permissions.insert(),
                    {
                        "group_name": "sysop",
                        "permission": "view_settings",
                        "granted": True,
                        "start_time": 0.0,
                        "end_time": None,
                    },
                )
        command.upgrade(config, "head")
        with engine.begin() as connection:
            grants = (
                connection.execute(select(permissions.c.permission)).scalars().all()
            )
            assert sorted(grants) == ["manage_settings", "view_settings"]
            markers = (
                connection.execute(
                    select(states.c.state_key).where(
                        states.c.owner == "migration:e952c02c1454"
                    )
                )
                .scalars()
                .all()
            )
            assert set(markers) == (
                {"manage_settings"}
                if preexisting
                else {"manage_settings", "view_settings"}
            )
            connection.execute(
                permissions.insert(),
                {
                    "group_name": "sysop",
                    "permission": "manage_settings",
                    "granted": True,
                    "start_time": 100.0,
                    "end_time": 200.0,
                },
            )
        command.downgrade(config, "16c86712512a")
        with engine.connect() as connection:
            grants = set(
                connection.execute(
                    select(
                        permissions.c.permission,
                        permissions.c.start_time,
                        permissions.c.end_time,
                    )
                )
            )
            expected = {("manage_settings", 100.0, 200.0)}
            if preexisting:
                expected.add(("view_settings", 0.0, None))
            assert grants == expected
            assert (
                connection.execute(
                    select(states.c.state_key).where(
                        states.c.owner == "migration:e952c02c1454"
                    )
                ).all()
                == []
            )


def test_setting_permission_migration_without_sysop_is_reversible(tmp_path):
    config = Config(Path(__file__).resolve().parents[3] / "src/alembic.ini")
    engine = create_engine(f"sqlite:///{(tmp_path / 'empty.db').as_posix()}")
    with ExitStack() as resources:
        resources.callback(engine.dispose)
        config.attributes["connection"] = resources.enter_context(engine.connect())
        User.metadata.create_all(engine)
        command.stamp(config, "16c86712512a")
        command.upgrade(config, "head")
        command.downgrade(config, "16c86712512a")
        with engine.connect() as connection:
            assert (
                connection.execute(
                    select(User.metadata.tables["group_permissions"])
                ).all()
                == []
            )
            assert (
                connection.execute(select(User.metadata.tables["system_states"])).all()
                == []
            )
