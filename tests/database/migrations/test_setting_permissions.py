from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import select

import include.database.models  # noqa: F401
from alembic import command
from include.database.session import Base

pytestmark = pytest.mark.component
_ALEMBIC_INI = Path(__file__).resolve().parents[3] / "src/alembic.ini"


@pytest.mark.parametrize("preexisting", [False, True])
def test_setting_permission_migration_preserves_independent_grants(
    sqlite_engine_factory, preexisting
):
    config = Config(_ALEMBIC_INI)
    engine = sqlite_engine_factory()
    tables = Base.metadata.tables
    permissions = tables["group_permissions"]
    states = tables["system_states"]
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.stamp(config, "16c86712512a")
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
        connection.commit()

        command.upgrade(config, "head")
        grants = connection.execute(select(permissions.c.permission)).scalars().all()
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
            {"manage_settings"} if preexisting else {"manage_settings", "view_settings"}
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
        connection.commit()

        command.downgrade(config, "16c86712512a")
        grants = set(
            connection.execute(
                select(
                    permissions.c.permission,
                    permissions.c.start_time,
                    permissions.c.end_time,
                )
            )
        )
        expected: set[tuple[str, float, float | None]] = {
            ("manage_settings", 100.0, 200.0)
        }
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


def test_setting_permission_migration_without_sysop_is_reversible(
    sqlite_engine_factory,
):
    config = Config(_ALEMBIC_INI)
    engine = sqlite_engine_factory()
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.stamp(config, "16c86712512a")
        command.upgrade(config, "head")
        command.downgrade(config, "16c86712512a")
        assert (
            connection.execute(select(Base.metadata.tables["group_permissions"])).all()
            == []
        )
        assert (
            connection.execute(select(Base.metadata.tables["system_states"])).all()
            == []
        )
