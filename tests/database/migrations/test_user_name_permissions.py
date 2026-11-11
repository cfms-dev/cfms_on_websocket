from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from alembic import command
from include.database.models.identity import (
    User,
    UserGroup,
    UserGroupPermission,
    UserPermission,
)
from include.database.models.operations import AuditEntry
from include.database.session import Base

pytestmark = pytest.mark.component


def test_nickname_permission_migration_preserves_records_and_round_trips(
    sqlite_engine_factory,
):
    engine = sqlite_engine_factory()
    Base.metadata.create_all(engine)
    with sessionmaker(bind=engine).begin() as session:
        user = User(username="existing")
        for name in ("user", "sysop", "custom"):
            group = UserGroup(group_name=name)
            for permission, granted, start, end in (
                ("rename_user", True, 0.0, None),
                ("rename_user", False, 1.0, None),
                ("rename_user", True, 2.0, 3.0),
                ("super_rename_user", True, 10**12, None),
                ("super_rename_user", False, 0.0, None),
                ("unrelated", True, 0.0, None),
            ):
                group.permissions.append(
                    UserGroupPermission(
                        permission=permission,
                        granted=granted,
                        start_time=start,
                        end_time=end,
                    )
                )
                user.rights.append(
                    UserPermission(
                        permission=permission,
                        granted=granted,
                        start_time=start,
                        end_time=end,
                    )
                )
            session.add(group)
        user.audit_entries.append(
            AuditEntry(
                action="core.user.rename",
                target="existing",
                data={"permission": "rename_user"},
                result=200,
            )
        )
        session.add(user)

    tables = (UserPermission.__table__, UserGroupPermission.__table__)
    config = Config(Path(__file__).resolve().parents[3] / "src/alembic.ini")
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.stamp(config, "3815ba18197b")
        before = [
            connection.execute(select(table).order_by(table.c.id)).mappings().all()
            for table in tables
        ]
        audit_before = connection.execute(select(AuditEntry.__table__)).all()
        connection.commit()
        command.upgrade(config, "03197fed3401")
        renamed = {
            "rename_user": "set_nickname",
            "super_rename_user": "super_set_nickname",
        }
        for table, rows in zip(tables, before, strict=True):
            after = (
                connection.execute(select(table).order_by(table.c.id)).mappings().all()
            )
            assert after == [
                {**row, "permission": renamed.get(row["permission"], row["permission"])}
                for row in rows
            ]
            assert all(
                row["permission"] not in {"set_username", "super_set_username"}
                for row in after
            )
        assert connection.execute(select(AuditEntry.__table__)).all() == audit_before
        connection.commit()
        command.downgrade(config, "3815ba18197b")
        for table, rows in zip(tables, before, strict=True):
            assert (
                connection.execute(select(table).order_by(table.c.id)).mappings().all()
                == rows
            )


def test_nickname_permission_migration_does_not_create_groups(sqlite_engine_factory):
    engine = sqlite_engine_factory()
    Base.metadata.create_all(engine)
    config = Config(Path(__file__).resolve().parents[3] / "src/alembic.ini")
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.stamp(config, "3815ba18197b")
        command.upgrade(config, "03197fed3401")
        assert connection.execute(select(UserGroup)).all() == []
        assert connection.execute(select(UserGroupPermission)).all() == []
