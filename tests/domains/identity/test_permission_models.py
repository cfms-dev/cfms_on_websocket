import time
from pathlib import Path

import pytest
from sqlalchemy import event, select
from sqlalchemy.orm import sessionmaker

pytestmark = pytest.mark.component

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_permission_entries_survive_reload_and_respect_time_windows(
    tmp_path, sqlite_engine_factory
) -> None:
    from include.database.models.identity import (
        User,
        UserGroup,
        UserGroupPermission,
        UserMembership,
        UserPermission,
    )
    from include.database.session import Base

    engine = sqlite_engine_factory(tmp_path / "permissions.db")
    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine)
    now = time.time()

    with test_session.begin() as session:
        group = UserGroup(group_name="staff")
        group.permissions.extend(
            [
                UserGroupPermission(
                    permission="list_users",
                    granted=True,
                    start_time=now - 100,
                    end_time=None,
                ),
                UserGroupPermission(
                    permission="future_group_permission",
                    granted=True,
                    start_time=now + 3600,
                    end_time=None,
                ),
                UserGroupPermission(
                    permission="expired_group_permission",
                    granted=True,
                    start_time=now - 200,
                    end_time=now - 100,
                ),
            ]
        )
        user = User(username="alice", created_time=now)
        user.rights.extend(
            [
                UserPermission(
                    permission="list_users",
                    granted=False,
                    start_time=now - 100,
                    end_time=None,
                ),
                UserPermission(
                    permission="create_user",
                    granted=True,
                    start_time=now - 100,
                    end_time=None,
                ),
                UserPermission(
                    permission="create_user",
                    granted=False,
                    start_time=now + 3600,
                    end_time=None,
                ),
                UserPermission(
                    permission="create_user",
                    granted=False,
                    start_time=now - 200,
                    end_time=now - 100,
                ),
            ]
        )
        user.groups.append(
            UserMembership(
                group_name="staff",
                start_time=now - 100,
                end_time=None,
            )
        )
        session.add_all([group, user])

    with test_session() as session:
        user = session.scalar(select(User).where(User.username == "alice"))
        group = session.get(UserGroup, "staff")

        assert user is not None
        assert group is not None
        assert len(user.rights) == 4
        assert len(group.permissions) == 3
        assert user.own_permissions == {"create_user"}
        assert user.inherited_permissions == {"list_users"}
        assert user.all_permissions == {"create_user"}
        assert group.all_permissions == {"list_users"}

        session.commit()

    with test_session() as session:
        user = session.scalar(select(User).where(User.username == "alice"))
        assert user is not None
        assert len(user.rights) == 4
        assert any(not entry.granted for entry in user.rights)


def test_group_permissions_batch_across_multiple_active_memberships(
    tmp_path, sqlite_engine_factory
) -> None:
    from include.database.models.identity import (
        User,
        UserGroup,
        UserGroupPermission,
        UserMembership,
    )
    from include.database.session import Base

    engine = sqlite_engine_factory(tmp_path / "batch_group_permissions.db")
    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine)
    now = time.time()

    with test_session.begin() as session:
        user = User(username="bob", created_time=now)
        for index in range(8):
            name = f"group_{index}"
            group = UserGroup(group_name=name)
            group.permissions.append(
                UserGroupPermission(
                    permission=f"perm_{index}",
                    granted=index != 7,
                    start_time=now - 100,
                    end_time=None,
                )
            )
            if index == 7:
                group.permissions.append(
                    UserGroupPermission(
                        permission="perm_0",
                        granted=False,
                        start_time=now - 100,
                        end_time=None,
                    )
                )
            session.add(group)
            user.groups.append(
                UserMembership(group_name=name, start_time=now - 100, end_time=None)
            )
        session.add(user)

    statements: list[str] = []

    def count_select(_conn, _cursor, statement, *_args):
        if statement.lstrip().upper().startswith("SELECT"):
            statements.append(statement)

    with test_session() as session:
        loaded_user = session.scalar(select(User).where(User.username == "bob"))
        assert loaded_user is not None
        event.listen(engine, "before_cursor_execute", count_select)
        try:
            permissions = loaded_user.all_permissions
        finally:
            event.remove(engine, "before_cursor_execute", count_select)

    assert permissions == {f"perm_{index}" for index in range(1, 7)}
    assert len(statements) == 3
