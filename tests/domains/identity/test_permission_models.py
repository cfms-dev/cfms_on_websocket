import time
from pathlib import Path
from shutil import copyfile

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_permission_entries_survive_reload_and_respect_time_windows(
    monkeypatch, tmp_path
) -> None:
    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)

    from include.database.models.identity import (
        User,
        UserGroup,
        UserGroupPermission,
        UserMembership,
        UserPermission,
    )
    from include.database.session import Base

    engine = create_engine(f"sqlite:///{tmp_path / 'permissions.db'}")
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
        user = User(username="alice", pass_hash="hash", created_time=now)
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
        user = session.get(User, "alice")
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
        user = session.get(User, "alice")
        assert user is not None
        assert len(user.rights) == 4
        assert any(not entry.granted for entry in user.rights)
