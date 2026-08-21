from pathlib import Path
from shutil import copyfile

import pytest
from sqlalchemy import create_engine, event, select, update
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def permission_cleanup_context(monkeypatch, tmp_path):
    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)

    from include.database.models.identity import (
        User,
        UserGroup,
        UserGroupPermission,
        UserPermission,
    )
    from include.database.session import Base, global_config
    from include.domains.identity.commands.permission_cleanup import (
        count_expired_permission_entries,
        purge_expired_permission_entries,
    )

    engine = create_engine(f"sqlite:///{tmp_path / 'permissions.db'}")
    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine)

    yield {
        "User": User,
        "UserGroup": UserGroup,
        "UserGroupPermission": UserGroupPermission,
        "UserPermission": UserPermission,
        "count": count_expired_permission_entries,
        "purge": purge_expired_permission_entries,
        "session": test_session,
    }

    global_config.stop()
    engine.dispose()


def _seed_permission_entries(context) -> None:
    User = context["User"]
    UserGroup = context["UserGroup"]
    UserGroupPermission = context["UserGroupPermission"]
    UserPermission = context["UserPermission"]

    with context["session"].begin() as session:
        user = User(username="alice", pass_hash="hash", created_time=0.0)
        user.rights.extend(
            [
                UserPermission(
                    permission="old_grant",
                    granted=True,
                    start_time=0.0,
                    end_time=800.0,
                ),
                UserPermission(
                    permission="old_revocation",
                    granted=False,
                    start_time=0.0,
                    end_time=900.0,
                ),
                UserPermission(
                    permission="boundary",
                    granted=True,
                    start_time=0.0,
                    end_time=1000.0,
                ),
                UserPermission(
                    permission="active",
                    granted=True,
                    start_time=0.0,
                    end_time=None,
                ),
                UserPermission(
                    permission="permanent_revocation",
                    granted=False,
                    start_time=0.0,
                    end_time=None,
                ),
                UserPermission(
                    permission="future",
                    granted=True,
                    start_time=2000.0,
                    end_time=3000.0,
                ),
            ]
        )
        group = UserGroup(group_name="staff")
        group.permissions.extend(
            [
                UserGroupPermission(
                    permission="old_group_grant",
                    granted=True,
                    start_time=0.0,
                    end_time=700.0,
                ),
                UserGroupPermission(
                    permission="active_group",
                    granted=True,
                    start_time=0.0,
                    end_time=None,
                ),
                UserGroupPermission(
                    permission="permanent_group_revocation",
                    granted=False,
                    start_time=0.0,
                    end_time=None,
                ),
            ]
        )
        session.add_all([user, group])


def test_cleanup_uses_strict_cutoff_and_preserves_active_entries(
    permission_cleanup_context,
) -> None:
    context = permission_cleanup_context
    _seed_permission_entries(context)

    with context["session"]() as session:
        user = session.get(context["User"], "alice")
        group = session.get(context["UserGroup"], "staff")
        assert user.own_permissions == {"active"}
        assert group.all_permissions == {"active_group"}
        assert context["count"](session, 1000.0).user_entries == 2
        assert context["count"](session, 1000.0).group_entries == 1

    with context["session"].begin() as session:
        removed = context["purge"](session, 1000.0, batch_size=10)

    assert removed.user_entries == 2
    assert removed.group_entries == 1
    with context["session"]() as session:
        user = session.get(context["User"], "alice")
        group = session.get(context["UserGroup"], "staff")
        assert user.own_permissions == {"active"}
        assert group.all_permissions == {"active_group"}
        assert {entry.permission for entry in user.rights} == {
            "boundary",
            "active",
            "permanent_revocation",
            "future",
        }
        assert {entry.permission for entry in group.permissions} == {
            "active_group",
            "permanent_group_revocation",
        }
        assert context["count"](session, 1000.0).total == 0


def test_cleanup_honors_per_table_batch_limit_and_is_idempotent(
    permission_cleanup_context,
) -> None:
    context = permission_cleanup_context
    _seed_permission_entries(context)

    with context["session"].begin() as session:
        first = context["purge"](session, 1000.0, batch_size=1)
    with context["session"].begin() as session:
        second = context["purge"](session, 1000.0, batch_size=1)
    with context["session"].begin() as session:
        third = context["purge"](session, 1000.0, batch_size=1)

    assert first.user_entries == 1
    assert first.group_entries == 1
    assert second.user_entries == 1
    assert second.group_entries == 0
    assert third.total == 0


def test_cleanup_participates_in_caller_transaction(permission_cleanup_context) -> None:
    context = permission_cleanup_context
    _seed_permission_entries(context)

    with context["session"]() as session:
        removed = context["purge"](session, 1000.0, batch_size=10)
        assert removed.total == 3
        session.rollback()

    with context["session"]() as session:
        assert context["count"](session, 1000.0).total == 3


def test_cleanup_rechecks_cutoff_when_deleting(permission_cleanup_context) -> None:
    context = permission_cleanup_context
    User = context["User"]
    UserPermission = context["UserPermission"]
    with context["session"].begin() as session:
        user = User(username="alice", pass_hash="hash", created_time=0.0)
        entry = UserPermission(
            permission="rescheduled",
            granted=True,
            start_time=0.0,
            end_time=900.0,
        )
        user.rights.append(entry)
        session.add(user)

    with context["session"]() as session:
        moved = False

        @event.listens_for(session, "do_orm_execute")
        def move_entry_past_cutoff(execute_state):
            nonlocal moved
            if not execute_state.is_delete or moved:
                return
            moved = True
            session.connection().execute(
                update(UserPermission)
                .where(UserPermission.permission == "rescheduled")
                .values(end_time=1100.0)
            )

        removed = context["purge"](session, 1000.0, batch_size=10)
        session.commit()

    assert removed.user_entries == 0
    with context["session"]() as session:
        entry = session.scalar(
            select(UserPermission).where(UserPermission.permission == "rescheduled")
        )
        assert entry is not None
        assert entry.end_time == 1100.0
