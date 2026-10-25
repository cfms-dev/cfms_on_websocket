from dataclasses import FrozenInstanceError

import pytest
from sqlalchemy import delete, select
from sqlalchemy.orm import sessionmaker

from include.database.models.identity import (
    User,
    UserGroup,
    UserGroupPermission,
    UserMembership,
    UserPermission,
)
from include.database.session import Base
from include.domains.identity.default_groups import DEFAULT_GROUP_PERMISSIONS
from include.runtime_lock import server_runtime_lock
from maintenance.operations import permissions
from maintenance.operations.exceptions import MaintenanceOperationError

pytestmark = pytest.mark.component


@pytest.fixture
def permission_sessions(monkeypatch, sqlite_engine_factory, tmp_path):
    engine = sqlite_engine_factory(tmp_path / "permissions.db")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(permissions, "enter_server_root", lambda: tmp_path)
    monkeypatch.setattr(permissions, "load_database_models", lambda: None)
    monkeypatch.setattr(permissions, "Session", sessions)
    return sessions


@pytest.mark.parametrize("group_names", [(), ("user",), ("sysop",), ("user", "sysop")])
def test_sync_adds_only_missing_records_to_existing_groups(
    permission_sessions, group_names
):
    with permission_sessions.begin() as session:
        session.add_all(UserGroup(group_name=name) for name in group_names)

    preview = permissions.inspect_default_group_permissions()
    expected = frozenset(
        (group, permission)
        for group in group_names
        for permission in DEFAULT_GROUP_PERMISSIONS[group]
    )
    assert preview.group_names == ("sysop", "user")
    assert preview.missing_groups == {"sysop", "user"} - set(group_names)
    assert preview.existing_permissions == frozenset()
    assert preview.missing_permissions == expected
    with pytest.raises(FrozenInstanceError):
        preview.group_names = ()

    assert permissions.sync_default_group_permissions(preview) == len(expected)
    repeated = permissions.inspect_default_group_permissions()
    assert repeated.missing_permissions == frozenset()
    assert repeated.existing_permissions == expected
    assert repeated.missing_groups == preview.missing_groups
    assert permissions.sync_default_group_permissions(repeated) == 0

    with permission_sessions() as session:
        assert set(session.scalars(select(UserGroup.group_name))) == set(group_names)
        rows = session.execute(
            select(
                UserGroupPermission.group_name,
                UserGroupPermission.permission,
                UserGroupPermission.granted,
                UserGroupPermission.start_time,
                UserGroupPermission.end_time,
            )
        ).all()
        assert set(rows) == {(*pair, True, 0.0, None) for pair in expected}
        assert len(rows) == len(expected)


@pytest.mark.parametrize(
    "selection",
    [None, ["user"], ["sysop"], ["sysop", "user", "sysop"]],
)
def test_group_selection_limits_writes_and_deduplicates_names(
    permission_sessions, selection
):
    with permission_sessions.begin() as session:
        session.add_all(UserGroup(group_name=name) for name in ("user", "sysop"))

    preview = permissions.inspect_default_group_permissions(selection)
    selected = set(selection) if selection is not None else {"user", "sysop"}
    assert preview.group_names == tuple(sorted(selected))
    assert {group for group, _ in preview.missing_permissions} == selected

    permissions.sync_default_group_permissions(preview)

    with permission_sessions() as session:
        assert set(session.scalars(select(UserGroupPermission.group_name))) == selected


@pytest.mark.parametrize(
    ("granted", "start", "end", "copies"),
    [
        pytest.param(True, 0.0, None, 1, id="permanent-grant"),
        pytest.param(False, 0.0, None, 1, id="permanent-revocation"),
        pytest.param(True, 0.0, 1.0, 1, id="expired-grant"),
        pytest.param(False, 0.0, 1.0, 1, id="expired-revocation"),
        pytest.param(True, 10**12, None, 1, id="future-grant"),
        pytest.param(False, 10**12, None, 1, id="future-revocation"),
        pytest.param(True, 0.0, None, 2, id="duplicate-grants"),
    ],
)
def test_sync_preserves_existing_records_and_other_identity_state(
    permission_sessions, granted, start, end, copies
):
    with permission_sessions.begin() as session:
        group = UserGroup(group_name="user", group_display_name="Customized users")
        group.permissions.extend(
            UserGroupPermission(
                permission="search",
                granted=granted,
                start_time=start,
                end_time=end,
            )
            for _ in range(copies)
        )
        group.permissions.append(
            UserGroupPermission(permission="extension.feature", granted=False)
        )
        staff = UserGroup(group_name="staff", group_display_name="Custom group")
        staff.permissions.append(UserGroupPermission(permission="staff_permission"))
        user = User(username="alice")
        user.groups.append(UserMembership(group=group, start_time=0.0))
        user.rights.append(
            UserPermission(permission="search", granted=False, start_time=0.0)
        )
        session.add_all([group, staff, user])

    tables = [
        model.__table__ for model in (UserGroup, UserMembership, UserPermission, User)
    ]
    with permission_sessions() as session:
        before = [
            session.execute(select(table).order_by(*table.primary_key)).all()
            for table in tables
        ]
        original_permissions = session.execute(
            select(UserGroupPermission.__table__).order_by(UserGroupPermission.id)
        ).all()

    preview = permissions.inspect_default_group_permissions(["user"])
    assert preview.existing_permissions == {("user", "search")}
    assert preview.missing_permissions == {("user", "configure_auth_methods")}
    assert permissions.sync_default_group_permissions(preview) == 1

    with permission_sessions() as session:
        assert [
            session.execute(select(table).order_by(*table.primary_key)).all()
            for table in tables
        ] == before
        assert (
            session.execute(
                select(UserGroupPermission.__table__)
                .where(
                    UserGroupPermission.id.in_([row.id for row in original_permissions])
                )
                .order_by(UserGroupPermission.id)
            ).all()
            == original_permissions
        )
        assert len(session.scalars(select(UserGroupPermission)).all()) == copies + 3


@pytest.mark.parametrize("change", ["permission", "missing-group", "same-count"])
def test_sync_rejects_changed_preview_without_writes(permission_sessions, change):
    with permission_sessions.begin() as session:
        group = UserGroup(group_name="user")
        if change == "same-count":
            group.permissions.append(UserGroupPermission(permission="search"))
        session.add(group)
    preview = permissions.inspect_default_group_permissions()
    with permission_sessions.begin() as session:
        if change == "missing-group":
            session.add(UserGroup(group_name="sysop"))
        else:
            if change == "same-count":
                session.execute(delete(UserGroupPermission))
            session.add(
                UserGroupPermission(
                    group_name="user", permission="configure_auth_methods"
                )
            )
    changed = permissions.inspect_default_group_permissions()

    with pytest.raises(MaintenanceOperationError):
        permissions.sync_default_group_permissions(preview)

    assert permissions.inspect_default_group_permissions() == changed
    assert permissions.sync_default_group_permissions(changed) == len(
        changed.missing_permissions
    )


def test_sync_rolls_back_all_inserts_and_releases_lock_on_failure(
    permission_sessions, tmp_path
):
    with permission_sessions.begin() as session:
        session.add(UserGroup(group_name="user"))
        session.connection().exec_driver_sql(
            "CREATE TRIGGER reject_search BEFORE INSERT ON group_permissions "
            "WHEN NEW.permission = 'search' "
            "BEGIN SELECT RAISE(ABORT, 'insertion blocked'); END"
        )
    preview = permissions.inspect_default_group_permissions(["user"])

    with pytest.raises(MaintenanceOperationError):
        permissions.sync_default_group_permissions(preview)

    assert permissions.inspect_default_group_permissions(["user"]) == preview
    with server_runtime_lock(tmp_path), permission_sessions.begin() as session:
        assert session.scalars(select(UserGroupPermission)).all() == []
        session.connection().exec_driver_sql("DROP TRIGGER reject_search")
    assert permissions.sync_default_group_permissions(preview) == 2


def test_preview_works_while_runtime_lock_blocks_writes(permission_sessions, tmp_path):
    with permission_sessions.begin() as session:
        session.add(UserGroup(group_name="user"))
    with server_runtime_lock(tmp_path):
        preview = permissions.inspect_default_group_permissions(["user"])
        assert len(preview.missing_permissions) == 2
        with pytest.raises(MaintenanceOperationError):
            permissions.sync_default_group_permissions(preview)
        assert permissions.inspect_default_group_permissions(["user"]) == preview
    assert permissions.sync_default_group_permissions(preview) == 2


def test_unfinished_deployment_blocks_writes(permission_sessions, tmp_path):
    with permission_sessions.begin() as session:
        session.add(UserGroup(group_name="user"))
    preview = permissions.inspect_default_group_permissions(["user"])
    transaction = tmp_path / ".maintenance" / "transaction.json"
    transaction.parent.mkdir()
    transaction.write_text("{}", encoding="utf-8")

    with pytest.raises(MaintenanceOperationError):
        permissions.sync_default_group_permissions(preview)

    assert permissions.inspect_default_group_permissions(["user"]) == preview
    assert not (transaction.parent / "server.lock").exists()


def test_inspection_translates_database_failure(permission_sessions):
    with permission_sessions.begin() as session:
        UserGroupPermission.__table__.drop(session.connection())

    with pytest.raises(MaintenanceOperationError):
        permissions.inspect_default_group_permissions()
