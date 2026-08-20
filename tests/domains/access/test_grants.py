import time

import pytest


def _make_user(models, session, *, username="alice", memberships=()):
    created_at = time.time()
    user = models.User(
        username=username,
        pass_hash="hash",
        passwd_last_modified=created_at,
        nickname=username,
        avatar_id=None,
        last_login=None,
        created_time=created_at,
        status=0,
        secret_key=f"{username}-secret",
        totp_secret=None,
        totp_enabled=False,
        totp_backup_codes=None,
        preference_dek_id=None,
    )
    for group_name, start_time, end_time in memberships:
        if session.get(models.UserGroup, group_name) is None:
            session.add(
                models.UserGroup(
                    group_name=group_name,
                    group_display_name=group_name,
                )
            )
        membership = models.UserMembership(
            username=username,
            group_name=group_name,
            start_time=start_time,
            end_time=None,
        )
        user.groups.append(membership)
        membership.end_time = end_time
    session.add(user)
    session.flush()
    return user


def _grant_read(models, session, *, entity_type, entity_identifier):
    session.add(
        models.ObjectAccessEntry(
            entity_type=entity_type,
            entity_identifier=entity_identifier,
            target_type="directory",
            target_identifier="folder",
            access_type="read",
            start_time=0.0,
            end_time=None,
        )
    )
    session.flush()


def _granted_ids(session, user, *, now=1000.0):
    from include.domains.access.authorization.grants import (
        batch_prefetch_granted_ids,
    )

    return batch_prefetch_granted_ids(
        session,
        user,
        ["folder"],
        "directory",
        "read",
        now,
    )


def test_group_grant_does_not_match_a_same_named_user(access_rule_session):
    models, session = access_rule_session
    user = _make_user(models, session, username="shared-name")
    session.add(
        models.UserGroup(
            group_name="shared-name",
            group_display_name="shared-name",
        )
    )
    _grant_read(
        models,
        session,
        entity_type="group",
        entity_identifier="shared-name",
    )

    assert _granted_ids(session, user) == set()


def test_user_grant_does_not_match_a_same_named_group(access_rule_session):
    models, session = access_rule_session
    _make_user(models, session, username="shared-name")
    user = _make_user(
        models,
        session,
        username="alice",
        memberships=(("shared-name", 0.0, None),),
    )
    _grant_read(
        models,
        session,
        entity_type="user",
        entity_identifier="shared-name",
    )

    assert _granted_ids(session, user) == set()


@pytest.mark.parametrize(
    ("membership_start", "membership_end", "expected"),
    [
        pytest.param(2000.0, None, set(), id="future"),
        pytest.param(0.0, 500.0, set(), id="expired"),
        pytest.param(0.0, None, {"folder"}, id="active"),
    ],
)
def test_group_grant_requires_an_active_membership(
    access_rule_session,
    membership_start,
    membership_end,
    expected,
):
    models, session = access_rule_session
    user = _make_user(
        models,
        session,
        memberships=(("readers", membership_start, membership_end),),
    )
    _grant_read(
        models,
        session,
        entity_type="group",
        entity_identifier="readers",
    )

    assert _granted_ids(session, user) == expected


def test_direct_user_grant_still_matches(access_rule_session):
    models, session = access_rule_session
    user = _make_user(models, session)
    _grant_read(
        models,
        session,
        entity_type="user",
        entity_identifier=user.username,
    )

    assert _granted_ids(session, user) == {"folder"}
