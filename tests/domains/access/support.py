import time

import pytest
from sqlalchemy.orm import sessionmaker


@pytest.fixture
def access_rule_session(sqlite_engine_factory):
    from include.database import models
    from include.database.session import Base

    engine = sqlite_engine_factory()
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    with SessionLocal() as session:
        session.add(models.Folder(id="/", name="/", inherit=False))
        session.commit()
        yield models, session


def _make_rule_user(models, session, *, permissions=(), groups=(), username="alice"):
    now = time.time()
    user = models.User(
        username=username,
        pass_hash="hash",
        passwd_last_modified=now,
        nickname=username,
        avatar_id=None,
        last_login=None,
        created_time=now,
        status=0,
        secret_key=f"{username}-secret",
        totp_secret=None,
        totp_enabled=False,
        totp_backup_codes=None,
        preference_dek_id=None,
    )
    for permission in permissions:
        user.rights.append(
            models.UserPermission(
                username=username,
                permission=permission,
                granted=True,
                start_time=0.0,
                end_time=None,
            )
        )
    for group_name in groups:
        if session.get(models.UserGroup, group_name) is None:
            session.add(
                models.UserGroup(
                    group_name=group_name,
                    group_display_name=group_name,
                )
            )
        user.groups.append(
            models.UserMembership(
                username=username,
                group_name=group_name,
                start_time=0.0,
                end_time=None,
            )
        )
    session.add(user)
    session.flush()
    return user


def _make_access_rule_user(models, session, username="alice"):
    now = time.time()
    user = models.User(
        username=username,
        pass_hash="hash",
        passwd_last_modified=now,
        nickname=username,
        avatar_id=None,
        last_login=None,
        created_time=now,
        status=0,
        secret_key=f"{username}-secret",
        totp_secret=None,
        totp_enabled=False,
        totp_backup_codes=None,
        preference_dek_id=None,
    )
    for permission in (
        "delete_document",
        "delete_directory",
        "list_users",
    ):
        user.rights.append(
            models.UserPermission(
                username=username,
                permission=permission,
                granted=True,
                start_time=0.0,
                end_time=None,
            )
        )
    session.add(user)
    session.flush()
    return user
