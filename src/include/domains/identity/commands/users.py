import time
import uuid

from include.database.models.auth import UserPasswordCredential
from include.database.models.identity import User, UserMembership, UserPermission
from include.database.session import Session
from include.domains.identity.auth.types import AuthPurpose
from include.domains.identity.commands.auth_policies import replace_auth_policy
from include.domains.identity.commands.credentials import set_password


def create_user(**kwargs) -> uuid.UUID:
    """
    Create a new user in the system.

    This utility hashes the provided password (if any) using argon2id and creates
    a user record along with associated credentials, permissions, and group memberships.

    Args:
        **kwargs: Arbitrary keyword arguments that may include:
            - username (str): The username for the new user.
            - password (str, optional): The password for the new user.
            - nickname (str, optional): The nickname for the new user.
            - permissions (list, optional): A list of dicts for user
              permissions. Each dict may contain:
                - permission (str): The permission to be granted.
                - granted (bool, optional): Whether the permission is
                  granted (default is True).
                - start_time (float, optional): The start time for the
                  permission (default is current time).
                - end_time (float, optional): The end time for the
                  permission (default is None).
            - groups (list, optional): A list of dicts for user group
              memberships. Each dict may contain:
                - group_name (str): The name of the group.
                - start_time (float, optional): The start time for the
                  membership (default is current time).
                - end_time (float, optional): The end time for the
                  membership (default is None).

    Returns:
        uuid.UUID: The ID of the committed user.
    """

    raw_password = kwargs.get("password")
    with Session() as session:
        user = User(
            username=kwargs["username"],
            nickname=kwargs.get("nickname", None),
            last_login=0,
            created_time=time.time(),
        )
        session.add(user)
        if raw_password:
            session.flush()
            set_password(session, user, raw_password)
            session.flush()
            credential = session.get(UserPasswordCredential, user.id)
            replace_auth_policy(
                session,
                user,
                AuthPurpose.LOGIN,
                [
                    [
                        {
                            "method": "password",
                            "credential_ids": [credential.credential_id],
                        }
                    ]
                ],
                expected_revision=0,
            )

        for i in kwargs.get("permissions", []):
            permission = UserPermission(
                user=user,
                permission=i["permission"],
                granted=i.get("granted", True),
                start_time=i.get("start_time", time.time()),
                end_time=i.get("end_time"),
            )
            session.add(permission)

        for k in kwargs.get("groups", []):
            membership = UserMembership(
                user=user,
                group_name=k["group_name"],
                start_time=k.get("start_time", time.time()),
                end_time=k.get("end_time", None),
            )
            session.add(membership)

        session.flush()
        user_id = user.id
        session.commit()
        return user_id
