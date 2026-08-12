__all__ = [
    "RequestListGroupsHandler",
    # ...
]

from include.database.models.identity import (
    User,
    UserGroup,
    UserGroupPermission,
    UserMembership,
)
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.identity.commands.groups import create_group
from include.domains.identity.request_models import (
    OffsetPaginationRequest,
    TimedPermission,
)
from include.domains.pagination import get_offset_pagination
from include.messages import Messages as smsg
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import (
    REQUEST_UNSET,
    Omittable,
    RequestDataModel,
    RequestHandler,
    Result,
)
from include.types import NonEmptyString


class _CreateGroupRequest(RequestDataModel):
    group_name: NonEmptyString
    display_name: str | None = None
    permissions: Omittable[list[TimedPermission]] = REQUEST_UNSET


class _GroupNameRequest(RequestDataModel):
    group_name: NonEmptyString


class _RenameGroupRequest(RequestDataModel):
    group_name: NonEmptyString
    display_name: str | None


class _ChangeGroupPermissionsRequest(RequestDataModel):
    group_name: NonEmptyString
    permissions: list[str]


class RequestListGroupsHandler(RequestHandler):
    request_model = OffsetPaginationRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        offset, count = get_offset_pagination(handler.data)

        with Session() as session:
            user = User.get_existing(session, handler.username)  # Requesting user.

            if Permissions.LIST_GROUPS not in user.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to list groups",
                    data={},
                )
                return

            total = session.query(UserGroup).count()
            groups = (
                session.query(UserGroup)
                .order_by(UserGroup.group_name.asc())
                .offset(offset)
                .limit(count)
                .all()
            )
            response = {
                "code": 200,
                "message": "List of groups",
                "data": {
                    "groups": [
                        {
                            "name": group.group_name,
                            "display_name": group.group_display_name,
                            "permissions": list(group.all_permissions),
                            "members": list(group.members),
                        }
                        for group in groups
                    ],
                    "total": total,
                    "offset": offset,
                    "count": count,
                    "has_more": offset + len(groups) < total,
                },
            }

            handler.conclude_request(**response)


class RequestCreateGroupHandler(RequestHandler):
    request_model = _CreateGroupRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        data = handler.data
        new_group_name = data["group_name"]
        new_display_name = data.get("display_name")
        new_group_permissions = data.get("permissions", [])

        with Session() as session:
            user = User.get_existing(session, handler.username)

            # currently handle_create_group() will not judge whether the requesting
            # user is eligible to apply the given permissions for the new group.
            #
            # `Permissions.CREATE_GROUP` is a dangerous privilege that should only
            # be held by administrators.

            if Permissions.CREATE_GROUP not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.PERMISSION_DENIED_CREATE_GROUP)
                return Result(
                    code=403, target=new_group_name, username=handler.username
                )

            if session.get(UserGroup, new_group_name):
                handler.conclude_request(400, {}, smsg.GROUP_ALREADY_EXISTS)
                return

            create_group(
                group_name=new_group_name,
                display_name=new_display_name,
                permissions=new_group_permissions,
            )

        handler.conclude_request(200, {}, "Group created successfully")
        return Result(code=0, target=new_group_name, username=handler.username)


class RequestDeleteGroupHandler(RequestHandler):
    request_model = _GroupNameRequest

    require_auth = True
    rate_limit_cost = 5

    def handle(self, handler: ConnectionHandler):

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            if Permissions.DELETE_GROUP not in this_user.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to delete groups",
                    data={},
                )
                return Result(
                    code=403,
                    target=handler.data["group_name"],
                    username=handler.username,
                )

            group_to_delete_name: str = handler.data["group_name"]
            group_to_delete = session.get(UserGroup, group_to_delete_name)

            if not group_to_delete:
                handler.conclude_request(
                    code=404, message="Group does not exist", data={}
                )
                return Result(
                    code=404, target=group_to_delete_name, username=handler.username
                )

            # Retrieve all memberships associated with the group
            memberships_to_delete = (
                session.query(UserMembership)
                .filter_by(group_name=group_to_delete_name)
                .all()
            )
            for membership in memberships_to_delete:
                session.delete(membership)

            # Retrieve all permissions associated with the group
            permissions_to_delete = (
                session.query(UserGroupPermission)
                .filter_by(group_name=group_to_delete_name)
                .all()
            )
            for permission in permissions_to_delete:
                session.delete(permission)

            session.delete(group_to_delete)
            session.commit()

        response = {
            "code": 200,
            "message": "Group deleted successfully",
            "data": {},
        }

        handler.conclude_request(**response)
        return Result(
            code=0, target=handler.data["group_name"], username=handler.username
        )


class RequestRenameGroupHandler(RequestHandler):
    request_model = _RenameGroupRequest

    require_auth = True
    rate_limit_cost = 5

    def handle(self, handler: ConnectionHandler):

        target_group_name: str = handler.data["group_name"]

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            if Permissions.RENAME_GROUP not in this_user.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to rename groups",
                    data={},
                )
                return Result(
                    code=403, target=target_group_name, username=handler.username
                )

            new_display_name: str | None = handler.data.get("display_name", None)
            if type(new_display_name) not in (str, None):
                handler.conclude_request(
                    code=400, message="display_name must be null or a string", data={}
                )
                return

            group_to_rename = session.get(UserGroup, target_group_name)
            if not group_to_rename:
                handler.conclude_request(
                    code=400, message="Group does not exist", data={}
                )
                return

            group_to_rename.group_display_name = new_display_name
            session.commit()

        response = {
            "code": 200,
            "message": "Group renamed successfully",
            "data": {},
        }

        handler.conclude_request(**response)
        return Result(code=0, target=target_group_name, username=handler.username)


class RequestGetGroupInfoHandler(RequestHandler):
    request_model = _GroupNameRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):

        with Session() as session:
            user = User.get_existing(session, handler.username)  # Requesting user.

            if not handler.data["group_name"]:
                handler.conclude_request(
                    code=400, message="Group name is required", data={}
                )
                return

            if Permissions.GET_GROUP_INFO not in user.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to view group info",
                    data={},
                )
                return Result(
                    code=403,
                    target=handler.data["group_name"],
                    username=handler.username,
                )

            group = session.get(UserGroup, handler.data["group_name"])
            if not group:
                handler.conclude_request(
                    code=404, message="Group does not exist", data={}
                )
                return Result(
                    code=404,
                    target=handler.data["group_name"],
                    username=handler.username,
                )

            response = {
                "code": 200,
                "message": "Group info retrieved successfully",
                "data": {
                    "name": group.group_name,
                    "display_name": group.group_display_name,
                    "permissions": list(group.all_permissions),
                    "members": list(group.members),
                },
            }

            handler.conclude_request(**response)
            return Result(
                code=0, target=handler.data["group_name"], username=handler.username
            )


class RequestChangeGroupPermissionsHandler(RequestHandler):
    request_model = _ChangeGroupPermissionsRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if not handler.data["group_name"]:
                handler.conclude_request(
                    code=400, message="Group name is required", data={}
                )
                return

            if Permissions.SET_GROUP_PERMISSIONS not in user.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to set group permissions",
                    data={},
                )
                return Result(
                    code=403,
                    target=handler.data["group_name"],
                    username=handler.username,
                )

            group = session.get(UserGroup, handler.data["group_name"])
            if not group:
                handler.conclude_request(
                    code=404, message="Group does not exist", data={}
                )
                return Result(
                    code=404,
                    target=handler.data["group_name"],
                    username=handler.username,
                )

            new_permissions = handler.data.get("permissions", [])

            # Check if all elements in new_permissions are of type str
            if not all(isinstance(permission, str) for permission in new_permissions):
                handler.conclude_request(
                    code=400, message="All permissions must be of type str", data={}
                )
                return

            # Avoid unnecessary DB work.
            if set(new_permissions) != group.all_permissions:
                group.all_permissions = new_permissions
                session.commit()

        response = {
            "code": 200,
            "message": "Group permissions set successfully",
            "data": {},
        }

        handler.conclude_request(**response)
        return Result(
            code=0, target=handler.data["group_name"], username=handler.username
        )
