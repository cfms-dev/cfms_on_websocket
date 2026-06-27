__all__ = [
    "RequestListGroupsHandler",
    # ...
]

from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.identity.commands.groups import create_group
from include.domains.identity.models import (
    User,
    UserGroup,
    UserGroupPermission,
    UserMembership,
)
from include.domains.operations.messages import Messages as smsg
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler


class RequestListGroupsHandler(RequestHandler):
    schema = {"type": "object", "additionalProperties": False}

    require_auth = True

    def handle(self, handler: ConnectionHandler):

        with Session() as session:
            user = User.get_existing(session, handler.username)  # 执行操作的用户

            if Permissions.LIST_GROUPS not in user.all_permissions:
                handler.conclude_request(
                    **{
                        "code": 403,
                        "message": "You do not have permission to list groups",
                        "data": {},
                    }
                )
                return

            groups = session.query(UserGroup).all()
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
                    ]
                },
            }

            handler.conclude_request(**response)


class RequestCreateGroupHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "group_name": {"type": "string", "minLength": 1},
            "display_name": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "permissions": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "permission": {"type": "string"},
                        "start_time": {"type": "number"},
                        "end_time": {"type": "number"},
                    },
                    "required": ["permission", "start_time"],
                    "additionalProperties": False,
                },
            },
        },
        "required": ["group_name"],
        "additionalProperties": False,
    }

    require_auth = True

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
                return 403, new_group_name, handler.username

            if session.get(UserGroup, new_group_name):
                handler.conclude_request(400, {}, smsg.GROUP_ALREADY_EXISTS)
                return

            create_group(
                group_name=new_group_name,
                display_name=new_display_name,
                permissions=new_group_permissions,
            )

        handler.conclude_request(200, {}, "Group created successfully")
        return 0, new_group_name, handler.username


class RequestDeleteGroupHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "group_name": {"type": "string", "minLength": 1},
        },
        "required": ["group_name"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            if Permissions.DELETE_GROUP not in this_user.all_permissions:
                handler.conclude_request(
                    **{
                        "code": 403,
                        "message": "You do not have permission to delete groups",
                        "data": {},
                    }
                )
                return 403, handler.data["group_name"], handler.username

            group_to_delete_name: str = handler.data["group_name"]
            group_to_delete = session.get(UserGroup, group_to_delete_name)

            if not group_to_delete:
                handler.conclude_request(
                    **{
                        "code": 404,
                        "message": "Group does not exist",
                        "data": {},
                    }
                )
                return 404, group_to_delete_name, handler.username

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
        return 0, handler.data["group_name"], handler.username


class RequestRenameGroupHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "group_name": {"type": "string", "minLength": 1},
            "display_name": {"anyOf": [{"type": "string"}, {"type": "null"}]},
        },
        "required": ["group_name", "display_name"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):

        target_group_name: str = handler.data["group_name"]

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            if Permissions.RENAME_GROUP not in this_user.all_permissions:
                handler.conclude_request(
                    **{
                        "code": 403,
                        "message": "You do not have permission to rename groups",
                        "data": {},
                    }
                )
                return 403, target_group_name, handler.username

            new_display_name: str | None = handler.data.get("display_name", None)
            if type(new_display_name) not in (str, None):
                handler.conclude_request(
                    **{
                        "code": 400,
                        "message": "display_name must be null or a string",
                        "data": {},
                    }
                )
                return

            group_to_rename = session.get(UserGroup, target_group_name)
            if not group_to_rename:
                handler.conclude_request(
                    **{
                        "code": 400,
                        "message": "Group does not exist",
                        "data": {},
                    }
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
        return 0, target_group_name, handler.username


class RequestGetGroupInfoHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "group_name": {"type": "string", "minLength": 1},
        },
        "required": ["group_name"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):

        with Session() as session:
            user = User.get_existing(session, handler.username)  # 执行操作的用户

            if not handler.data["group_name"]:
                handler.conclude_request(
                    **{
                        "code": 400,
                        "message": "Group name is required",
                        "data": {},
                    }
                )
                return

            if Permissions.GET_GROUP_INFO not in user.all_permissions:
                handler.conclude_request(
                    **{
                        "code": 403,
                        "message": "You do not have permission to view group info",
                        "data": {},
                    }
                )
                return 403, handler.data["group_name"], handler.username

            group = session.get(UserGroup, handler.data["group_name"])
            if not group:
                handler.conclude_request(
                    **{
                        "code": 404,
                        "message": "Group does not exist",
                        "data": {},
                    }
                )
                return 404, handler.data["group_name"], handler.username

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
            return 0, handler.data["group_name"], handler.username


class RequestChangeGroupPermissionsHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "group_name": {"type": "string", "minLength": 1},
            "permissions": {
                "type": "array",
                "items": {
                    "type": "string",
                    "additionalProperties": False,
                },
            },
        },
        "required": ["group_name", "permissions"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if not handler.data["group_name"]:
                handler.conclude_request(
                    **{
                        "code": 400,
                        "message": "Group name is required",
                        "data": {},
                    }
                )
                return

            if Permissions.SET_GROUP_PERMISSIONS not in user.all_permissions:
                handler.conclude_request(
                    **{
                        "code": 403,
                        "message": "You do not have permission to set group permissions",
                        "data": {},
                    }
                )
                return 403, handler.data["group_name"], handler.username

            group = session.get(UserGroup, handler.data["group_name"])
            if not group:
                handler.conclude_request(
                    **{
                        "code": 404,
                        "message": "Group does not exist",
                        "data": {},
                    }
                )
                return 404, handler.data["group_name"], handler.username

            new_permissions = handler.data.get("permissions", [])

            # Check if all elements in new_permissions are of type str
            if not all(isinstance(permission, str) for permission in new_permissions):
                handler.conclude_request(
                    **{
                        "code": 400,
                        "message": "All permissions must be of type str",
                        "data": {},
                    }
                )
                return

            if set(new_permissions) != group.all_permissions:  # 预判断，减少数据库开销
                group.all_permissions = new_permissions
                session.commit()

        response = {
            "code": 200,
            "message": "Group permissions set successfully",
            "data": {},
        }

        handler.conclude_request(**response)
        return 0, handler.data["group_name"], handler.username
