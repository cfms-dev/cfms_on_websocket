__all__ = [
    "RequestBlockUserHandler",
    "RequestChangeUserGroupsHandler",
    "RequestChangeUserPermissionsHandler",
    "RequestCreateUserHandler",
    "RequestDeleteUserHandler",
    "RequestGetUserAvatarHandler",
    "RequestGetUserInfoHandler",
    "RequestListUserBlocksHandler",
    "RequestListUsersHandler",
    "RequestManageUserStatusHandler",
    "RequestRenameUserHandler",
    "RequestSetPasswdHandler",
    "RequestSetUserAvatarHandler",
    "RequestUnblockUserHandler",
    "RequestUpdateUserBlockHandler",
]

import time
from typing import Annotated, Literal, Self

import filetype
from pydantic import Field, model_validator
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import selectinload

from include.config.constants import AVAILABLE_BLOCK_TYPES
from include.config.settings import global_config
from include.database.models.access import (
    UserBlockEntry,
    UserBlockSubEntry,
)
from include.database.models.documents import Document
from include.database.models.files import TransferMode
from include.database.models.identity import (
    User,
    UserGroup,
    UserStatus,
)
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.documents.handlers.documents import create_file_task
from include.domains.identity.commands.users import create_user
from include.domains.identity.password_auth import verify_password_or_dummy
from include.domains.identity.permission_entries import serialize_permission_entries
from include.domains.identity.request_models import (
    OffsetPaginationRequest,
    PermissionEntry,
)
from include.domains.identity.types import RequestUsername
from include.domains.identity.validators.passwords import (
    InvalidPasswordLengthError,
    RuleRequirementsNotMetError,
    check_passwd_requirements,
)
from include.domains.operations.comments import (
    CommentStore,
    OperationReason,
    reason_change_audit_data,
)
from include.domains.pagination import (
    CursorError,
    PaginationCursor,
    PaginationCursorToken,
    PaginationPageSize,
    get_offset_pagination,
    get_page_size,
    make_cursor_response,
)
from include.domains.security.guards.login import AuthFactor, LoginGuard
from include.messages import Messages as smsg
from include.transport.client_address import get_client_ip
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import (
    REQUEST_UNSET,
    Omittable,
    RequestDataModel,
    RequestHandler,
    Result,
)
from include.types import NonEmptyString, NonNegativeFloat


class _TimedGroup(RequestDataModel):
    group_name: str
    start_time: float
    end_time: Omittable[float] = REQUEST_UNSET


class _CreateUserRequest(RequestDataModel):
    username: RequestUsername
    password: str
    nickname: Omittable[str] = REQUEST_UNSET
    permissions: Omittable[list[PermissionEntry]] = REQUEST_UNSET
    groups: Omittable[list[_TimedGroup]] = REQUEST_UNSET


class _UsernameRequest(RequestDataModel):
    username: NonEmptyString


class _RenameUserRequest(RequestDataModel):
    username: NonEmptyString
    nickname: str | None = None


class _BlockTarget(RequestDataModel):
    type: Literal["all", "directory", "document"]
    id: Omittable[NonEmptyString] = REQUEST_UNSET


class _BlockUserRequest(RequestDataModel):
    username: NonEmptyString
    target: _BlockTarget
    block_types: Annotated[list[str], Field(min_length=1)]
    not_before: Omittable[NonNegativeFloat] = REQUEST_UNSET
    not_after: Omittable[float] = REQUEST_UNSET
    reason: OperationReason | None = None


class _BlockIDRequest(RequestDataModel):
    block_id: NonEmptyString


class _UpdateUserBlockRequest(RequestDataModel):
    block_id: NonEmptyString
    reason: OperationReason | None


class _ListUserBlocksRequest(RequestDataModel):
    username: NonEmptyString
    page_size: Omittable[PaginationPageSize] = REQUEST_UNSET
    cursor: PaginationCursorToken | None = None


class _SetUserAvatarRequest(RequestDataModel):
    username: NonEmptyString
    document_id: NonEmptyString


class _ChangeUserGroupsRequest(RequestDataModel):
    username: NonEmptyString
    groups: Omittable[list[str]] = REQUEST_UNSET


class _ChangeUserPermissionsRequest(RequestDataModel):
    username: NonEmptyString
    permissions: list[PermissionEntry]


class _SetPasswordRequest(RequestDataModel):
    username: RequestUsername
    old_passwd: str | None = None
    new_passwd: NonEmptyString
    force_update_after_login: Omittable[bool] = REQUEST_UNSET
    bypass_passwd_requirements: Omittable[bool] = REQUEST_UNSET


class _ManageUserStatusRequest(RequestDataModel):
    status: Literal["active", "disabled"]
    username: NonEmptyString
    reason: Omittable[OperationReason | None] = REQUEST_UNSET

    @model_validator(mode="after")
    def reject_reason_when_activating(self) -> Self:
        if self.status == "active" and "reason" in self.model_fields_set:
            raise ValueError("reason is not allowed when activating a user")
        return self


def _serialize_user_block(entry: UserBlockEntry) -> dict:
    return {
        "block_id": entry.block_id,
        "timestamp": entry.timestamp,
        "not_before": entry.not_before,
        "not_after": entry.not_after,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "block_types": [sub_entry.block_type for sub_entry in entry.sub_entries],
        "reason": entry.reason,
    }


class RequestListUsersHandler(RequestHandler):
    request_model = OffsetPaginationRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        offset, count = get_offset_pagination(handler.data)

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            if Permissions.LIST_USERS not in this_user.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to list users",
                    data={},
                )
                return Result(code=403, username=handler.username)

            total = session.query(func.count(User.username)).scalar()
            users = (
                session.query(User)
                .order_by(User.username.asc())
                .offset(offset)
                .limit(count)
                .all()
            )
            users_data = [
                {
                    "username": user.username,
                    "nickname": user.nickname,
                    "created_time": user.created_time,
                    "last_login": user.last_login,
                    "permissions": serialize_permission_entries(user.rights),
                    "effective_permissions": sorted(user.all_permissions),
                    "effective_own_permissions": sorted(user.own_permissions),
                    "effective_inherited_permissions": sorted(
                        user.inherited_permissions
                    ),
                    "groups": list(user.all_groups),
                }
                for user in users
            ]

            handler.conclude_request(
                code=200,
                message="List of users",
                data={
                    "users": users_data,
                    "total": total,
                    "offset": offset,
                    "count": count,
                    "has_more": offset + len(users_data) < total,
                },
            )
            return Result(
                code=0,
                data={"offset": offset, "count": count},
                username=handler.username,
            )


class RequestCreateUserHandler(RequestHandler):
    request_model = _CreateUserRequest

    require_auth = True
    rate_limit_cost = 5

    def handle(self, handler: ConnectionHandler):
        data = handler.data
        new_username = data["username"]
        new_password = data["password"]
        new_nickname = data.get("nickname")
        new_user_rights = data.get("permissions", [])
        new_user_groups = data.get("groups", [])

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            # currently handle_create_user() will not judge whether the requesting
            # user is eligible to apply the given permissions for the new user.
            #
            # "create_user" is a dangerous privilege that should only be held by administrators.

            if Permissions.CREATE_USER not in this_user.all_permissions:
                handler.conclude_request(
                    403, {}, "You do not have permission to create users"
                )
                return

            user_exists = (
                session.query(User.username).filter_by(username=new_username).first()
                is not None
            )
            if user_exists:
                handler.conclude_request(400, {}, "Username already exists")
                return

            if new_user_groups:
                requested_group_names = {g["group_name"] for g in new_user_groups}
                existing_groups = (
                    session.query(UserGroup.group_name)
                    .filter(UserGroup.group_name.in_(requested_group_names))
                    .all()
                )
                existing_group_names = {row[0] for row in existing_groups}

                missing_groups = requested_group_names - existing_group_names
                if missing_groups:
                    handler.conclude_request(
                        400, {}, f"Groups do not exist: {', '.join(missing_groups)}"
                    )
                    return

            create_user(
                username=new_username,
                password=new_password,
                nickname=new_nickname,
                permissions=new_user_rights,
                groups=new_user_groups,
            )

        handler.conclude_request(200, {}, "User created successfully")
        return Result(code=0, target=new_username, username=handler.username)


class RequestDeleteUserHandler(RequestHandler):
    request_model = _UsernameRequest

    require_auth = True
    rate_limit_cost = 5

    def handle(self, handler: ConnectionHandler):

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            if Permissions.DELETE_USER not in this_user.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to delete users",
                    data={},
                )
                return

            user_to_delete_username = handler.data["username"]

            user_to_delete = session.get(User, user_to_delete_username)
            if not user_to_delete:
                handler.conclude_request(
                    code=404, message="User does not exist", data={}
                )
                return

            if user_to_delete.username == this_user.username:
                handler.conclude_request(
                    code=400, message="Cannot delete yourself", data={}
                )
                return

            # if "create_user" not in this_user.all_permissions:
            #     users_with_create_permission = session.query(User).filter(
            #         User.all_permissions.contains("create_user")
            #     ).all()

            #     if len(users_with_create_permission) <= 1:
            #         handler.conclude_request(
            #             **{
            #                 "code": 400,
            #                 "message": "There must be at least one user with 'create_user' permission",
            #                 "data": {},
            #             }
            #         )
            #         return

            for membership in user_to_delete.groups:
                session.delete(membership)

            for block_entry in user_to_delete.block_entries:
                for sub_entry in block_entry.sub_entries:
                    session.delete(sub_entry)

                session.delete(block_entry)

            session.delete(user_to_delete)
            session.commit()

        response = {
            "code": 200,
            "message": "User deleted successfully",
            "data": {},
        }

        handler.conclude_request(**response)


class RequestRenameUserHandler(RequestHandler):
    request_model = _RenameUserRequest
    rate_limit_cost = 5

    def handle(self, handler: ConnectionHandler):

        target_username: str = handler.data["username"]

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            if not this_user or not this_user.is_token_valid(handler.token):
                handler.conclude_request(
                    code=403, message="Invalid user or token", data={}
                )
                return

            permissions = this_user.all_permissions
            is_renaming_self = target_username == this_user.username

            has_permission = Permissions.SUPER_RENAME_USER in permissions or (
                is_renaming_self and Permissions.RENAME_USER in permissions
            )

            if not has_permission:
                handler.conclude_request(
                    code=403,
                    message=(
                        "You do not have permission to rename yourself"
                        if is_renaming_self
                        else "You do not have permission to rename users"
                    ),
                    data={},
                )
                return

            new_nickname = handler.data.get("nickname", None)

            user_to_rename = session.get(User, target_username)
            if not user_to_rename:
                handler.conclude_request(
                    code=400, message="User does not exist", data={}
                )
                return

            user_to_rename.nickname = new_nickname
            session.commit()

        response = {
            "code": 200,
            "message": "User renamed successfully",
            "data": {},
        }

        handler.conclude_request(**response)


class RequestBlockUserHandler(RequestHandler):
    """
    Handler for action `block_user`.

    This operation accepts only one block at a time, and if there are multiple blocks
    (NOT multiple block types), it should be requested in installments.
    """

    request_model = _BlockUserRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):

        target_username: str = handler.data["username"]
        block_types: list[str] = handler.data["block_types"]

        not_before: int | float = handler.data.get("not_before", 0)
        not_after: int | float = handler.data.get("not_after", -1)
        reason: str | None = handler.data.get("reason")

        target_type: str = handler.data["target"]["type"]
        target_id: str | None = handler.data["target"].get("id")

        if not set(block_types).issubset(AVAILABLE_BLOCK_TYPES):
            handler.conclude_request(400, {}, "Unsupported block type(s)")
            return Result(code=400, target=target_username)

        if not_after >= 0 and not_after <= not_before:
            handler.conclude_request(
                400, {}, "`not_after` must be later than `not_before`"
            )
            return Result(code=400, target=target_username)

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            if Permissions.BLOCK not in this_user.all_permissions:
                handler.conclude_request(
                    403, {}, "You do not have permission to block users"
                )
                return Result(
                    code=403, target=target_username, username=handler.username
                )

            # Create the parent entry.
            now = time.time()
            block_entry = UserBlockEntry(
                username=target_username,
                timestamp=now,
                not_before=not_before,
                not_after=not_after,
                target_type=target_type,
                target_id=target_id,
                reason_comment_id=(
                    CommentStore.get_or_create_id(session, reason)
                    if reason is not None
                    else None
                ),
            )
            session.add(block_entry)

            for each_type in block_types:
                new_sub_entry = UserBlockSubEntry(
                    block_type=each_type, parent_entry=block_entry
                )
                session.add(new_sub_entry)

            session.flush()
            response_data = _serialize_user_block(block_entry)
            session.commit()

        handler.conclude_request(200, response_data, "User blocked")
        return Result(
            code=200,
            target=target_username,
            data={
                "block_id": response_data["block_id"],
                **reason_change_audit_data(None, response_data["reason"]),
            },
            username=handler.username,
        )


class RequestUnblockUserHandler(RequestHandler):
    """
    Handler for action `unblock_user`.
    """

    request_model = _BlockIDRequest

    require_auth = True
    rate_limit_cost = 2

    def handle(self, handler: ConnectionHandler):

        block_id: str = handler.data["block_id"]

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            if not this_user or not this_user.is_token_valid(handler.token):
                handler.conclude_request(401, {}, "Invalid user or token")
                return Result(code=401, target=block_id)

            if Permissions.UNBLOCK not in this_user.all_permissions:
                handler.conclude_request(
                    403, {}, "You do not have permission to unblock users"
                )
                return Result(code=403, target=block_id, username=handler.username)

            block_entry = session.get(UserBlockEntry, block_id)
            if not block_entry:
                handler.conclude_request(404, {}, "Specified entry not found")
                return Result(code=404, target=block_id, username=handler.username)

            if 0 <= block_entry.not_after < time.time():
                handler.conclude_request(400, {}, "The specified block has ended")
                return Result(code=400, target=block_id, username=handler.username)

            # Currently, the operation of unblocking is to remove entries from
            # the database. However, an alternative approach is to set their
            # expiration time to the present.
            session.delete(block_entry)
            session.commit()

        handler.conclude_request(200, {}, "Unblocked user")
        return Result(code=200, target=block_id, username=handler.username)


class RequestUpdateUserBlockHandler(RequestHandler):
    request_model = _UpdateUserBlockRequest
    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        block_id: str = handler.data["block_id"]
        reason: str | None = handler.data["reason"]

        with Session() as session:
            this_user = User.get_existing(session, handler.username)
            if Permissions.BLOCK not in this_user.all_permissions:
                handler.conclude_request(
                    403, {}, "You do not have permission to update user blocks"
                )
                return Result(code=403, target=block_id, username=handler.username)

            block_entry = session.get(
                UserBlockEntry,
                block_id,
                options=(selectinload(UserBlockEntry.sub_entries),),
            )
            if block_entry is None:
                handler.conclude_request(404, {}, "Specified entry not found")
                return Result(code=404, target=block_id, username=handler.username)

            previous_reason = block_entry.reason
            if previous_reason != reason:
                block_entry.reason_comment_id = (
                    CommentStore.get_or_create_id(session, reason)
                    if reason is not None
                    else None
                )
            session.flush()
            response_data = {
                **_serialize_user_block(block_entry),
                "reason": reason,
            }
            target_username = block_entry.username
            session.commit()

        handler.conclude_request(200, response_data, "User block updated")
        return Result(
            code=200,
            target=block_id,
            data={
                "username": target_username,
                **reason_change_audit_data(previous_reason, reason),
            },
            username=handler.username,
        )


class RequestListUserBlocksHandler(RequestHandler):
    request_model = _ListUserBlocksRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):

        target_username: str = handler.data["username"]
        page_size = get_page_size(handler.data)
        cursor = handler.data.get("cursor")

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            if not this_user or not this_user.is_token_valid(handler.token):
                handler.conclude_request(401, {}, "Invalid user or token")
                return Result(code=401, target=target_username)

            if (
                Permissions.LIST_USER_BLOCKS not in this_user.all_permissions
                and target_username != this_user.username
            ):
                handler.conclude_request(
                    403, {}, "You do not have permission to list user blocks"
                )
                return Result(
                    code=403, target=target_username, username=handler.username
                )

            filters = {"username": target_username}
            sort = "timestamp_block_id:desc"
            try:
                decoded_cursor = PaginationCursor.decode(
                    cursor,
                    action="list_user_blocks",
                    sort=sort,
                    filters=filters,
                    value_types=[(int, float), str],
                )
                last_key = None if decoded_cursor is None else decoded_cursor.last
            except CursorError as exc:
                handler.conclude_request(400, {}, str(exc))
                return Result(
                    code=400, target=target_username, username=handler.username
                )

            block_query = (
                session.query(UserBlockEntry)
                .options(
                    selectinload(UserBlockEntry.sub_entries),
                    selectinload(UserBlockEntry.reason_comment),
                )
                .filter(UserBlockEntry.username == target_username)
            )
            if last_key is not None:
                last_timestamp, last_block_id = last_key
                block_query = block_query.filter(
                    or_(
                        UserBlockEntry.timestamp < last_timestamp,
                        and_(
                            UserBlockEntry.timestamp == last_timestamp,
                            UserBlockEntry.block_id < last_block_id,
                        ),
                    )
                )

            block_entries = (
                block_query.order_by(
                    UserBlockEntry.timestamp.desc(), UserBlockEntry.block_id.desc()
                )
                .limit(page_size + 1)
                .all()
            )

            blocks_data = [_serialize_user_block(entry) for entry in block_entries]

            response_data = make_cursor_response(
                blocks_data,
                page_size=page_size,
                action="list_user_blocks",
                sort=sort,
                filters=filters,
                cursor_key=lambda item: [item["timestamp"], item["block_id"]],
            )

        handler.conclude_request(200, response_data, "List of user blocks")
        return Result(code=200, target=target_username, username=handler.username)


class RequestGetUserInfoHandler(RequestHandler):
    request_model = _UsernameRequest

    require_auth = True
    rate_limit_cost = 2

    def handle(self, handler: ConnectionHandler):
        user_to_get_username = handler.data["username"]

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            if (
                user_to_get_username != this_user.username
                and Permissions.GET_USER_INFO not in this_user.all_permissions
            ):
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to get user information",
                    data={},
                )
                return

            user_to_get = session.get(User, user_to_get_username)
            if not user_to_get:
                handler.conclude_request(
                    code=404, message="User does not exist", data={}
                )
                return

            user_info = {
                "nickname": user_to_get.nickname,
                "username": user_to_get.username,
                "status": UserStatus(user_to_get.status).value,
                "permissions": serialize_permission_entries(user_to_get.rights),
                "effective_permissions": sorted(user_to_get.all_permissions),
                "effective_own_permissions": sorted(user_to_get.own_permissions),
                "effective_inherited_permissions": sorted(
                    user_to_get.inherited_permissions
                ),
                "groups": list(user_to_get.all_groups),
                "last_login": user_to_get.last_login,
                "created_time": user_to_get.created_time,
                "passwd_last_modified": user_to_get.passwd_last_modified,
            }

            handler.conclude_request(code=200, message="OK", data=user_info)


class RequestGetUserAvatarHandler(RequestHandler):
    """
    Handler for action `get_user_avatar`.

    This operation retrieves the avatar file ID of a specified user.
    However, when a user successfully authenticates themselves, their avatar ID is
    already included in the response.
    """

    request_model = _UsernameRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        user_to_get_username = handler.data["username"]
        if not user_to_get_username:
            handler.conclude_request(code=400, message="Username is required", data={})
            return

        with Session() as session:
            # when require_auth is True, user authentication has been verified
            this_user = User.get_existing(session, handler.username)

            if (
                user_to_get_username != this_user.username
                and Permissions.GET_USER_INFO not in this_user.all_permissions
            ):
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to get user information",
                    data={},
                )
                return

            user_to_get = session.get(User, user_to_get_username)
            if not user_to_get:
                handler.conclude_request(
                    code=404, message="User does not exist", data={}
                )
                return

            avatar = user_to_get.avatar

            if avatar:
                avatar_task_data = create_file_task(
                    session, avatar, TransferMode.DOWNLOAD
                )
                session.commit()
                handler.conclude_request(
                    200, {"task_data": avatar_task_data}, smsg.SUCCESS
                )
            else:
                handler.conclude_request(404, {}, smsg.TARGET_NOT_FOUND)


class RequestSetUserAvatarHandler(RequestHandler):
    """
    Handler for action `set_user_avatar`.

    This operation sets the user's avatar to the latest revision of a specified document.

    Note: The document itself is not required to be an image file, but its latest revision
    must be an image file. Additionally, if the access permissions of the document originally
    designated as the avatar are changed later, the avatar setting will not be lost.
    """

    request_model = _SetUserAvatarRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        target_username: str = handler.data["username"]
        document_id: str | None = handler.data["document_id"]

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            permissions = this_user.all_permissions
            is_setting_own_avatar = target_username == this_user.username

            has_permission = Permissions.SUPER_SET_USER_AVATAR in permissions or (
                is_setting_own_avatar and Permissions.SET_USER_AVATAR in permissions
            )

            if not has_permission:
                handler.conclude_request(
                    code=403,
                    data={},
                    message=(
                        "You do not have permission to set your avatar"
                        if is_setting_own_avatar
                        else "You do not have permission to set another user's avatar"
                    ),
                )
                return Result(
                    code=403,
                    target=target_username,
                    username=handler.username,
                )

            user_to_update = session.get(User, target_username)
            if not user_to_update:
                handler.conclude_request(404, {}, "User does not exist")
                return

            # judge whether the user has the right to use the document as avatar
            document = session.get(Document, document_id)
            if not document:
                handler.conclude_request(404, {}, "Document does not exist")
                return

            if not document.check_access_requirements(user_to_update, "read"):
                handler.conclude_request(
                    403, {}, "User does not have access to the specified document"
                )
                return

            latest_rev_file = document.get_latest_revision().file
            # check whether the file is an image
            extension = filetype.guess_extension(latest_rev_file.path)
            if extension not in ["jpg", "jpeg", "png", "gif", "bmp", "webp"]:
                handler.conclude_request(
                    400, {}, "The specified document is not an image file"
                )
                return

            user_to_update.avatar_id = latest_rev_file.id
            session.commit()

        handler.conclude_request(200, {}, "User avatar updated successfully")
        return Result(code=200, target=target_username, username=handler.username)


class RequestChangeUserGroupsHandler(RequestHandler):
    request_model = _ChangeUserGroupsRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            if Permissions.CHANGE_USER_GROUPS not in this_user.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to change user groups",
                    data={},
                )
                return

            user_to_change_username = handler.data["username"]
            if not user_to_change_username:
                handler.conclude_request(
                    code=400, message="Username is required", data={}
                )
                return

            user_to_change = session.get(User, user_to_change_username)
            if not user_to_change:
                handler.conclude_request(
                    code=404, message="User does not exist", data={}
                )
                return

            new_user_groups: list[str] = handler.data.get("groups", [])

            if set(new_user_groups) != user_to_change.all_groups:
                user_to_change.all_groups = new_user_groups
                session.commit()

        response = {
            "code": 200,
            "message": "User groups changed successfully",
            "data": {},
        }

        handler.conclude_request(**response)


class RequestChangeUserPermissionsHandler(RequestHandler):
    request_model = _ChangeUserPermissionsRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            if Permissions.SET_USER_PERMISSIONS not in this_user.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to set user permissions",
                    data={},
                )
                return Result(
                    code=403, target=handler.data["username"], username=handler.username
                )

            target_username = handler.data["username"]
            if not target_username:
                handler.conclude_request(
                    code=400, message="Username is required", data={}
                )
                return

            user_to_change = session.get(User, target_username)
            if not user_to_change:
                handler.conclude_request(
                    code=404, message="User does not exist", data={}
                )
                return Result(
                    code=404, target=target_username, username=handler.username
                )

            new_permissions = handler.data.get("permissions", [])
            user_to_change.own_permissions = new_permissions
            session.commit()

        response = {
            "code": 200,
            "message": "User permissions set successfully",
            "data": {},
        }

        handler.conclude_request(**response)
        return Result(
            code=0, target=handler.data["username"], username=handler.username
        )


class RequestSetPasswdHandler(RequestHandler):
    request_model = _SetPasswordRequest
    rate_limit_cost = 10

    def handle(self, handler: ConnectionHandler):
        target_username: str = handler.data["username"]
        old_passwd: str | None = handler.data.get("old_passwd")
        new_passwd: str = handler.data["new_passwd"]
        operator_username = handler.username
        bypass_passwd_requirements: bool = handler.data.get(
            "bypass_passwd_requirements", False
        )
        force_update_after_login: bool = handler.data.get(
            "force_update_after_login", False
        )
        ip: str | None = None

        def respond(
            code: int,
            message: str,
            data: dict | None = None,
            *,
            username: str | None = None,
        ) -> Result:
            handler.conclude_request(code=code, data=data or {}, message=message)
            return Result(code=code, target=target_username, username=username)

        if old_passwd is not None:
            ip = get_client_ip(handler.stream.connection._ws)
            decision = LoginGuard.evaluate(ip, target_username, AuthFactor.PASSWORD)
            if not decision.allowed:
                data = {}
                if decision.retry_after_seconds is not None:
                    data["retry_after_seconds"] = decision.retry_after_seconds
                return respond(
                    429,
                    "Too many authentication attempts. Please try again later.",
                    data,
                )

        with Session() as session:
            operator_user = None
            if operator_username:
                if not handler.token:
                    return respond(400, "Given an operator, token is required")

                operator_user = session.get(User, operator_username)
                if not operator_user or not operator_user.is_token_valid(handler.token):
                    return respond(401, "Invalid user or token")

            if old_passwd is not None:
                user = session.get(User, target_username)
                if not verify_password_or_dummy(user, old_passwd):
                    assert ip is not None
                    LoginGuard.report_failure(ip, target_username, AuthFactor.PASSWORD)
                    return respond(401, "Invalid credentials")

                assert user is not None
                assert ip is not None
                LoginGuard.report_success(
                    ip,
                    target_username,
                    AuthFactor.PASSWORD,
                    completed_authentication=True,
                )
                actor_username = target_username

                flags_set = []
                if bypass_passwd_requirements:
                    flags_set.append("bypass_passwd_requirements")
                if force_update_after_login:
                    flags_set.append("force_update_after_login")

                if flags_set:
                    return respond(
                        400,
                        "The following options cannot be set to True when "
                        "changing your own password: " + ", ".join(flags_set),
                        {flag: True for flag in flags_set},
                        username=actor_username,
                    )
                if user.status != UserStatus.ACTIVE:
                    return respond(
                        403, "Account is not active", username=actor_username
                    )

                if not (
                    {Permissions.SET_PASSWD, Permissions.SUPER_SET_PASSWD}
                    & user.all_permissions
                ):
                    return respond(
                        403,
                        "You do not have permission to change your own password",
                        username=actor_username,
                    )
            else:
                if not operator_user:
                    return respond(
                        400, "Operator is required when setting other user password"
                    )
                if Permissions.SUPER_SET_PASSWD not in operator_user.all_permissions:
                    return respond(
                        403,
                        "You do not have permission to set user password",
                        username=operator_username,
                    )

                actor_username = operator_username
                user = session.get(User, target_username)
                if user is None:
                    return respond(404, "User does not exist", username=actor_username)

            try:
                if not bypass_passwd_requirements:
                    check_passwd_requirements(
                        new_passwd,
                        global_config["security"]["passwd_min_length"],
                        global_config["security"]["passwd_max_length"],
                        global_config["security"]["passwd_rules"],
                        global_config["security"]["passwd_min_passed_count"],
                    )
            except InvalidPasswordLengthError as e:
                return respond(
                    400,
                    str(e),
                    {"min_length": e.min_length, "max_length": e.max_length},
                    username=actor_username,
                )
            except RuleRequirementsNotMetError as e:
                return respond(
                    400,
                    str(e),
                    {
                        "passed_count": e.passed_count,
                        "min_passed_count": e.min_passed_count,
                        "unpassed_rules": tuple(e.unpassed_rules),
                    },
                    username=actor_username,
                )

            if user.verify_password(new_passwd):
                return respond(
                    400,
                    "New password should not be the same",
                    username=actor_username,
                )

            user.set_password(
                new_passwd, force_update_after_login=force_update_after_login
            )
            session.commit()

        return respond(200, "Password set successfully", username=actor_username)


class RequestManageUserStatusHandler(RequestHandler):
    request_model = _ManageUserStatusRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        new_status: str = handler.data["status"]
        username: str = handler.data["username"]
        reason: str | None = handler.data.get("reason")
        reason_provided = "reason" in handler.data

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            if Permissions.MANAGE_USER_STATUS not in this_user.all_permissions:
                handler.conclude_request(
                    403, {}, "You do not have permission to manage user status"
                )
                return Result(code=403, target=None, username=handler.username)

            mapping = {
                "active": UserStatus.ACTIVE,
                "disabled": UserStatus.DISABLED,
            }

            if username == handler.username:
                handler.conclude_request(
                    400, {}, "Cannot change your own account status"
                )
                return Result(code=400, target=username, username=handler.username)

            user = session.get(User, username)
            if not user:
                handler.conclude_request(404, {}, "User does not exist")
                return Result(code=404, target=None, username=handler.username)

            previous_reason = user.status_reason
            status_changed = user.status != mapping[new_status]
            if status_changed:
                user.status = mapping[new_status]
                user.status_comment_id = (
                    CommentStore.get_or_create_id(session, reason)
                    if new_status == "disabled" and reason is not None
                    else None
                )
            elif new_status == "disabled" and reason_provided:
                if previous_reason != reason:
                    user.status_comment_id = (
                        CommentStore.get_or_create_id(session, reason)
                        if reason is not None
                        else None
                    )

            current_reason = (
                reason
                if new_status == "disabled" and (status_changed or reason_provided)
                else previous_reason
                if new_status == "disabled"
                else None
            )
            session.commit()

        response_data = {
            "username": username,
            "status": new_status,
            "reason": current_reason,
        }
        handler.conclude_request(200, response_data, "User status updated successfully")
        return Result(
            code=200,
            target=username,
            data={
                "status": new_status,
                **reason_change_audit_data(previous_reason, response_data["reason"]),
            },
            username=handler.username,
        )
