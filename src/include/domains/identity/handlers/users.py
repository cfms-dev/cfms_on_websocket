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
from sqlalchemy import and_, func, or_, select
from sqlalchemy.orm import selectinload

from include.config.constants import AVAILABLE_BLOCK_TYPES
from include.config.settings import global_config
from include.database.models.access import (
    UserBlockEntry,
    UserBlockSubEntry,
)
from include.database.models.auth import UserPasswordCredential
from include.database.models.documents import Document
from include.database.models.files import TransferMode
from include.database.models.identity import (
    User,
    UserGroup,
    UserStatus,
)
from include.database.session import Session
from include.domains.access.authorization.evaluation import check_access_requirements
from include.domains.access.permissions import Permissions
from include.domains.documents.handlers.documents import create_file_task
from include.domains.identity.auth.flows import get_login_progress
from include.domains.identity.auth.password_state import password_change_requirement
from include.domains.identity.auth.types import InvalidAuthenticationAttempt
from include.domains.identity.commands.credentials import set_password
from include.domains.identity.commands.users import create_user
from include.domains.identity.permission_entries import serialize_permission_entries
from include.domains.identity.request_models import (
    OffsetPaginationRequest,
    PermissionEntry,
)
from include.domains.identity.tokens import TokenPurpose
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
from include.messages import Messages as smsg
from include.transport.request_handler import (
    REQUEST_UNSET,
    Omittable,
    RequestDataModel,
    RequestHandler,
    Result,
)
lazy from include.domains.identity.types import RequestUserID, RequestUsername
lazy from include.types import NonEmptyString, NonNegativeFloat


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


class _UserIDRequest(RequestDataModel):
    user_id: RequestUserID


class _GetUserInfoRequest(RequestDataModel):
    username: Omittable[NonEmptyString] = REQUEST_UNSET
    user_id: Omittable[RequestUserID] = REQUEST_UNSET

    @model_validator(mode="after")
    def require_one_selector(self) -> Self:
        if len({"username", "user_id"} & self.model_fields_set) != 1:
            raise ValueError("Provide exactly one of username or user_id")
        return self


class _RenameUserRequest(_UserIDRequest):
    nickname: str | None = None


class _BlockTarget(RequestDataModel):
    type: Literal["all", "directory", "document"]
    id: Omittable[NonEmptyString] = REQUEST_UNSET


class _BlockUserRequest(_UserIDRequest):
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


class _ListUserBlocksRequest(_UserIDRequest):
    page_size: Omittable[PaginationPageSize] = REQUEST_UNSET
    cursor: PaginationCursorToken | None = None


class _SetUserAvatarRequest(_UserIDRequest):
    document_id: NonEmptyString


class _ChangeUserGroupsRequest(_UserIDRequest):
    groups: Omittable[list[str]] = REQUEST_UNSET


class _ChangeUserPermissionsRequest(_UserIDRequest):
    permissions: list[PermissionEntry]


class _SetPasswordRequest(RequestDataModel):
    user_id: Omittable[RequestUserID] = REQUEST_UNSET
    new_passwd: NonEmptyString
    force_update_after_login: Omittable[bool] = REQUEST_UNSET
    bypass_passwd_requirements: Omittable[bool] = REQUEST_UNSET


class _ManageUserStatusRequest(_UserIDRequest):
    status: Literal["active", "disabled"]
    reason: Omittable[OperationReason | None] = REQUEST_UNSET

    @model_validator(mode="after")
    def reject_reason_when_activating(self) -> Self:
        if self.status == "active" and "reason" in self.model_fields_set:
            raise ValueError("reason is not allowed when activating a user")
        return self


def _serialize_user_block(entry: UserBlockEntry) -> dict:
    return {
        "block_id": entry.block_id,
        "user_id": str(entry.user_id),
        "timestamp": entry.timestamp,
        "not_before": entry.not_before,
        "not_after": entry.not_after,
        "target_type": entry.target_type,
        "target_id": entry.target_id,
        "block_types": [sub_entry.block_type for sub_entry in entry.sub_entries],
        "reason": entry.reason,
    }


class RequestListUsersHandler(RequestHandler[OffsetPaginationRequest]):
    request_model = OffsetPaginationRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        offset, count = get_offset_pagination(
            request.model_dump(mode="json", exclude_unset=True)
        )

        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            if Permissions.LIST_USERS not in this_user.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to list users",
                    data={},
                )
                return Result(code=403, user_id=handler.user_id)

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
                    "user_id": str(user.id),
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
                user_id=handler.user_id,
            )


class RequestCreateUserHandler(RequestHandler[_CreateUserRequest]):
    request_model = _CreateUserRequest

    requires_auth = True
    rate_limit_cost = 5

    def handle(self, handler, request):
        data = request.model_dump(mode="json", exclude_unset=True)
        new_username = data["username"]
        new_password = data["password"]
        new_nickname = data.get("nickname")
        new_user_rights = data.get("permissions", [])
        new_user_groups = data.get("groups", [])

        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

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

            new_user_id = create_user(
                username=new_username,
                password=new_password,
                nickname=new_nickname,
                permissions=new_user_rights,
                groups=new_user_groups,
            )

        handler.conclude_request(
            200,
            {"user_id": str(new_user_id), "username": new_username},
            "User created successfully",
        )
        return Result(
            code=0,
            target=str(new_user_id),
            data={"target_username": new_username},
            user_id=handler.user_id,
        )


class RequestDeleteUserHandler(RequestHandler[_UserIDRequest]):
    request_model = _UserIDRequest

    requires_auth = True
    rate_limit_cost = 5

    def handle(self, handler, request):
        target_user_id = request.user_id

        audit_data = {}
        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            if Permissions.DELETE_USER not in this_user.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to delete users",
                    data={},
                )
                return Result(
                    code=403,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

            user_to_delete = session.get(User, target_user_id)
            if not user_to_delete:
                handler.conclude_request(
                    code=404, message="User does not exist", data={}
                )
                return Result(
                    code=404,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

            audit_data["target_username"] = user_to_delete.username

            if user_to_delete.id == this_user.id:
                handler.conclude_request(
                    code=400, message="Cannot delete yourself", data={}
                )
                return Result(
                    code=400,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

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

        return Result(
            code=200,
            target=str(target_user_id),
            data=audit_data,
            user_id=handler.user_id,
        )


class RequestRenameUserHandler(RequestHandler[_RenameUserRequest]):
    request_model = _RenameUserRequest
    requires_auth = True
    rate_limit_cost = 5

    def handle(self, handler, request):

        target_user_id = request.user_id

        audit_data = {}
        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            permissions = this_user.all_permissions
            is_renaming_self = target_user_id == this_user.id

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
                return Result(
                    code=403,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

            new_nickname = request.nickname

            user_to_rename = session.get(User, target_user_id)
            if not user_to_rename:
                handler.conclude_request(
                    code=400, message="User does not exist", data={}
                )
                return Result(
                    code=400,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

            audit_data["target_username"] = user_to_rename.username

            user_to_rename.nickname = new_nickname
            session.commit()

        response = {
            "code": 200,
            "message": "User renamed successfully",
            "data": {},
        }

        handler.conclude_request(**response)

        return Result(
            code=200,
            target=str(target_user_id),
            data=audit_data,
            user_id=handler.user_id,
        )


class RequestBlockUserHandler(RequestHandler[_BlockUserRequest]):
    """
    Handler for action `block_user`.

    This operation accepts only one block at a time, and if there are multiple blocks
    (NOT multiple block types), it should be requested in installments.
    """

    request_model = _BlockUserRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):

        target_user_id = request.user_id
        block_types: list[str] = request.block_types

        not_before: int | float = (
            request.not_before if request.not_before is not REQUEST_UNSET else 0
        )
        not_after: int | float = (
            request.not_after if request.not_after is not REQUEST_UNSET else -1
        )
        reason: str | None = request.reason

        target_type: str = request.target.type
        target_id: str | None = (
            request.target.id if request.target.id is not REQUEST_UNSET else None
        )

        if not set(block_types).issubset(AVAILABLE_BLOCK_TYPES):
            handler.conclude_request(400, {}, "Unsupported block type(s)")
            return Result(code=400, target=str(target_user_id), user_id=handler.user_id)

        if not_after >= 0 and not_after <= not_before:
            handler.conclude_request(
                400, {}, "`not_after` must be later than `not_before`"
            )
            return Result(code=400, target=str(target_user_id), user_id=handler.user_id)

        audit_data = {}
        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            if Permissions.BLOCK not in this_user.all_permissions:
                handler.conclude_request(
                    403, {}, "You do not have permission to block users"
                )
                return Result(
                    code=403,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

            target_user = session.get(User, target_user_id)
            if target_user is None:
                handler.conclude_request(404, {}, smsg.USER_DOES_NOT_EXIST)
                return Result(
                    code=404,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

            audit_data["target_username"] = target_user.username

            # Create the parent entry.
            now = time.time()
            block_entry = UserBlockEntry(
                user_id=target_user.id,
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
            target=str(target_user_id),
            data={
                **audit_data,
                "block_id": response_data["block_id"],
                **reason_change_audit_data(None, response_data["reason"]),
            },
            user_id=handler.user_id,
        )


class RequestUnblockUserHandler(RequestHandler[_BlockIDRequest]):
    """
    Handler for action `unblock_user`.
    """

    request_model = _BlockIDRequest

    requires_auth = True
    rate_limit_cost = 2

    def handle(self, handler, request):

        block_id: str = request.block_id

        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            if Permissions.UNBLOCK not in this_user.all_permissions:
                handler.conclude_request(
                    403, {}, "You do not have permission to unblock users"
                )
                return Result(code=403, target=block_id, user_id=handler.user_id)

            block_entry = session.get(UserBlockEntry, block_id)
            if not block_entry:
                handler.conclude_request(404, {}, "Specified entry not found")
                return Result(code=404, target=block_id, user_id=handler.user_id)

            if 0 <= block_entry.not_after < time.time():
                handler.conclude_request(400, {}, "The specified block has ended")
                return Result(code=400, target=block_id, user_id=handler.user_id)

            # Currently, the operation of unblocking is to remove entries from
            # the database. However, an alternative approach is to set their
            # expiration time to the present.
            target_user_id = str(block_entry.user_id)
            session.delete(block_entry)
            session.commit()

        handler.conclude_request(200, {}, "Unblocked user")
        return Result(
            code=200,
            target=block_id,
            data={"target_user_id": target_user_id},
            user_id=handler.user_id,
        )


class RequestUpdateUserBlockHandler(RequestHandler[_UpdateUserBlockRequest]):
    request_model = _UpdateUserBlockRequest
    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        block_id: str = request.block_id
        reason: str | None = request.reason

        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)
            if Permissions.BLOCK not in this_user.all_permissions:
                handler.conclude_request(
                    403, {}, "You do not have permission to update user blocks"
                )
                return Result(code=403, target=block_id, user_id=handler.user_id)

            block_entry = session.get(
                UserBlockEntry,
                block_id,
                options=(selectinload(UserBlockEntry.sub_entries),),
            )
            if block_entry is None:
                handler.conclude_request(404, {}, "Specified entry not found")
                return Result(code=404, target=block_id, user_id=handler.user_id)

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
            target_username = block_entry.user.username
            target_user_id = str(block_entry.user_id)
            session.commit()

        handler.conclude_request(200, response_data, "User block updated")
        return Result(
            code=200,
            target=block_id,
            data={
                "target_username": target_username,
                "target_user_id": target_user_id,
                **reason_change_audit_data(previous_reason, reason),
            },
            user_id=handler.user_id,
        )


class RequestListUserBlocksHandler(RequestHandler[_ListUserBlocksRequest]):
    request_model = _ListUserBlocksRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):

        target_user_id = request.user_id
        page_size = get_page_size(request.model_dump(mode="json", exclude_unset=True))
        cursor = request.cursor

        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            if (
                Permissions.LIST_USER_BLOCKS not in this_user.all_permissions
                and target_user_id != this_user.id
            ):
                handler.conclude_request(
                    403, {}, "You do not have permission to list user blocks"
                )
                return Result(
                    code=403, target=str(target_user_id), user_id=handler.user_id
                )

            target_user = session.get(User, target_user_id)
            audit_data = (
                {"target_username": target_user.username} if target_user else None
            )

            filters = {"user_id": str(target_user_id)}
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
                    code=400,
                    target=str(target_user_id),
                    data=audit_data,
                    user_id=handler.user_id,
                )

            block_query = (
                session.query(UserBlockEntry)
                .options(
                    selectinload(UserBlockEntry.sub_entries),
                    selectinload(UserBlockEntry.reason_comment),
                )
                .filter(UserBlockEntry.user_id == target_user_id)
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
        return Result(
            code=200,
            target=str(target_user_id),
            data=audit_data,
            user_id=handler.user_id,
        )


class RequestGetUserInfoHandler(RequestHandler[_GetUserInfoRequest]):
    request_model = _GetUserInfoRequest

    requires_auth = True
    rate_limit_cost = 2

    def handle(self, handler, request):
        username = request.username if request.username is not REQUEST_UNSET else None
        target_user_id = (
            request.user_id if "user_id" in request.model_fields_set else None
        )

        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            if (
                not (target_user_id == this_user.id or username == this_user.username)
                and Permissions.GET_USER_INFO not in this_user.all_permissions
            ):
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to get user information",
                    data={},
                )
                return Result(
                    code=403,
                    target=str(target_user_id) if target_user_id else None,
                    user_id=handler.user_id,
                )

            user_to_get = (
                session.get(User, target_user_id)
                if target_user_id is not None
                else session.scalar(select(User).where(User.username == username))
            )
            if not user_to_get:
                handler.conclude_request(
                    code=404, message="User does not exist", data={}
                )
                return Result(
                    code=404,
                    target=str(target_user_id) if target_user_id else None,
                    user_id=handler.user_id,
                )

            password_credential = session.get(UserPasswordCredential, user_to_get.id)
            user_info = {
                "nickname": user_to_get.nickname,
                "user_id": str(user_to_get.id),
                "username": user_to_get.username,
                "status": user_to_get.status,
                "permissions": serialize_permission_entries(user_to_get.rights),
                "effective_permissions": sorted(user_to_get.all_permissions),
                "effective_own_permissions": sorted(user_to_get.own_permissions),
                "effective_inherited_permissions": sorted(
                    user_to_get.inherited_permissions
                ),
                "groups": list(user_to_get.all_groups),
                "last_login": user_to_get.last_login,
                "created_time": user_to_get.created_time,
                "passwd_last_modified": (
                    password_credential.passwd_last_modified
                    if password_credential
                    else 0.0
                ),
            }

            handler.conclude_request(code=200, message="OK", data=user_info)
            return Result(
                code=200,
                target=str(user_to_get.id),
                data={"target_username": user_to_get.username},
                user_id=handler.user_id,
            )


class RequestGetUserAvatarHandler(RequestHandler[_UserIDRequest]):
    """
    Handler for action `get_user_avatar`.

    This operation retrieves the avatar file ID of a specified user.
    However, when a user successfully authenticates themselves, their avatar ID is
    already included in the response.
    """

    request_model = _UserIDRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        target_user_id = request.user_id

        audit_data = {}
        with Session() as session:
            # when requires_auth is True, user authentication has been verified
            this_user = User.get_existing(session, handler.user_id)

            if (
                target_user_id != this_user.id
                and Permissions.GET_USER_INFO not in this_user.all_permissions
            ):
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to get user information",
                    data={},
                )
                return Result(
                    code=403,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

            user_to_get = session.get(User, target_user_id)
            if not user_to_get:
                handler.conclude_request(
                    code=404, message="User does not exist", data={}
                )
                return Result(
                    code=404,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

            audit_data["target_username"] = user_to_get.username

            avatar = user_to_get.avatar

            if avatar:
                avatar_task_data = create_file_task(
                    session, avatar, TransferMode.DOWNLOAD
                )
                session.commit()
                handler.conclude_request(
                    200, {"task_data": avatar_task_data}, smsg.SUCCESS
                )
                return Result(
                    code=200,
                    target=str(target_user_id),
                    data=audit_data,
                    user_id=handler.user_id,
                )
            else:
                handler.conclude_request(404, {}, smsg.TARGET_NOT_FOUND)
                return Result(
                    code=404,
                    target=str(target_user_id),
                    data=audit_data,
                    user_id=handler.user_id,
                )


class RequestSetUserAvatarHandler(RequestHandler[_SetUserAvatarRequest]):
    """
    Handler for action `set_user_avatar`.

    This operation sets the user's avatar to the latest revision of a specified document.

    Note: The document itself is not required to be an image file, but its latest revision
    must be an image file. Additionally, if the access permissions of the document originally
    designated as the avatar are changed later, the avatar setting will not be lost.
    """

    request_model = _SetUserAvatarRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        target_user_id = request.user_id
        document_id: str | None = request.document_id

        audit_data = {}
        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            permissions = this_user.all_permissions
            is_setting_own_avatar = target_user_id == this_user.id

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
                    target=str(target_user_id),
                    user_id=handler.user_id,
                )

            user_to_update = session.get(User, target_user_id)
            if not user_to_update:
                handler.conclude_request(404, {}, "User does not exist")
                return Result(
                    code=404,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

            audit_data["target_username"] = user_to_update.username

            # judge whether the user has the right to use the document as avatar
            document = session.get(Document, document_id)
            if not document:
                handler.conclude_request(404, {}, "Document does not exist")
                return Result(
                    code=404,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

            if not check_access_requirements(session, user_to_update, document, "read"):
                handler.conclude_request(
                    403, {}, "User does not have access to the specified document"
                )
                return Result(
                    code=403,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

            latest_rev_file = document.get_latest_revision().file
            # check whether the file is an image
            extension = filetype.guess_extension(latest_rev_file.path)
            if extension not in ["jpg", "jpeg", "png", "gif", "bmp", "webp"]:
                handler.conclude_request(
                    400, {}, "The specified document is not an image file"
                )
                return Result(
                    code=400,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

            user_to_update.avatar_id = latest_rev_file.id
            session.commit()

        handler.conclude_request(200, {}, "User avatar updated successfully")
        return Result(
            code=200,
            target=str(target_user_id),
            data=audit_data or None,
            user_id=handler.user_id,
        )


class RequestChangeUserGroupsHandler(RequestHandler[_ChangeUserGroupsRequest]):
    request_model = _ChangeUserGroupsRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        target_user_id = request.user_id

        audit_data = {}
        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            if Permissions.CHANGE_USER_GROUPS not in this_user.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to change user groups",
                    data={},
                )
                return Result(
                    code=403,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

            user_to_change = session.get(User, target_user_id)
            if not user_to_change:
                handler.conclude_request(
                    code=404, message="User does not exist", data={}
                )
                return Result(
                    code=404,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

            audit_data["target_username"] = user_to_change.username

            new_user_groups: list[str] = (
                request.groups if request.groups is not REQUEST_UNSET else []
            )

            if set(new_user_groups) != user_to_change.all_groups:
                user_to_change.all_groups = new_user_groups
                session.commit()

        response = {
            "code": 200,
            "message": "User groups changed successfully",
            "data": {},
        }

        handler.conclude_request(**response)

        return Result(
            code=200,
            target=str(target_user_id),
            data=audit_data,
            user_id=handler.user_id,
        )


class RequestChangeUserPermissionsHandler(
    RequestHandler[_ChangeUserPermissionsRequest]
):
    request_model = _ChangeUserPermissionsRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        target_user_id = request.user_id
        audit_data = {}
        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            if Permissions.SET_USER_PERMISSIONS not in this_user.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to set user permissions",
                    data={},
                )
                return Result(
                    code=403,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

            user_to_change = session.get(User, target_user_id)
            if not user_to_change:
                handler.conclude_request(
                    code=404, message="User does not exist", data={}
                )
                return Result(
                    code=404,
                    target=str(target_user_id),
                    data=audit_data or None,
                    user_id=handler.user_id,
                )

            audit_data["target_username"] = user_to_change.username

            new_permissions = [entry.model_dump() for entry in request.permissions]
            user_to_change.own_permissions = new_permissions
            session.commit()

        response = {
            "code": 200,
            "message": "User permissions set successfully",
            "data": {},
        }

        handler.conclude_request(**response)
        return Result(
            code=0,
            target=str(target_user_id),
            data=audit_data or None,
            user_id=handler.user_id,
        )


class RequestSetPasswdHandler(RequestHandler[_SetPasswordRequest]):
    request_model = _SetPasswordRequest
    rate_limit_cost = 10
    requires_auth = True
    required_token_purpose = TokenPurpose.ESCALATION | TokenPurpose.POST_AUTH

    def handle(self, handler, request):
        assert handler.token is not None

        target_user_id = (
            request.user_id if request.user_id is not REQUEST_UNSET else handler.user_id
        )
        audit_data = {}

        # Because `POST_AUTH` must be the token's sole purpose, this check is
        # sufficient.
        post_auth = handler.token.has_purpose(TokenPurpose.POST_AUTH)

        bypass_passwd_requirements = (
            request.bypass_passwd_requirements
            if request.bypass_passwd_requirements is not REQUEST_UNSET
            else False
        )
        force_update_after_login = (
            request.force_update_after_login
            if request.force_update_after_login is not REQUEST_UNSET
            else False
        )

        def respond(code: int, message: str, data: dict | None = None) -> Result:
            handler.conclude_request(code=code, data=data or {}, message=message)
            return Result(
                code=code,
                target=str(target_user_id),
                data=audit_data or None,
                user_id=handler.user_id,
            )

        if post_auth and request.model_fields_set != {"new_passwd"}:
            return respond(400, "POST_AUTH accepts only new_passwd")

        with Session() as session:
            operator = User.get_existing(session, handler.user_id)

            if not post_auth:
                permissions = operator.all_permissions
                is_super = Permissions.SUPER_CONFIGURE_AUTH_METHODS in permissions
                if not (
                    is_super
                    or (
                        target_user_id == operator.id
                        and Permissions.CONFIGURE_AUTH_METHODS in permissions
                    )
                ):
                    return respond(403, "Permission denied")

                if (
                    bypass_passwd_requirements or force_update_after_login
                ) and not is_super:
                    return respond(
                        403,
                        "Password management options require super permission",
                    )

            user = session.get(
                User, target_user_id, with_for_update=True, populate_existing=True
            )
            if user is None:
                return respond(404, "User does not exist")

            audit_data["target_username"] = user.username

            if post_auth:
                context = handler.token.auth_context
                try:
                    if (
                        context is None
                        or not get_login_progress(session, user, context).satisfied
                        or password_change_requirement(session, user, context) is None
                    ):
                        return respond(403, "Password change is not authorized")
                except InvalidAuthenticationAttempt as exc:
                    return respond(401, str(exc))

            try:
                if not bypass_passwd_requirements:
                    check_passwd_requirements(
                        request.new_passwd,
                        global_config["security"]["passwd_min_length"],
                        global_config["security"]["passwd_max_length"],
                        global_config["security"]["passwd_rules"],
                        global_config["security"]["passwd_min_passed_count"],
                    )
            except InvalidPasswordLengthError as exc:
                return respond(
                    400,
                    str(exc),
                    {"min_length": exc.min_length, "max_length": exc.max_length},
                )
            except RuleRequirementsNotMetError as exc:
                return respond(
                    400,
                    str(exc),
                    {
                        "passed_count": exc.passed_count,
                        "min_passed_count": exc.min_passed_count,
                        "unpassed_rules": tuple(exc.unpassed_rules),
                    },
                )
            credential = session.get(UserPasswordCredential, user.id)
            if credential is not None and credential.verify(request.new_passwd):
                return respond(400, "New password should not be the same")
            try:
                set_password(
                    session,
                    user,
                    request.new_passwd,
                    force_update_after_login=force_update_after_login,
                    expected_signing_key=(
                        handler.token._secret
                        if target_user_id == handler.user_id
                        else None
                    ),
                )
            except InvalidAuthenticationAttempt as exc:
                return respond(401, str(exc))
            session.commit()
        return respond(200, "Password set successfully")


class RequestManageUserStatusHandler(RequestHandler[_ManageUserStatusRequest]):
    request_model = _ManageUserStatusRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler, request):
        new_status: str = request.status
        target_user_id = request.user_id
        reason: str | None = (
            request.reason if request.reason is not REQUEST_UNSET else None
        )
        reason_provided = "reason" in request.model_fields_set

        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            if Permissions.MANAGE_USER_STATUS not in this_user.all_permissions:
                handler.conclude_request(
                    403, {}, "You do not have permission to manage user status"
                )
                return Result(
                    code=403, target=str(target_user_id), user_id=handler.user_id
                )

            mapping = {
                "active": UserStatus.ACTIVE,
                "disabled": UserStatus.DISABLED,
            }

            if target_user_id == this_user.id:
                handler.conclude_request(
                    400, {}, "Cannot change your own account status"
                )
                return Result(
                    code=400,
                    target=str(target_user_id),
                    data={"target_username": this_user.username},
                    user_id=handler.user_id,
                )

            user = session.get(User, target_user_id)
            if not user:
                handler.conclude_request(404, {}, "User does not exist")
                return Result(
                    code=404, target=str(target_user_id), user_id=handler.user_id
                )

            previous_reason = user.status_reason
            target_username = user.username
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
            "user_id": str(target_user_id),
            "username": target_username,
            "status": new_status,
            "reason": current_reason,
        }
        handler.conclude_request(200, response_data, "User status updated successfully")
        return Result(
            code=200,
            target=str(target_user_id),
            data={
                "target_username": target_username,
                "status": new_status,
                **reason_change_audit_data(previous_reason, response_data["reason"]),
            },
            user_id=handler.user_id,
        )
