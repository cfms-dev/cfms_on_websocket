"""
Keyring handlers for CFMS.

These handlers allow authenticated users to upload, query, and delete their own
encryption keys. A key marked as *preference* is returned in the login response
so that any compliant client can retrieve the configuration-encryption DEK
without needing to know the key identifier in advance.

Security constraints enforced by these handlers:
- A user may only access and manage their own keys.
- Admins with the ``manage_keyrings`` permission may manage any user's keys.
- At most one key per user may be marked *preference*; uploading a new
  preference key automatically demotes the previous one.
"""

__all__ = [
    "RequestDeleteUserKeyHandler",
    "RequestGetUserKeyHandler",
    "RequestListUserKeysHandler",
    "RequestSetPreferenceDEKHandler",
    "RequestUploadUserKeyHandler",
]

import time
import uuid
from typing import Annotated

from pydantic import StringConstraints

from include.database.models.identity import User
from include.database.models.keyrings import UserKey
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.pagination import (
    PaginationOffset,
    PaginationPageSize,
    get_offset_pagination,
)
from include.messages import Messages as smsg
from include.transport.request_handler import (
    REQUEST_UNSET,
    Omittable,
    RequestDataModel,
    RequestHandler,
    Result,
)
lazy from include.domains.identity.types import RequestUserID
lazy from include.transport.connection import ConnectionHandler
lazy from include.types import NonEmptyString

_KeyContent = Annotated[str, StringConstraints(min_length=1, max_length=512)]


class _UploadUserKeyRequest(RequestDataModel):
    content: _KeyContent
    label: Omittable[str] = REQUEST_UNSET
    user_id: Omittable[RequestUserID] = REQUEST_UNSET


class _KeyIDRequest(RequestDataModel):
    id: NonEmptyString


class _ListUserKeysRequest(RequestDataModel):
    user_id: Omittable[RequestUserID] = REQUEST_UNSET
    offset: Omittable[PaginationOffset] = REQUEST_UNSET
    count: Omittable[PaginationPageSize] = REQUEST_UNSET


class RequestUploadUserKeyHandler(RequestHandler[_UploadUserKeyRequest]):
    """
    Upload a new key into the user's keyring.

    The caller must be authenticated. The key is bound to the authenticated user
    unless the caller has ``manage_keyrings`` permission and explicitly passes a
    ``user_id``.

    Request data:
        content  (str, required)  - The key material / encrypted DEK.
        label        (str, optional)  - Human-readable label.
        user_id (UUID string, opt.)   - Admin-only: operate on another user.

    Response codes:
        200 - Key uploaded successfully; ``key_id`` is returned in data.
        403 - Permission denied.
        404 - User does not exist (admin path only).
    """

    request_model = _UploadUserKeyRequest

    requires_auth = True
    rate_limit_cost = 2

    def handle(self, handler: ConnectionHandler):
        key_content: str = handler.data["content"]
        label: str | None = handler.data.get("label")
        target_user_id = (
            uuid.UUID(handler.data["user_id"])
            if "user_id" in handler.data
            else handler.user_id
        )

        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            # Determine which user's keyring to write to
            if target_user_id != this_user.id:
                if Permissions.MANAGE_KEYRINGS not in this_user.all_permissions:
                    handler.conclude_request(403, {}, smsg.PERMISSION_DENIED)
                    return Result(
                        code=403, target=str(target_user_id), user_id=handler.user_id
                    )
                owner = session.get(User, target_user_id)
                if not owner:
                    handler.conclude_request(404, {}, smsg.USER_DOES_NOT_EXIST)
                    return Result(
                        code=404, target=str(target_user_id), user_id=handler.user_id
                    )
            else:
                owner = this_user

            target_username = owner.username
            key = UserKey(
                user_id=owner.id,
                content=key_content,
                label=label,
                created_time=time.time(),
            )
            session.add(key)
            session.commit()

            handler.conclude_request(
                200,
                {"id": key.id},
                "Key uploaded successfully",
            )
            return Result(
                code=200,
                target=str(target_user_id),
                data={"target_username": target_username},
                user_id=handler.user_id,
            )


class RequestGetUserKeyHandler(RequestHandler[_KeyIDRequest]):
    """
    Retrieve a single key from the keyring by its ``key_id``.

    The authenticated user may retrieve only their own keys unless they hold
    ``manage_keyrings`` permission.

    Request data:
        id          (str, required) - The key identifier to retrieve.

    Response codes:
        200 - Key found; key details returned in data.
        403 - Permission denied.
        404 - Key not found.
    """

    request_model = _KeyIDRequest

    requires_auth = True
    rate_limit_cost = 1

    def handle(self, handler: ConnectionHandler):
        key_id: str = handler.data["id"]

        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            key = session.get(UserKey, key_id)
            if not key:
                handler.conclude_request(404, {}, smsg.KEY_NOT_FOUND)
                return Result(code=404, target=key_id, user_id=handler.user_id)

            # Authorisation: the key must belong to the requesting user, or the
            # user must have admin-level manage_keyrings permission.
            if (
                key.user_id != handler.user_id
                and Permissions.MANAGE_KEYRINGS not in this_user.all_permissions
            ):
                handler.conclude_request(403, {}, smsg.PERMISSION_DENIED)
                return Result(code=403, target=key_id, user_id=handler.user_id)

            audit_data = {"target_user_id": str(key.user_id)}
            handler.conclude_request(
                200,
                {
                    "key_id": key.id,
                    "user_id": str(key.user_id),
                    "label": key.label,
                    "key_content": key.content,
                    "created_time": key.created_time,
                },
                "Key retrieved successfully",
            )
            return Result(
                code=200, target=key_id, data=audit_data, user_id=handler.user_id
            )


class RequestDeleteUserKeyHandler(RequestHandler[_KeyIDRequest]):
    """
    Delete a key from the keyring by its ``key_id``.

    The authenticated user may delete only their own keys unless they hold
    ``manage_keyrings`` permission.

    Request data:
        id          (str, required) - The key identifier to delete.

    Response codes:
        200 - Key deleted successfully.
        403 - Permission denied.
        404 - Key not found.
    """

    request_model = _KeyIDRequest

    requires_auth = True
    rate_limit_cost = 2

    def handle(self, handler: ConnectionHandler):
        key_id: str = handler.data["id"]

        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            key = session.get(UserKey, key_id)
            if not key:
                handler.conclude_request(404, {}, smsg.KEY_NOT_FOUND)
                return Result(code=404, target=key_id, user_id=handler.user_id)

            if (
                key.user_id != handler.user_id
                and Permissions.MANAGE_KEYRINGS not in this_user.all_permissions
            ):
                handler.conclude_request(403, {}, smsg.PERMISSION_DENIED)
                return Result(code=403, target=key_id, user_id=handler.user_id)

            audit_data = {"target_user_id": str(key.user_id)}
            # If this key is set as the owner's preference DEK, clear it before deletion
            owner_user = session.get(User, key.user_id)
            if owner_user is not None:
                # Prefer checking by id to avoid unnecessary loading of relations
                preference_dek_id = getattr(owner_user, "preference_dek_id", None)
                if preference_dek_id == key_id:
                    owner_user.preference_dek = None
            session.delete(key)
            session.commit()

            handler.conclude_request(200, {}, "Key deleted successfully")
            return Result(
                code=200, target=key_id, data=audit_data, user_id=handler.user_id
            )


class RequestSetPreferenceDEKHandler(RequestHandler[_KeyIDRequest]):
    """
    Designate a key as the preference data encryption key for the user.

    The preference DEK will be returned in the login response so clients can
    retrieve the config DEK transparently. At most one key per user is primary;
    calling this endpoint demotes any previously primary key.

    Request data:
        id          (str, required) - The key identifier to mark primary.

    Response codes:
        200 - Primary key updated.
        403 - Permission denied.
        404 - Key not found.
    """

    request_model = _KeyIDRequest

    requires_auth = True
    rate_limit_cost = 2

    def handle(self, handler: ConnectionHandler):
        key_id: str = handler.data["id"]

        with Session() as session:
            this_user = User.get_existing(session, handler.user_id)

            key = session.get(UserKey, key_id)
            if not key:
                handler.conclude_request(404, {}, smsg.KEY_NOT_FOUND)
                return Result(code=404, target=key_id, user_id=handler.user_id)

            if (
                key.user_id != handler.user_id
                and Permissions.MANAGE_KEYRINGS not in this_user.all_permissions
            ):
                handler.conclude_request(403, {}, smsg.PERMISSION_DENIED)
                return Result(code=403, target=key_id, user_id=handler.user_id)

            audit_data = {"target_user_id": str(key.user_id)}
            key_owner = User.get_existing(session, key.user_id)
            key_owner.preference_dek = key
            session.add(key)
            session.commit()

            handler.conclude_request(200, {}, "Preference DEK updated successfully")
            return Result(
                code=200, target=key_id, data=audit_data, user_id=handler.user_id
            )


class RequestListUserKeysHandler(RequestHandler[_ListUserKeysRequest]):
    """
    List all keys in the authenticated user's keyring (metadata only, no key_content).

    The authenticated user sees only their own keys unless they hold
    ``manage_keyrings`` permission and pass ``user_id``.

    Request data:
        user_id (UUID string, optional) - Admin-only: list another user's keys.

    Response codes:
        200 - List returned in ``data.keys``.
        403 - Permission denied.
        404 - User does not exist (admin path only).
    """

    request_model = _ListUserKeysRequest

    requires_auth = True
    rate_limit_cost = 2

    def handle(self, handler: ConnectionHandler):
        target_user_id = (
            uuid.UUID(handler.data["user_id"])
            if "user_id" in handler.data
            else handler.user_id
        )
        offset, count = get_offset_pagination(handler.data)

        with Session() as session:
            operator = User.get_existing(session, handler.user_id)

            if (
                target_user_id != operator.id
                and Permissions.MANAGE_KEYRINGS not in operator.all_permissions
            ):
                handler.conclude_request(403, {}, smsg.PERMISSION_DENIED)
                return Result(
                    code=403, target=str(target_user_id), user_id=handler.user_id
                )

            target_user = session.get(User, target_user_id)
            if not target_user:
                handler.conclude_request(404, {}, smsg.USER_DOES_NOT_EXIST)
                return Result(
                    code=404, target=str(target_user_id), user_id=handler.user_id
                )

            keys_query = session.query(UserKey).filter(
                UserKey.user_id == target_user.id
            )
            total = keys_query.count()
            keys = (
                keys_query.order_by(UserKey.created_time.desc(), UserKey.id.asc())
                .offset(offset)
                .limit(count)
                .all()
            )

            handler.conclude_request(
                200,
                {
                    "keys": [
                        {
                            "id": k.id,
                            "label": k.label,
                            "is_preference_dek": target_user.preference_dek_id == k.id,
                            "created_time": k.created_time,
                        }
                        for k in keys
                    ],
                    "total": total,
                    "offset": offset,
                    "count": count,
                    "has_more": offset + len(keys) < total,
                },
                "Keyring listed successfully",
            )
            return Result(
                code=200,
                target=str(target_user_id),
                data={"target_username": target_user.username},
                user_id=handler.user_id,
            )
