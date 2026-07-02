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
    "RequestUploadUserKeyHandler",
    "RequestGetUserKeyHandler",
    "RequestDeleteUserKeyHandler",
    "RequestSetPreferenceDEKHandler",
    "RequestListUserKeysHandler",
]

import time

from include.database.models.identity import User
from include.database.models.keyrings import UserKey
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.pagination import OFFSET_PAGINATION_SCHEMA, get_offset_pagination
from include.messages import Messages as smsg
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler, Result


class RequestUploadUserKeyHandler(RequestHandler):
    """
    Upload a new key into the user's keyring.

    The caller must be authenticated. The key is bound to the authenticated user
    unless the caller has ``manage_keyrings`` permission and explicitly passes a
    ``target_username``.

    Request data:
        content  (str, required)  - The key material / encrypted DEK.
        label        (str, optional)  - Human-readable label.
        target_username (str, opt.)   - Admin-only: operate on another user.

    Response codes:
        200 - Key uploaded successfully; ``key_id`` is returned in data.
        403 - Permission denied.
        404 - User does not exist (admin path only).
    """

    schema = {
        "type": "object",
        "properties": {
            "content": {"type": "string", "minLength": 1, "maxLength": 512},
            "label": {"type": "string"},
            "target_username": {"type": "string", "minLength": 1},
        },
        "required": ["content"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        key_content: str = handler.data["content"]
        label: str | None = handler.data.get("label")
        target_username: str | None = handler.data.get("target_username")

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            # Determine which user's keyring to write to
            if target_username and target_username != handler.username:
                if Permissions.MANAGE_KEYRINGS not in this_user.all_permissions:
                    handler.conclude_request(403, {}, smsg.PERMISSION_DENIED)
                    return Result(
                        code=403, target=target_username, username=handler.username
                    )
                owner = session.get(User, target_username)
                if not owner:
                    handler.conclude_request(404, {}, smsg.USER_DOES_NOT_EXIST)
                    return Result(
                        code=404, target=target_username, username=handler.username
                    )
            else:
                target_username = handler.username
                owner = this_user

            key = UserKey(
                username=target_username,
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
            return Result(code=200, target=target_username, username=handler.username)


class RequestGetUserKeyHandler(RequestHandler):
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

    schema = {
        "type": "object",
        "properties": {
            "id": {"type": "string", "minLength": 1},
        },
        "required": ["id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        key_id: str = handler.data["id"]

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            key = session.get(UserKey, key_id)
            if not key:
                handler.conclude_request(404, {}, smsg.KEY_NOT_FOUND)
                return Result(code=404, target=key_id, username=handler.username)

            # Authorisation: the key must belong to the requesting user, or the
            # user must have admin-level manage_keyrings permission.
            if key.username != handler.username:
                if Permissions.MANAGE_KEYRINGS not in this_user.all_permissions:
                    handler.conclude_request(403, {}, smsg.PERMISSION_DENIED)
                    return Result(code=403, target=key_id, username=handler.username)

            handler.conclude_request(
                200,
                {
                    "key_id": key.id,
                    "username": key.username,
                    "label": key.label,
                    "key_content": key.content,
                    "created_time": key.created_time,
                },
                "Key retrieved successfully",
            )
            return Result(code=200, target=key_id, username=handler.username)


class RequestDeleteUserKeyHandler(RequestHandler):
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

    schema = {
        "type": "object",
        "properties": {
            "id": {"type": "string", "minLength": 1},
        },
        "required": ["id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        key_id: str = handler.data["id"]

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            key = session.get(UserKey, key_id)
            if not key:
                handler.conclude_request(404, {}, smsg.KEY_NOT_FOUND)
                return Result(code=404, target=key_id, username=handler.username)

            if key.username != handler.username:
                if Permissions.MANAGE_KEYRINGS not in this_user.all_permissions:
                    handler.conclude_request(403, {}, smsg.PERMISSION_DENIED)
                    return Result(code=403, target=key_id, username=handler.username)

            # If this key is set as the owner's preference DEK, clear it before deletion
            owner_user = session.get(User, key.username)
            if owner_user is not None:
                # Prefer checking by id to avoid unnecessary loading of relations
                preference_dek_id = getattr(owner_user, "preference_dek_id", None)
                if preference_dek_id == key_id:
                    owner_user.preference_dek = None
            session.delete(key)
            session.commit()

            handler.conclude_request(200, {}, "Key deleted successfully")
            return Result(code=200, target=key_id, username=handler.username)


class RequestSetPreferenceDEKHandler(RequestHandler):
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

    schema = {
        "type": "object",
        "properties": {
            "id": {"type": "string", "minLength": 1},
        },
        "required": ["id"],
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        key_id: str = handler.data["id"]

        with Session() as session:
            this_user = User.get_existing(session, handler.username)

            key = session.get(UserKey, key_id)
            if not key:
                handler.conclude_request(404, {}, smsg.KEY_NOT_FOUND)
                return Result(code=404, target=key_id, username=handler.username)

            if key.username != handler.username:
                if Permissions.MANAGE_KEYRINGS not in this_user.all_permissions:
                    handler.conclude_request(403, {}, smsg.PERMISSION_DENIED)
                    return Result(code=403, target=key_id, username=handler.username)

            key_owner = User.get_existing(session, key.username)
            key_owner.preference_dek = key
            session.add(key)
            session.commit()

            handler.conclude_request(200, {}, "Preference DEK updated successfully")
            return Result(code=200, target=key_id, username=handler.username)


class RequestListUserKeysHandler(RequestHandler):
    """
    List all keys in the authenticated user's keyring (metadata only, no key_content).

    The authenticated user sees only their own keys unless they hold
    ``manage_keyrings`` permission and pass ``target_username``.

    Request data:
        target_username (str, optional) - Admin-only: list another user's keys.

    Response codes:
        200 - List returned in ``data.keys``.
        403 - Permission denied.
        404 - User does not exist (admin path only).
    """

    schema = {
        "type": "object",
        "properties": {
            "target_username": {"type": "string", "minLength": 1},
            **OFFSET_PAGINATION_SCHEMA,
        },
        "additionalProperties": False,
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        target_username: str = handler.data.get("target_username") or handler.username
        offset, count = get_offset_pagination(handler.data)

        with Session() as session:
            target_user = session.get(User, target_username)
            operator = User.get_existing(session, handler.username)

            if target_username != handler.username:
                if Permissions.MANAGE_KEYRINGS not in operator.all_permissions:
                    handler.conclude_request(403, {}, smsg.PERMISSION_DENIED)
                    return Result(
                        code=403, target=target_username, username=handler.username
                    )

            if not target_user:
                handler.conclude_request(404, {}, smsg.USER_DOES_NOT_EXIST)
                return Result(
                    code=404, target=target_username, username=handler.username
                )

            keys_query = session.query(UserKey).filter(
                UserKey.username == target_username
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
            return Result(code=200, target=target_username, username=handler.username)
