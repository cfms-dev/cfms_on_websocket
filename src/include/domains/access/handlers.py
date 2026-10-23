__all__ = ["RequestGrantAccessHandler", "RequestRevokeAccessHandler"]

import uuid
from typing import Annotated, Literal, Self

from pydantic import Field, TypeAdapter, model_validator
from sqlalchemy import false

from include.database.models.access import ObjectAccessEntry
from include.database.models.documents import (
    Document,
    Folder,
)
from include.database.models.identity import (
    User,
    UserGroup,
)
from include.database.session import Session
from include.domains.access.authorization.evaluation import check_access_requirements
from include.domains.access.permissions import Permissions
from include.domains.identity.types import RequestUserID
from include.domains.pagination import (
    CursorError,
    PaginationCursor,
    PaginationCursorToken,
    PaginationPageSize,
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
lazy from include.transport.connection import ConnectionHandler
lazy from include.types import JsonInteger, NonEmptyString, NonNegativeFloat

TARGET_TYPE_MAPPING = {"document": Document, "directory": Folder}
_user_id_adapter = TypeAdapter(RequestUserID)


class _GrantAccessRequest(RequestDataModel):
    entity_type: Literal["user", "group"]
    entity_identifier: NonEmptyString
    target_type: Literal["document", "directory"]
    target_identifier: NonEmptyString
    access_types: list[str]
    start_time: NonNegativeFloat
    end_time: Omittable[NonNegativeFloat] = REQUEST_UNSET

    @model_validator(mode="after")
    def validate_user_identifier(self) -> Self:
        if self.entity_type == "user":
            _user_id_adapter.validate_python(self.entity_identifier)
        return self


class _ViewAccessEntriesRequest(RequestDataModel):
    object_type: Literal["user", "group", "document", "directory"]
    object_identifier: NonEmptyString
    page_size: Omittable[PaginationPageSize] = REQUEST_UNSET
    cursor: PaginationCursorToken | None = None

    @model_validator(mode="after")
    def validate_user_identifier(self) -> Self:
        if self.object_type == "user":
            _user_id_adapter.validate_python(self.object_identifier)
        return self


class _RevokeAccessRequest(RequestDataModel):
    entry_id: Annotated[JsonInteger, Field(ge=1)]


class RequestGrantAccessHandler(RequestHandler[_GrantAccessRequest]):
    request_model = _GrantAccessRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):

        entity_type: str = handler.data["entity_type"]
        entity_identifier: str = handler.data["entity_identifier"]
        if entity_type == "user":
            entity_identifier = str(uuid.UUID(entity_identifier))

        audit_data = {**handler.data, "entity_identifier": entity_identifier}

        target_type: str = handler.data["target_type"]
        target_identifier: str = handler.data["target_identifier"]

        access_types: list[str] = handler.data["access_types"]
        start_time: float = handler.data["start_time"]
        end_time: float | None = handler.data.get("end_time")

        with Session() as session:
            if end_time and not start_time <= end_time:
                handler.conclude_request(
                    400, {}, "The start time should be before the end time"
                )
                return Result(
                    code=400, target=None, data=audit_data, user_id=handler.user_id
                )

            operator = User.get_existing(session, handler.user_id)

            if Permissions.MANAGE_ACCESS not in operator.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_MANAGE_ACCESS)
                return Result(code=403, target=None, user_id=operator.id)

            entity: User | UserGroup | None = (
                session.get(User, uuid.UUID(entity_identifier))
                if entity_type == "user"
                else session.get(UserGroup, entity_identifier)
            )
            if not entity:
                handler.conclude_request(404, {}, smsg.ENTITY_NOT_FOUND)
                return Result(
                    code=404, target=None, data=audit_data, user_id=handler.user_id
                )

            target: Document | Folder | None = session.get(
                TARGET_TYPE_MAPPING[target_type], target_identifier
            )
            if not target:
                handler.conclude_request(404, {}, smsg.TARGET_NOT_FOUND)
                return Result(
                    code=404, target=None, data=audit_data, user_id=handler.user_id
                )

            for access_type in access_types:
                if not check_access_requirements(
                    session, operator, target, access_type
                ):
                    handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                    return Result(
                        code=403,
                        target=None,
                        data=audit_data,
                        user_id=handler.user_id,
                    )

                new = ObjectAccessEntry(
                    entity_type=entity_type,
                    entity_identifier=entity_identifier,
                    target_type=target_type,
                    target_identifier=target_identifier,
                    access_type=access_type,
                    start_time=start_time,
                    end_time=end_time,
                )
                session.add(new)

            session.commit()

        handler.conclude_request(200, {}, smsg.SUCCESS)
        return Result(code=200, target=None, data=audit_data, user_id=handler.user_id)


class RequestViewAccessEntriesHandler(RequestHandler[_ViewAccessEntriesRequest]):
    request_model = _ViewAccessEntriesRequest

    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        object_type: str = handler.data["object_type"]
        object_identifier: str = handler.data["object_identifier"]
        if object_type == "user":
            object_identifier = str(uuid.UUID(object_identifier))
        audit_target = object_identifier if object_type == "user" else None
        page_size = get_page_size(handler.data)
        cursor = handler.data.get("cursor")

        with Session() as session:
            operator = User.get_existing(session, handler.user_id)

            if Permissions.VIEW_ACCESS_ENTRIES not in operator.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to view access entries",
                    data={},
                )
                return Result(code=403, target=audit_target, user_id=operator.id)

            filters = {
                "object_type": object_type,
                "object_identifier": object_identifier,
            }
            audit_data = filters.copy()
            target_user = None
            if object_type == "user":
                target_user = session.get(User, uuid.UUID(object_identifier))
                if target_user is not None:
                    audit_data["target_username"] = target_user.username
            sort = "id:asc"
            try:
                decoded_cursor = PaginationCursor.decode(
                    cursor,
                    action="view_access_entries",
                    sort=sort,
                    filters=filters,
                    value_types=[int],
                )
                last_key = None if decoded_cursor is None else decoded_cursor.last
            except CursorError as exc:
                handler.conclude_request(400, {}, str(exc))
                return Result(code=400, target=audit_target, user_id=operator.id)

            if object_type in ["user", "group"]:
                access_query = session.query(ObjectAccessEntry).filter(
                    ObjectAccessEntry.entity_type == object_type,
                    ObjectAccessEntry.entity_identifier == object_identifier,
                )
                if object_type == "user" and target_user is None:
                    access_query = access_query.filter(false())
            else:
                access_query = session.query(ObjectAccessEntry).filter(
                    ObjectAccessEntry.target_type == object_type,
                    ObjectAccessEntry.target_identifier == object_identifier,
                )

            if last_key is not None:
                access_query = access_query.filter(ObjectAccessEntry.id > last_key[0])

            _query_result = (
                access_query.order_by(ObjectAccessEntry.id.asc())
                .limit(page_size + 1)
                .all()
            )

            result = [
                {
                    "id": each.id,
                    "entity_type": each.entity_type,
                    "entity_identifier": each.entity_identifier,
                    "target_type": each.target_type,
                    "target_identifier": each.target_identifier,
                    "access_type": each.access_type,
                    "start_time": each.start_time,
                    "end_time": each.end_time,
                }
                for each in _query_result
            ]
            response_data = make_cursor_response(
                result,
                page_size=page_size,
                action="view_access_entries",
                sort=sort,
                filters=filters,
                cursor_key=lambda item: [item["id"]],
            )

        handler.conclude_request(200, response_data, smsg.SUCCESS)
        return Result(
            code=200,
            target=audit_target,
            data=audit_data,
            user_id=handler.user_id,
        )


class RequestRevokeAccessHandler(RequestHandler[_RevokeAccessRequest]):
    request_model = _RevokeAccessRequest

    requires_auth = True
    rate_limit_cost = 2

    def handle(self, handler: ConnectionHandler):
        entry_id: int = handler.data["entry_id"]

        with Session() as session:
            operator = User.get_existing(session, handler.user_id)

            if Permissions.MANAGE_ACCESS not in operator.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_MANAGE_ACCESS)
                return Result(code=403, target=None, user_id=handler.user_id)

            # Get the access entry
            entry = session.get(ObjectAccessEntry, entry_id)
            if not entry:
                handler.conclude_request(404, {}, smsg.ACCESS_ENTRY_NOT_FOUND)
                return Result(
                    code=404, target=None, data=handler.data, user_id=handler.user_id
                )

            # Delete the entry
            session.delete(entry)
            session.commit()

        handler.conclude_request(200, {}, smsg.SUCCESS)
        return Result(code=200, target=None, data=handler.data, user_id=handler.user_id)
