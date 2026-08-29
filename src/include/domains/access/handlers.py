__all__ = ["RequestGrantAccessHandler", "RequestRevokeAccessHandler"]

from typing import Annotated, Literal

from pydantic import Field

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
from include.domains.pagination import (
    CursorError,
    PaginationCursor,
    PaginationCursorToken,
    PaginationPageSize,
    get_page_size,
    make_cursor_response,
)
from include.messages import Messages as smsg
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import (
    REQUEST_UNSET,
    Omittable,
    RequestDataModel,
    RequestHandler,
    Result,
)
from include.types import JsonInteger, NonEmptyString, NonNegativeFloat

ENTITY_TYPE_MAPPING = {"user": User, "group": UserGroup}
TARGET_TYPE_MAPPING = {"document": Document, "directory": Folder}


class _GrantAccessRequest(RequestDataModel):
    entity_type: Literal["user", "group"]
    entity_identifier: NonEmptyString
    target_type: Literal["document", "directory"]
    target_identifier: NonEmptyString
    access_types: list[str]
    start_time: NonNegativeFloat
    end_time: Omittable[NonNegativeFloat] = REQUEST_UNSET


class _ViewAccessEntriesRequest(RequestDataModel):
    object_type: Literal["user", "group", "document", "directory"]
    object_identifier: NonEmptyString
    page_size: Omittable[PaginationPageSize] = REQUEST_UNSET
    cursor: PaginationCursorToken | None = None


class _RevokeAccessRequest(RequestDataModel):
    entry_id: Annotated[JsonInteger, Field(ge=1)]


class RequestGrantAccessHandler(RequestHandler):
    request_model = _GrantAccessRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):

        entity_type: str = handler.data["entity_type"]
        entity_identifier: str = handler.data["entity_identifier"]

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
                    code=400, target=None, data=handler.data, username=handler.username
                )

            operator = User.get_existing(session, handler.username)

            if Permissions.MANAGE_ACCESS not in operator.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_MANAGE_ACCESS)
                return Result(code=403, target=handler.username)

            entity: User | UserGroup | None = session.get(
                ENTITY_TYPE_MAPPING[entity_type], entity_identifier
            )
            if not entity:
                handler.conclude_request(404, {}, smsg.ENTITY_NOT_FOUND)
                return Result(
                    code=404, target=None, data=handler.data, username=handler.username
                )

            target: Document | Folder | None = session.get(
                TARGET_TYPE_MAPPING[target_type], target_identifier
            )
            if not target:
                handler.conclude_request(404, {}, smsg.TARGET_NOT_FOUND)
                return Result(
                    code=404, target=None, data=handler.data, username=handler.username
                )

            for access_type in access_types:
                if not check_access_requirements(
                    session, operator, target, access_type
                ):
                    handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                    return Result(
                        code=403,
                        target=None,
                        data=handler.data,
                        username=handler.username,
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
        return Result(
            code=200, target=None, data=handler.data, username=handler.username
        )


class RequestViewAccessEntriesHandler(RequestHandler):
    request_model = _ViewAccessEntriesRequest

    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        object_type: str = handler.data["object_type"]
        object_identifier: str = handler.data["object_identifier"]
        page_size = get_page_size(handler.data)
        cursor = handler.data.get("cursor")

        with Session() as session:
            operator = User.get_existing(session, handler.username)

            if Permissions.VIEW_ACCESS_ENTRIES not in operator.all_permissions:
                handler.conclude_request(
                    code=403,
                    message="You do not have permission to view access entries",
                    data={},
                )
                return Result(code=403, target=handler.username)

            filters = {
                "object_type": object_type,
                "object_identifier": object_identifier,
            }
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
                return Result(code=400, target=handler.username)

            if object_type in ["user", "group"]:
                access_query = session.query(ObjectAccessEntry).filter(
                    ObjectAccessEntry.entity_type == object_type,
                    ObjectAccessEntry.entity_identifier == object_identifier,
                )
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
            target=None,
            data={
                "object_type": object_type,
                "object_identifier": object_identifier,
            },
            username=handler.username,
        )


class RequestRevokeAccessHandler(RequestHandler):
    request_model = _RevokeAccessRequest

    require_auth = True
    rate_limit_cost = 2

    def handle(self, handler: ConnectionHandler):
        entry_id: int = handler.data["entry_id"]

        with Session() as session:
            operator = User.get_existing(session, handler.username)

            if Permissions.MANAGE_ACCESS not in operator.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED_MANAGE_ACCESS)
                return Result(code=403, target=None, username=handler.username)

            # Get the access entry
            entry = session.get(ObjectAccessEntry, entry_id)
            if not entry:
                handler.conclude_request(404, {}, smsg.ACCESS_ENTRY_NOT_FOUND)
                return Result(
                    code=404, target=None, data=handler.data, username=handler.username
                )

            # Delete the entry
            session.delete(entry)
            session.commit()

        handler.conclude_request(200, {}, smsg.SUCCESS)
        return Result(
            code=200, target=None, data=handler.data, username=handler.username
        )
