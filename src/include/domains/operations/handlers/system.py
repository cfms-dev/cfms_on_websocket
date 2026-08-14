from typing import Self

from pydantic import model_validator
from sqlalchemy import and_, desc, or_, true

from include.database.models.identity import User
from include.database.models.operations import AuditEntry
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.operations.comments import reason_change_audit_data
from include.domains.operations.lockdown import LockdownReason, apply_lockdown
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


class _LockdownRequest(RequestDataModel):
    status: bool
    reason: Omittable[LockdownReason | None] = REQUEST_UNSET

    @model_validator(mode="after")
    def reject_reason_when_disabling(self) -> Self:
        if not self.status and "reason" in self.model_fields_set:
            raise ValueError("reason is not allowed when disabling lockdown")
        return self


class _ViewAuditLogsRequest(RequestDataModel):
    page_size: Omittable[PaginationPageSize] = REQUEST_UNSET
    cursor: PaginationCursorToken | None = None
    filters: Omittable[list[str]] = REQUEST_UNSET


class RequestLockdownHandler(RequestHandler):
    request_model = _LockdownRequest

    require_auth = True
    rate_limit_cost = 10

    def handle(self, handler: ConnectionHandler):
        status_to_change: bool = handler.data["status"]
        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.APPLY_LOCKDOWN not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return Result(code=403, target=None, username=handler.username)

        transition = (
            apply_lockdown(status_to_change, handler.data["reason"])
            if "reason" in handler.data
            else apply_lockdown(status_to_change)
        )

        response_data = transition.state.as_response_data()
        handler.conclude_request(200, response_data, smsg.SUCCESS)
        return Result(
            code=0,
            target=None,
            data={
                **response_data,
                **reason_change_audit_data(
                    transition.previous_state.reason,
                    transition.state.reason,
                ),
            },
            username=handler.username,
        )


class RequestViewAuditLogsHandler(RequestHandler):
    request_model = _ViewAuditLogsRequest
    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        page_size = get_page_size(handler.data)
        cursor = handler.data.get("cursor")
        filtered_actions: list[str] = handler.data.get("filters", [])
        filters = {"filters": sorted(filtered_actions)}
        sort = "logged_time_id:desc"
        try:
            decoded_cursor = PaginationCursor.decode(
                cursor,
                action="view_audit_logs",
                sort=sort,
                filters=filters,
                ttl=3600,
                value_types=[(int, float), str],
            )
            last_key = None if decoded_cursor is None else decoded_cursor.last
        except CursorError as exc:
            handler.conclude_request(400, {}, str(exc))
            return Result(code=400, target=None, username=handler.username)

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.VIEW_AUDIT_LOGS not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return Result(code=403, target=None, username=handler.username)

            audit_query = session.query(AuditEntry).filter(
                AuditEntry.action.in_(filtered_actions) if filtered_actions else true()
            )
            if last_key is not None:
                last_logged_time, last_id = last_key
                audit_query = audit_query.filter(
                    or_(
                        AuditEntry.logged_time < last_logged_time,
                        and_(
                            AuditEntry.logged_time == last_logged_time,
                            AuditEntry.id < last_id,
                        ),
                    )
                )

            queried_entries = (
                audit_query.order_by(desc(AuditEntry.logged_time), desc(AuditEntry.id))
                .limit(page_size + 1)
                .all()
            )

            result = [
                {
                    "id": entry.id,
                    "action": entry.action,
                    "username": entry.username,
                    "target": entry.target,
                    "data": entry.data,
                    "result": entry.result,
                    "remote_address": entry.remote_address,
                    "logged_time": entry.logged_time,
                }
                for entry in queried_entries
            ]
            response_data = make_cursor_response(
                result,
                page_size=page_size,
                action="view_audit_logs",
                sort=sort,
                filters=filters,
                cursor_key=lambda item: [item["logged_time"], item["id"]],
            )

        handler.conclude_request(200, response_data, smsg.SUCCESS)
        return Result(
            code=0,
            target=None,
            data={"page_size": page_size},
            username=handler.username,
        )
