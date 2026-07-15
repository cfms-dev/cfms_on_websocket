import time

import orjson
from sqlalchemy import and_, desc, or_, true, update

from include.database.models.files import FileTask
from include.database.models.identity import User
from include.database.models.operations import AuditEntry
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.operations.lockdown import lockdown_state_manager
from include.domains.pagination import (
    CURSOR_PAGINATION_SCHEMA,
    CursorError,
    PaginationCursor,
    get_page_size,
    make_cursor_response,
)
from include.messages import Messages as smsg
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler, Result


class RequestLockdownHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "status": {"type": "boolean"},
            "reason": {"type": "string", "minLength": 1, "maxLength": 1024},
        },
        "required": ["status"],
        "additionalProperties": False,
        "allOf": [
            {
                "if": {
                    "properties": {"status": {"const": False}},
                    "required": ["status"],
                },
                "then": {"not": {"required": ["reason"]}},
            }
        ],
    }

    require_auth = True

    def handle(self, handler: ConnectionHandler):
        status_to_change: bool = handler.data["status"]
        reason: str | None = handler.data.get("reason")

        with Session() as session:
            user = User.get_existing(session, handler.username)

            if Permissions.APPLY_LOCKDOWN not in user.all_permissions:
                handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
                return Result(code=403, target=None, username=handler.username)

            if status_to_change:
                lockdown_state = lockdown_state_manager.enable(reason)

                # cancel all pending file tasks to prevent new file
                # operations during lockdown.
                now = time.time()
                stmt = (
                    update(FileTask)
                    .where(FileTask.status == 0, FileTask.end_time >= now)
                    .values(status=2)
                )
                session.execute(stmt)
                session.commit()
            else:
                lockdown_state = lockdown_state_manager.disable()

        response_data = lockdown_state.as_response_data()
        handler.conclude_request(200, response_data, smsg.SUCCESS)
        handler.broadcast(
            orjson.dumps(
                {
                    "event": "lockdown",
                    "data": response_data,
                }
            )
        )
        return Result(code=0, target=None, username=handler.username)


class RequestViewAuditLogsHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            **CURSOR_PAGINATION_SCHEMA,
            "filters": {"type": "array", "items": {"type": "string"}},
        },
        "required": [],
        "additionalProperties": False,
    }
    require_auth = True

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
