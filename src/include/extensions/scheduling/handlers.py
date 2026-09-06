from typing import Annotated, Any, Literal

from pydantic import Field, StringConstraints
from sqlalchemy import and_, desc, or_, select

from include.database.models.identity import User
from include.database.models.scheduling import Schedule
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.pagination import (
    CursorError,
    PaginationCursor,
    PaginationCursorToken,
    PaginationPageSize,
    get_page_size,
    make_cursor_response,
)
from include.extensions.manager import collect_scheduled_tasks
from include.providers.manager import ProviderManager
from include.scheduling.commands import (
    ScheduleConflictError,
    ScheduleNotFoundError,
    create_schedule,
    delete_schedule,
    schedule_response,
    update_schedule,
)
from include.scheduling.triggers import TriggerValidationError
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import (
    REQUEST_UNSET,
    EmptyRequestDataModel,
    Omittable,
    RequestDataModel,
    RequestHandler,
    Result,
)
from include.types import JsonInteger

TaskName = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=3, max_length=255),
]
ScheduleId = Annotated[str, StringConstraints(min_length=1, max_length=32)]
ScheduleRevision = Annotated[JsonInteger, Field(ge=1)]


class _TriggerRequest(RequestDataModel):
    type: Literal["cron", "date", "interval"]
    data: dict[str, Any]
    timezone: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)
    ]


class _CreateScheduleRequest(RequestDataModel):
    task_name: TaskName
    payload: dict[str, Any]
    trigger: _TriggerRequest
    enabled: bool = True


class _ScheduleIdRequest(RequestDataModel):
    id: ScheduleId


class _ListSchedulesRequest(RequestDataModel):
    page_size: Omittable[PaginationPageSize] = REQUEST_UNSET
    cursor: PaginationCursorToken | None = None
    include_deleted: bool = False


class _UpdateScheduleRequest(RequestDataModel):
    id: ScheduleId
    revision: ScheduleRevision
    task_name: Omittable[TaskName] = REQUEST_UNSET
    payload: Omittable[dict[str, Any]] = REQUEST_UNSET
    trigger: Omittable[_TriggerRequest] = REQUEST_UNSET
    enabled: Omittable[bool] = REQUEST_UNSET


class _DeleteScheduleRequest(RequestDataModel):
    id: ScheduleId
    revision: ScheduleRevision


def _provider_error(handler: ConnectionHandler, username: str) -> Result | None:
    status = ProviderManager().scheduling.status()
    if status.available:
        return None
    handler.conclude_request(
        503,
        {"provider": status.mode, "status": "degraded"},
        "Scheduling provider is unavailable",
    )
    return Result(code=503, username=username)


def _permissions(username: str) -> set[Permissions]:
    with Session() as session:
        return User.get_existing(session, username).all_permissions


def _deny(handler: ConnectionHandler, username: str) -> Result:
    handler.conclude_request(403, {}, "Permission denied")
    return Result(code=403, username=username)


def _task_permission_allowed(
    permissions: set[Permissions], task_name: str, registry
) -> bool:
    registration = registry.get(task_name)
    return (
        registration is not None
        and registration.user_schedulable
        and registration.required_permission in permissions
    )


class RequestListScheduledTaskTypesHandler(RequestHandler):
    request_model = EmptyRequestDataModel
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        if error := _provider_error(handler, handler.username):
            return error
        permissions = _permissions(handler.username)
        if Permissions.VIEW_SCHEDULES not in permissions:
            return _deny(handler, handler.username)
        registry = collect_scheduled_tasks()
        items = [
            {
                "name": registration.name,
                "contract_version": registration.contract_version,
                "required_permission": registration.required_permission,
                "payload_schema": registration.payload_model.model_json_schema(),
                "max_attempts": registration.max_attempts,
            }
            for registration in registry.all()
            if registration.user_schedulable
            and registration.required_permission in permissions
        ]
        handler.conclude_request(200, {"items": items}, "Scheduled task types listed")
        return Result(code=0, data={"count": len(items)}, username=handler.username)


class RequestCreateScheduleHandler(RequestHandler):
    request_model = _CreateScheduleRequest
    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        if error := _provider_error(handler, handler.username):
            return error
        permissions = _permissions(handler.username)
        registry = collect_scheduled_tasks()
        task_name = handler.data["task_name"]
        if (
            Permissions.MANAGE_SCHEDULES not in permissions
            or not _task_permission_allowed(permissions, task_name, registry)
        ):
            return _deny(handler, handler.username)
        trigger = handler.data["trigger"]
        try:
            with Session() as session, session.begin():
                schedule = create_schedule(
                    session,
                    registry,
                    username=handler.username,
                    task_name=task_name,
                    payload=handler.data["payload"],
                    trigger_type=trigger["type"],
                    trigger_data=trigger["data"],
                    timezone=trigger["timezone"],
                    enabled=handler.data.get("enabled", True),
                )
                response = schedule_response(schedule, registry)
        except (LookupError, TriggerValidationError, ValueError) as exc:
            handler.conclude_request(400, {}, str(exc))
            return Result(code=400, username=handler.username)
        ProviderManager().scheduling.notify_schedule_change()
        handler.conclude_request(200, response, "Schedule created")
        return Result(
            code=0,
            target=response["id"],
            data={"task_name": task_name},
            username=handler.username,
        )


class RequestGetScheduleHandler(RequestHandler):
    request_model = _ScheduleIdRequest
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        if error := _provider_error(handler, handler.username):
            return error
        if Permissions.VIEW_SCHEDULES not in _permissions(handler.username):
            return _deny(handler, handler.username)
        registry = collect_scheduled_tasks()
        with Session() as session:
            schedule = session.get(Schedule, handler.data["id"])
            if (
                schedule is None
                or schedule.status == "deleted"
                or schedule.system_managed
            ):
                handler.conclude_request(404, {}, "Schedule not found")
                return Result(code=404, username=handler.username)
            response = schedule_response(schedule, registry)
        handler.conclude_request(200, response, "Schedule retrieved")
        return Result(code=0, target=response["id"], username=handler.username)


class RequestListSchedulesHandler(RequestHandler):
    request_model = _ListSchedulesRequest
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        if error := _provider_error(handler, handler.username):
            return error
        if Permissions.VIEW_SCHEDULES not in _permissions(handler.username):
            return _deny(handler, handler.username)
        page_size = get_page_size(handler.data)
        include_deleted = handler.data.get("include_deleted", False)
        filters = {"include_deleted": include_deleted}
        sort = "created_at_id:desc"
        try:
            cursor = PaginationCursor.decode(
                handler.data.get("cursor"),
                action="list_schedules",
                sort=sort,
                filters=filters,
                ttl=3600,
                value_types=[(int, float), str],
            )
        except CursorError as exc:
            handler.conclude_request(400, {}, str(exc))
            return Result(code=400, username=handler.username)

        registry = collect_scheduled_tasks()
        with Session() as session:
            query = select(Schedule).where(Schedule.system_managed.is_(False))
            if not include_deleted:
                query = query.where(Schedule.status != "deleted")
            if cursor is not None:
                created_at, schedule_id = cursor.last
                query = query.where(
                    or_(
                        Schedule.created_at < created_at,
                        and_(
                            Schedule.created_at == created_at,
                            Schedule.id < schedule_id,
                        ),
                    )
                )
            schedules = session.scalars(
                query.order_by(desc(Schedule.created_at), desc(Schedule.id)).limit(
                    page_size + 1
                )
            ).all()
            items = [schedule_response(schedule, registry) for schedule in schedules]
        response = make_cursor_response(
            items,
            page_size=page_size,
            action="list_schedules",
            sort=sort,
            filters=filters,
            cursor_key=lambda item: [item["created_at"], item["id"]],
        )
        handler.conclude_request(200, response, "Schedules listed")
        return Result(code=0, data={"page_size": page_size}, username=handler.username)


class RequestUpdateScheduleHandler(RequestHandler):
    request_model = _UpdateScheduleRequest
    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        if error := _provider_error(handler, handler.username):
            return error
        permissions = _permissions(handler.username)
        registry = collect_scheduled_tasks()
        with Session() as session:
            current = session.get(Schedule, handler.data["id"])
            if current is None or current.status == "deleted" or current.system_managed:
                handler.conclude_request(404, {}, "Schedule not found")
                return Result(code=404, username=handler.username)
            task_name = handler.data.get("task_name", current.task_name)
        if (
            Permissions.MANAGE_SCHEDULES not in permissions
            or not _task_permission_allowed(permissions, task_name, registry)
        ):
            return _deny(handler, handler.username)

        changes = {
            key: handler.data[key]
            for key in ("task_name", "payload", "enabled")
            if key in handler.data
        }
        if "trigger" in handler.data:
            trigger = handler.data["trigger"]
            changes.update(
                trigger_type=trigger["type"],
                trigger_data=trigger["data"],
                timezone=trigger["timezone"],
            )
        if not changes:
            handler.conclude_request(400, {}, "No schedule changes were provided")
            return Result(code=400, username=handler.username)
        try:
            with Session() as session, session.begin():
                schedule = update_schedule(
                    session,
                    registry,
                    handler.data["id"],
                    handler.data["revision"],
                    changes,
                    username=handler.username,
                )
                response = schedule_response(schedule, registry)
        except ScheduleNotFoundError:
            handler.conclude_request(404, {}, "Schedule not found")
            return Result(code=404, username=handler.username)
        except ScheduleConflictError as exc:
            handler.conclude_request(409, {}, str(exc))
            return Result(code=409, username=handler.username)
        except (LookupError, TriggerValidationError, ValueError) as exc:
            handler.conclude_request(400, {}, str(exc))
            return Result(code=400, username=handler.username)
        ProviderManager().scheduling.notify_schedule_change()
        handler.conclude_request(200, response, "Schedule updated")
        return Result(code=0, target=response["id"], username=handler.username)


class RequestDeleteScheduleHandler(RequestHandler):
    request_model = _DeleteScheduleRequest
    require_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        if error := _provider_error(handler, handler.username):
            return error
        if Permissions.MANAGE_SCHEDULES not in _permissions(handler.username):
            return _deny(handler, handler.username)
        with Session() as session:
            schedule = session.get(Schedule, handler.data["id"])
            if schedule is not None and schedule.system_managed:
                handler.conclude_request(404, {}, "Schedule not found")
                return Result(code=404, username=handler.username)
        try:
            with Session() as session, session.begin():
                delete_schedule(
                    session,
                    handler.data["id"],
                    handler.data["revision"],
                    username=handler.username,
                )
        except ScheduleNotFoundError:
            handler.conclude_request(404, {}, "Schedule not found")
            return Result(code=404, username=handler.username)
        except ScheduleConflictError as exc:
            handler.conclude_request(409, {}, str(exc))
            return Result(code=409, username=handler.username)
        ProviderManager().scheduling.notify_schedule_change()
        handler.conclude_request(200, {}, "Schedule deleted")
        return Result(
            code=0,
            target=handler.data["id"],
            username=handler.username,
        )


HANDLERS = {
    "list_scheduled_task_types": RequestListScheduledTaskTypesHandler,
    "create_schedule": RequestCreateScheduleHandler,
    "get_schedule": RequestGetScheduleHandler,
    "list_schedules": RequestListSchedulesHandler,
    "update_schedule": RequestUpdateScheduleHandler,
    "delete_schedule": RequestDeleteScheduleHandler,
}
