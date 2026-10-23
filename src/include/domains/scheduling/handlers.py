"""WebSocket management actions for the core scheduled-task domain."""

import uuid
from typing import Annotated, Any, Literal

from pydantic import Field, StringConstraints
from sqlalchemy import and_, desc, or_, select
lazy from sqlalchemy.orm import Session as OrmSession

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
    lock_schedule,
    schedule_response,
    update_schedule,
)
from include.scheduling.triggers import TriggerValidationError
from include.transport.request_handler import (
    REQUEST_UNSET,
    EmptyRequestDataModel,
    Omittable,
    RequestDataModel,
    RequestHandler,
    Result,
)
from include.types import JsonInteger
lazy from include.transport.connection import ConnectionHandler

TaskName = Annotated[
    str,
    StringConstraints(strip_whitespace=True, min_length=3, max_length=255),
]
ScheduleId = Annotated[str, StringConstraints(min_length=1, max_length=32)]
ScheduleRevision = Annotated[JsonInteger, Field(ge=1)]


class _TriggerRequest(RequestDataModel):
    """External trigger shape accepted by create and update actions."""

    type: Literal["cron", "date", "interval"]
    data: dict[str, Any]
    timezone: Annotated[
        str, StringConstraints(strip_whitespace=True, min_length=1, max_length=255)
    ]


class _CreateScheduleRequest(RequestDataModel):
    """Validated input for creating one user-managed schedule."""

    task_name: TaskName
    payload: dict[str, Any]
    trigger: _TriggerRequest
    enabled: bool = True


class _ScheduleIdRequest(RequestDataModel):
    """Validated lookup key for a user-visible schedule."""

    id: ScheduleId


class _ListSchedulesRequest(RequestDataModel):
    """Cursor pagination and logical-deletion options for schedule listing."""

    page_size: Omittable[PaginationPageSize] = REQUEST_UNSET
    cursor: PaginationCursorToken | None = None
    include_deleted: bool = False


class _UpdateScheduleRequest(RequestDataModel):
    """Optimistic partial update requiring the caller's observed revision."""

    id: ScheduleId
    revision: ScheduleRevision
    task_name: Omittable[TaskName] = REQUEST_UNSET
    payload: Omittable[dict[str, Any]] = REQUEST_UNSET
    trigger: Omittable[_TriggerRequest] = REQUEST_UNSET
    enabled: Omittable[bool] = REQUEST_UNSET


class _DeleteScheduleRequest(RequestDataModel):
    """Optimistic logical deletion of a user-managed schedule."""

    id: ScheduleId
    revision: ScheduleRevision


def _provider_error(handler: ConnectionHandler, user_id: uuid.UUID) -> Result | None:
    """Return a safe 503 response when the configured runtime is degraded."""

    status = ProviderManager().scheduling.status()
    if status.available:
        return None
    handler.conclude_request(
        503,
        {"provider": status.mode, "status": "degraded"},
        "Scheduling provider is unavailable",
    )
    return Result(code=503, user_id=user_id)


def _permissions(
    user_id: uuid.UUID, session: OrmSession | None = None
) -> set[Permissions]:
    """Read effective permissions, optionally inside the mutation transaction."""

    if session is not None:
        return User.get_existing(session, user_id).all_permissions

    with Session() as session:  # noqa: PLR1704
        return User.get_existing(session, user_id).all_permissions


def _deny(handler: ConnectionHandler, user_id: uuid.UUID) -> Result:
    """Emit the uniform scheduling permission-denied response."""

    handler.conclude_request(403, {}, "Permission denied")
    return Result(code=403, user_id=user_id)


def _task_permission_allowed(
    permissions: set[Permissions], task_name: str, registry
) -> bool:
    """Check that a task is user-visible and the principal may schedule it."""

    registration = registry.get(task_name)
    return (
        registration is not None
        and registration.user_schedulable
        and registration.required_permission in permissions
    )


class RequestListScheduledTaskTypesHandler(RequestHandler[EmptyRequestDataModel]):
    """List task contracts the authenticated principal is allowed to schedule."""

    request_model = EmptyRequestDataModel
    requires_auth = True

    def handle(self, handler: ConnectionHandler):
        """Filter task registrations by view and task-specific permissions."""

        assert handler.user_id is not None
        if error := _provider_error(handler, handler.user_id):
            return error
        permissions = _permissions(handler.user_id)
        if Permissions.VIEW_SCHEDULES not in permissions:
            return _deny(handler, handler.user_id)
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
        return Result(code=0, data={"count": len(items)}, user_id=handler.user_id)


class RequestCreateScheduleHandler(RequestHandler[_CreateScheduleRequest]):
    """Validate, authorize, and persist a new user-managed schedule."""

    request_model = _CreateScheduleRequest
    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        """Create a schedule transactionally, then wake the active Provider."""

        assert handler.user_id is not None
        if error := _provider_error(handler, handler.user_id):
            return error
        permissions = _permissions(handler.user_id)
        registry = collect_scheduled_tasks()
        task_name = handler.data["task_name"]
        if (
            Permissions.MANAGE_SCHEDULES not in permissions
            or not _task_permission_allowed(permissions, task_name, registry)
        ):
            return _deny(handler, handler.user_id)
        trigger = handler.data["trigger"]
        try:
            with Session() as session, session.begin():
                schedule = create_schedule(
                    session,
                    registry,
                    user_id=handler.user_id,
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
            return Result(code=400, user_id=handler.user_id)
        ProviderManager().scheduling.notify_schedule_change()
        handler.conclude_request(200, response, "Schedule created")
        return Result(
            code=0,
            target=response["id"],
            data={"task_name": task_name},
            user_id=handler.user_id,
        )


class RequestGetScheduleHandler(RequestHandler[_ScheduleIdRequest]):
    """Return one non-deleted, non-system schedule by ID."""

    request_model = _ScheduleIdRequest
    requires_auth = True

    def handle(self, handler: ConnectionHandler):
        """Hide deleted and system-managed rows from direct lookup."""

        assert handler.user_id is not None
        if error := _provider_error(handler, handler.user_id):
            return error
        if Permissions.VIEW_SCHEDULES not in _permissions(handler.user_id):
            return _deny(handler, handler.user_id)
        registry = collect_scheduled_tasks()
        with Session() as session:
            schedule = session.get(Schedule, handler.data["id"])
            if (
                schedule is None
                or schedule.status == "deleted"
                or schedule.system_managed
            ):
                handler.conclude_request(404, {}, "Schedule not found")
                return Result(code=404, user_id=handler.user_id)
            response = schedule_response(schedule, registry)
        handler.conclude_request(200, response, "Schedule retrieved")
        return Result(code=0, target=response["id"], user_id=handler.user_id)


class RequestListSchedulesHandler(RequestHandler[_ListSchedulesRequest]):
    """List user-managed schedules with signed cursor pagination."""

    request_model = _ListSchedulesRequest
    requires_auth = True

    def handle(self, handler: ConnectionHandler):
        """Return one descending page without exposing system-managed rows."""

        assert handler.user_id is not None
        if error := _provider_error(handler, handler.user_id):
            return error
        if Permissions.VIEW_SCHEDULES not in _permissions(handler.user_id):
            return _deny(handler, handler.user_id)
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
            return Result(code=400, user_id=handler.user_id)

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
        return Result(code=0, data={"page_size": page_size}, user_id=handler.user_id)


class RequestUpdateScheduleHandler(RequestHandler[_UpdateScheduleRequest]):
    """Apply an authorized optimistic update to an idle user schedule."""

    request_model = _UpdateScheduleRequest
    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        """Authorize against locked current state and apply supplied fields."""

        assert handler.user_id is not None
        if error := _provider_error(handler, handler.user_id):
            return error
        registry = collect_scheduled_tasks()
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
        try:
            with Session() as session, session.begin():
                current = lock_schedule(session, handler.data["id"])
                if (
                    current is None
                    or current.status == "deleted"
                    or current.system_managed
                ):
                    handler.conclude_request(404, {}, "Schedule not found")
                    return Result(code=404, user_id=handler.user_id)
                if current.revision != handler.data["revision"]:
                    raise ScheduleConflictError("Schedule revision is stale")
                task_name = changes.get("task_name", current.task_name)
                permissions = _permissions(handler.user_id, session)
                if (
                    Permissions.MANAGE_SCHEDULES not in permissions
                    or not _task_permission_allowed(permissions, task_name, registry)
                ):
                    return _deny(handler, handler.user_id)
                if not changes:
                    handler.conclude_request(
                        400, {}, "No schedule changes were provided"
                    )
                    return Result(code=400, user_id=handler.user_id)
                schedule = update_schedule(
                    session,
                    registry,
                    handler.data["id"],
                    handler.data["revision"],
                    changes,
                    user_id=handler.user_id,
                )
                response = schedule_response(schedule, registry)
        except ScheduleNotFoundError:
            handler.conclude_request(404, {}, "Schedule not found")
            return Result(code=404, user_id=handler.user_id)
        except ScheduleConflictError as exc:
            handler.conclude_request(409, {}, str(exc))
            return Result(code=409, user_id=handler.user_id)
        except (LookupError, TriggerValidationError, ValueError) as exc:
            handler.conclude_request(400, {}, str(exc))
            return Result(code=400, user_id=handler.user_id)
        ProviderManager().scheduling.notify_schedule_change()
        handler.conclude_request(200, response, "Schedule updated")
        return Result(code=0, target=response["id"], user_id=handler.user_id)


class RequestDeleteScheduleHandler(RequestHandler[_DeleteScheduleRequest]):
    """Logically delete a user schedule without interrupting running work."""

    request_model = _DeleteScheduleRequest
    requires_auth = True
    rate_limit_cost = 3

    def handle(self, handler: ConnectionHandler):
        """Retire a user schedule at the expected revision and wake the Provider."""

        assert handler.user_id is not None
        if error := _provider_error(handler, handler.user_id):
            return error
        if Permissions.MANAGE_SCHEDULES not in _permissions(handler.user_id):
            return _deny(handler, handler.user_id)
        with Session() as session:
            schedule = session.get(Schedule, handler.data["id"])
            if schedule is not None and schedule.system_managed:
                handler.conclude_request(404, {}, "Schedule not found")
                return Result(code=404, user_id=handler.user_id)
        try:
            with Session() as session, session.begin():
                delete_schedule(
                    session,
                    handler.data["id"],
                    handler.data["revision"],
                    user_id=handler.user_id,
                )
        except ScheduleNotFoundError:
            handler.conclude_request(404, {}, "Schedule not found")
            return Result(code=404, user_id=handler.user_id)
        except ScheduleConflictError as exc:
            handler.conclude_request(409, {}, str(exc))
            return Result(code=409, user_id=handler.user_id)
        ProviderManager().scheduling.notify_schedule_change()
        handler.conclude_request(200, {}, "Schedule deleted")
        return Result(
            code=0,
            target=handler.data["id"],
            user_id=handler.user_id,
        )
