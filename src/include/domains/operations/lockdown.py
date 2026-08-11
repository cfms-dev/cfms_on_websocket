__all__ = [
    "LockdownReason",
    "LockdownState",
    "LockdownStateManager",
    "LockdownTransition",
    "apply_lockdown",
    "lockdown_state_manager",
]

import time
from dataclasses import dataclass
from typing import Annotated, Any, Self, cast

import orjson
from loguru import logger as log
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    FiniteFloat,
    StringConstraints,
    ValidationError,
    model_validator,
)
from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session as OrmSession

from include.config.constants import GLOBAL_BROADCAST_EVENT_CHANNEL
from include.database.models.files import FileTask, FileTaskStatus
from include.database.session import Session
from include.database.system_states import (
    StoredSystemState,
    create_system_state,
    read_system_state,
    update_system_state,
)
from include.domains.documents.file_task_signals import (
    publish_cancelled_file_tasks,
)
from include.providers.manager import ProviderManager

logger = log.bind(name="lockdown")

_LOCKDOWN_OWNER = "core"
_LOCKDOWN_STATE_KEY = "lockdown"
_LOCKDOWN_SCHEMA_VERSION = 1
_LOCKDOWN_CAS_MAX_ATTEMPTS = 8
_LOCKDOWN_CAS_RETRY_BASE_SECONDS = 0.005
_ACTIVE_FILE_TASK_STATUSES = (
    FileTaskStatus.PENDING,
    FileTaskStatus.IN_PROGRESS,
)


LockdownReason = Annotated[
    str,
    StringConstraints(min_length=1, max_length=1024),
]


class _LockdownStateBase(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        strict=True,
        extra="forbid",
    )

    enabled: bool
    reason: LockdownReason | None

    @model_validator(mode="after")
    def _validate_reason(self) -> Self:
        if not self.enabled and self.reason is not None:
            raise ValueError("A lockdown reason requires lockdown to be enabled")
        return self


class LockdownState(_LockdownStateBase):
    enabled: bool = False
    reason: LockdownReason | None = None

    def as_response_data(self) -> dict[str, bool | str | None]:
        return {
            "status": self.enabled,
            "reason": self.reason,
        }


class _LockdownPayload(_LockdownStateBase):
    last_disabled_at: Annotated[
        FiniteFloat,
        Field(ge=0),
    ]


@dataclass(frozen=True, slots=True)
class LockdownTransition:
    state: LockdownState
    applied: bool
    cancelled_file_tasks: int = 0


@dataclass(frozen=True, slots=True)
class _StoredLockdownState:
    state: LockdownState
    last_disabled_at: float
    revision: int


def _parse_lockdown_state(
    stored: StoredSystemState,
) -> _StoredLockdownState:
    if stored.schema_version != _LOCKDOWN_SCHEMA_VERSION:
        raise RuntimeError(
            f"Unsupported lockdown state schema version: {stored.schema_version}"
        )

    payload = _LockdownPayload.model_validate(stored.payload)

    return _StoredLockdownState(
        state=LockdownState(
            enabled=payload.enabled,
            reason=payload.reason,
        ),
        last_disabled_at=payload.last_disabled_at,
        revision=stored.revision,
    )


def _read_lockdown_state(
    session: OrmSession,
) -> _StoredLockdownState | None:
    try:
        stored = read_system_state(
            session,
            _LOCKDOWN_OWNER,
            _LOCKDOWN_STATE_KEY,
        )
        return None if stored is None else _parse_lockdown_state(stored)
    except ValidationError as exc:
        raise RuntimeError("Invalid persisted lockdown state") from exc


class LockdownStateManager:
    def get_state(self) -> LockdownState:
        with Session() as session:
            stored = _read_lockdown_state(session)

        return LockdownState() if stored is None else stored.state

    def get_last_disabled_at(self) -> float:
        with Session() as session:
            stored = _read_lockdown_state(session)

        return 0.0 if stored is None else stored.last_disabled_at


lockdown_state_manager = LockdownStateManager()


def _publish_lockdown_state(state: LockdownState) -> None:
    message = orjson.dumps(
        {
            "event": "lockdown",
            "data": state.as_response_data(),
        }
    ).decode()

    try:
        ProviderManager().event_bus.publish(
            GLOBAL_BROADCAST_EVENT_CHANNEL,
            message,
        )
    except Exception:
        logger.exception("Failed to broadcast lockdown state")


def _cancel_pending_file_tasks(
    session: OrmSession,
) -> tuple[list[str], int]:
    task_ids = list(
        session.scalars(
            select(FileTask.id).where(FileTask.status.in_(_ACTIVE_FILE_TASK_STATUSES))
        ).all()
    )

    result = cast(
        CursorResult[Any],
        session.execute(
            update(FileTask)
            .where(FileTask.status.in_(_ACTIVE_FILE_TASK_STATUSES))
            .values(status=FileTaskStatus.CANCELLED)
        ),
    )

    return task_ids, result.rowcount or 0


def apply_lockdown(
    status: bool,
    reason: str | None = None,
    *,
    only_if_inactive: bool = False,
) -> LockdownTransition:
    """Persist a lockdown transition and its database effects atomically."""
    state = LockdownState(
        enabled=status,
        reason=reason,
    )

    if not status and only_if_inactive:
        raise ValueError("only_if_inactive is only valid when enabling lockdown")

    attempt = 0

    while True:
        task_ids: list[str] = []
        cancelled_file_tasks = 0

        with Session.begin() as session:
            current = _read_lockdown_state(session)

            if (
                status
                and only_if_inactive
                and current is not None
                and current.state.enabled
            ):
                return LockdownTransition(
                    state=current.state,
                    applied=False,
                )

            last_disabled_at = (
                time.time()
                if not status
                else (0.0 if current is None else current.last_disabled_at)
            )

            payload = _LockdownPayload(
                enabled=state.enabled,
                reason=state.reason,
                last_disabled_at=last_disabled_at,
            ).model_dump(mode="json")

            if current is None:
                applied = create_system_state(
                    session,
                    _LOCKDOWN_OWNER,
                    _LOCKDOWN_STATE_KEY,
                    schema_version=_LOCKDOWN_SCHEMA_VERSION,
                    payload=payload,
                )
            else:
                applied = update_system_state(
                    session,
                    _LOCKDOWN_OWNER,
                    _LOCKDOWN_STATE_KEY,
                    expected_revision=current.revision,
                    schema_version=_LOCKDOWN_SCHEMA_VERSION,
                    payload=payload,
                )

            if applied and status:
                task_ids, cancelled_file_tasks = _cancel_pending_file_tasks(session)

        if applied:
            publish_cancelled_file_tasks(task_ids)
            _publish_lockdown_state(state)

            return LockdownTransition(
                state=state,
                applied=True,
                cancelled_file_tasks=cancelled_file_tasks,
            )

        attempt += 1

        if attempt >= _LOCKDOWN_CAS_MAX_ATTEMPTS:
            raise RuntimeError(
                "Failed to apply lockdown after repeated concurrent updates"
            )

        time.sleep(_LOCKDOWN_CAS_RETRY_BASE_SECONDS * 2 ** (attempt - 1))
