__all__ = [
    "LockdownReason",
    "LockdownSource",
    "LockdownState",
    "LockdownStateManager",
    "LockdownTransition",
    "LockdownTransitionOutcome",
    "ScheduledLockdownActivation",
    "apply_automatic_lockdown",
    "apply_lockdown",
    "apply_scheduled_lockdown",
    "disable_scheduled_lockdown",
    "expire_scheduled_lockdown",
    "lockdown_state_manager",
]

import time
from dataclasses import dataclass
from enum import StrEnum
from typing import Annotated, Any, Literal, Self, cast

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
from include.database.clock import database_now
from include.database.models.files import FileTask, FileTaskStatus
from include.database.session import Session
from include.database.system_states import (
    StoredSystemState,
    create_system_state,
    delete_system_state,
    read_system_state,
    update_system_state,
)
from include.domains.documents.file_task_signals import (
    publish_cancelled_file_tasks,
)
from include.domains.operations.comments import OperationReason
from include.providers.manager import ProviderManager

logger = log.bind(name="lockdown")

_LOCKDOWN_OWNER = "core"
_LOCKDOWN_STATE_KEY = "lockdown"
_LOCKDOWN_LEGACY_SCHEMA_VERSION = 1
_LOCKDOWN_SCHEMA_VERSION = 2
_LOCKDOWN_ACTIVATION_STATE_KEY = "lockdown_activation"
_LOCKDOWN_ACTIVATION_LEGACY_SCHEMA_VERSION = 1
_LOCKDOWN_ACTIVATION_SCHEMA_VERSION = 2
_LOCKDOWN_CAS_MAX_ATTEMPTS = 8
_LOCKDOWN_CAS_RETRY_BASE_SECONDS = 0.005
_ACTIVE_FILE_TASK_STATUSES = (
    FileTaskStatus.PENDING,
    FileTaskStatus.IN_PROGRESS,
)


LockdownReason = OperationReason
_PersistedLockdownSource = Literal["manual", "scheduled", "automatic"]


class LockdownSource(StrEnum):
    """Internal provenance used to protect security-owned lockdowns."""

    MANUAL = "manual"
    SCHEDULED = "scheduled"
    AUTOMATIC = "automatic"
    UNKNOWN = "unknown"


class _ReasonUnset:
    pass  # TODO: Use a sentinel type when Python 3.15 comes out


_REASON_UNSET = _ReasonUnset()


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


class _LockdownPayloadV1(_LockdownStateBase):
    last_disabled_at: Annotated[
        FiniteFloat,
        Field(ge=0),
    ]


class _LockdownPayload(_LockdownPayloadV1):
    source: _PersistedLockdownSource | None

    @model_validator(mode="after")
    def _validate_source(self) -> Self:
        if self.enabled and self.source is None:
            raise ValueError("An enabled lockdown requires a source")
        if not self.enabled and self.source is not None:
            raise ValueError("A disabled lockdown cannot have a source")
        return self


class _LockdownActivationBase(BaseModel):
    model_config = ConfigDict(
        frozen=True,
        strict=True,
        extra="forbid",
    )

    activation_id: Annotated[
        str,
        StringConstraints(min_length=1, max_length=128),
    ]
    lockdown_revision: Annotated[int, Field(gt=0)]


class _LockdownActivationPayloadV1(_LockdownActivationBase):
    expires_at: Annotated[FiniteFloat, Field(ge=0)]


class _LockdownActivationPayload(_LockdownActivationBase):
    expires_at: Annotated[FiniteFloat, Field(ge=0)] | None


class LockdownTransitionOutcome(StrEnum):
    APPLIED = "applied"
    UNCHANGED = "unchanged"
    CONDITION_NOT_MET = "condition_not_met"


@dataclass(frozen=True, slots=True)
class ScheduledLockdownActivation:
    activation_id: str
    expires_at: float | None
    observed_at: float


@dataclass(frozen=True, slots=True)
class LockdownTransition:
    previous_state: LockdownState
    state: LockdownState
    outcome: LockdownTransitionOutcome
    cancelled_file_tasks: int = 0
    previous_source: LockdownSource | None = None
    source: LockdownSource | None = None

    @property
    def applied(self) -> bool:
        return self.outcome is LockdownTransitionOutcome.APPLIED


@dataclass(frozen=True, slots=True)
class _StoredLockdownState:
    state: LockdownState
    source: LockdownSource | None
    last_disabled_at: float
    revision: int


@dataclass(frozen=True, slots=True)
class _StoredLockdownActivation:
    payload: _LockdownActivationPayload
    revision: int


def _parse_lockdown_state(
    stored: StoredSystemState,
) -> _StoredLockdownState:
    if stored.schema_version == _LOCKDOWN_LEGACY_SCHEMA_VERSION:
        payload = _LockdownPayloadV1.model_validate(stored.payload)
        source = LockdownSource.UNKNOWN if payload.enabled else None
    elif stored.schema_version == _LOCKDOWN_SCHEMA_VERSION:
        payload = _LockdownPayload.model_validate(stored.payload)
        source = None if payload.source is None else LockdownSource(payload.source)
    else:
        raise RuntimeError(
            f"Unsupported lockdown state schema version: {stored.schema_version}"
        )

    return _StoredLockdownState(
        state=LockdownState(
            enabled=payload.enabled,
            reason=payload.reason,
        ),
        source=source,
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


def _read_lockdown_activation(
    session: OrmSession,
) -> _StoredLockdownActivation | None:
    try:
        stored = read_system_state(
            session,
            _LOCKDOWN_OWNER,
            _LOCKDOWN_ACTIVATION_STATE_KEY,
        )
        if stored is None:
            return None
        if stored.schema_version == _LOCKDOWN_ACTIVATION_LEGACY_SCHEMA_VERSION:
            legacy = _LockdownActivationPayloadV1.model_validate(stored.payload)
            payload = _LockdownActivationPayload(
                activation_id=legacy.activation_id,
                expires_at=legacy.expires_at,
                lockdown_revision=legacy.lockdown_revision,
            )
        elif stored.schema_version == _LOCKDOWN_ACTIVATION_SCHEMA_VERSION:
            payload = _LockdownActivationPayload.model_validate(stored.payload)
        else:
            raise RuntimeError(
                "Unsupported lockdown activation schema version: "
                f"{stored.schema_version}"
            )
        return _StoredLockdownActivation(
            payload=payload,
            revision=stored.revision,
        )
    except ValidationError as exc:
        raise RuntimeError("Invalid persisted lockdown activation") from exc


def _valid_lockdown_activation(
    state: _StoredLockdownState | None,
    activation: _StoredLockdownActivation | None,
) -> _LockdownActivationPayload | None:
    if (
        state is None
        or not state.state.enabled
        or activation is None
        or activation.payload.lockdown_revision != state.revision
        or state.source not in (LockdownSource.SCHEDULED, LockdownSource.UNKNOWN)
    ):
        return None
    return activation.payload


def _lockdown_source(
    state: _StoredLockdownState | None,
    activation: _LockdownActivationPayload | None,
) -> LockdownSource | None:
    if state is None or not state.state.enabled:
        return None
    if state.source is LockdownSource.UNKNOWN and activation is not None:
        return LockdownSource.SCHEDULED
    if state.source is LockdownSource.SCHEDULED and activation is None:
        return LockdownSource.UNKNOWN
    return state.source


class LockdownStateManager:
    def get_state(self) -> LockdownState:
        with Session() as session:
            stored = _read_lockdown_state(session)

        return LockdownState() if stored is None else stored.state

    def get_last_disabled_at(self) -> float:
        with Session() as session:
            stored = _read_lockdown_state(session)

        return 0.0 if stored is None else stored.last_disabled_at

    def get_source(self) -> LockdownSource | None:
        with Session() as session:
            state = _read_lockdown_state(session)
            activation = _valid_lockdown_activation(
                state,
                _read_lockdown_activation(session),
            )

        return _lockdown_source(state, activation)

    def get_scheduled_activation(self) -> ScheduledLockdownActivation | None:
        with Session() as session:
            state = _read_lockdown_state(session)
            activation = _valid_lockdown_activation(
                state,
                _read_lockdown_activation(session),
            )
            observed_at = database_now(session)

        if activation is None:
            return None
        return ScheduledLockdownActivation(
            activation_id=activation.activation_id,
            expires_at=activation.expires_at,
            observed_at=observed_at,
        )


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


class _LockdownCasConflict(RuntimeError):
    pass


def _persist_lockdown_state(
    session: OrmSession,
    current: _StoredLockdownState | None,
    state: LockdownState,
    source: LockdownSource | None,
    last_disabled_at: float,
) -> int:
    payload = _LockdownPayload(
        enabled=state.enabled,
        reason=state.reason,
        source=None if source is None else source.value,
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
        revision = 1
    else:
        applied = update_system_state(
            session,
            _LOCKDOWN_OWNER,
            _LOCKDOWN_STATE_KEY,
            expected_revision=current.revision,
            schema_version=_LOCKDOWN_SCHEMA_VERSION,
            payload=payload,
        )
        revision = current.revision + 1
    if not applied:
        raise _LockdownCasConflict
    return revision


def _persist_lockdown_activation(
    session: OrmSession,
    current: _StoredLockdownActivation | None,
    payload: _LockdownActivationPayload,
) -> None:
    values = payload.model_dump(mode="json")
    if current is None:
        applied = create_system_state(
            session,
            _LOCKDOWN_OWNER,
            _LOCKDOWN_ACTIVATION_STATE_KEY,
            schema_version=_LOCKDOWN_ACTIVATION_SCHEMA_VERSION,
            payload=values,
        )
    else:
        applied = update_system_state(
            session,
            _LOCKDOWN_OWNER,
            _LOCKDOWN_ACTIVATION_STATE_KEY,
            expected_revision=current.revision,
            schema_version=_LOCKDOWN_ACTIVATION_SCHEMA_VERSION,
            payload=values,
        )
    if not applied:
        raise _LockdownCasConflict


def _delete_lockdown_activation(
    session: OrmSession,
    current: _StoredLockdownActivation | None,
) -> bool:
    if current is None:
        return False
    if not delete_system_state(
        session,
        _LOCKDOWN_OWNER,
        _LOCKDOWN_ACTIVATION_STATE_KEY,
        expected_revision=current.revision,
    ):
        raise _LockdownCasConflict
    return True


def _retry_lockdown_cas(attempt: int) -> int:
    attempt += 1
    if attempt >= _LOCKDOWN_CAS_MAX_ATTEMPTS:
        raise RuntimeError("Failed to apply lockdown after repeated concurrent updates")
    time.sleep(_LOCKDOWN_CAS_RETRY_BASE_SECONDS * 2 ** (attempt - 1))
    return attempt


def _notify_schedule_change() -> None:
    try:
        ProviderManager().scheduling.notify_schedule_change()
    except Exception:
        logger.exception("Failed to notify scheduler of a lockdown state change")


def apply_lockdown(
    status: bool,
    reason: str | None | _ReasonUnset = _REASON_UNSET,
    *,
    only_if_inactive: bool = False,
    take_over_scheduled: bool = False,
) -> LockdownTransition:
    """Persist a lockdown transition and its database effects atomically."""
    if not status and only_if_inactive:
        raise ValueError("only_if_inactive is only valid when enabling lockdown")
    if take_over_scheduled and (not status or not only_if_inactive):
        raise ValueError("take_over_scheduled requires enabling with only_if_inactive")
    if not status and not isinstance(reason, _ReasonUnset):
        raise ValueError("A lockdown reason requires lockdown to be enabled")

    attempt = 0

    while True:
        task_ids: list[str] = []
        cancelled_file_tasks = 0
        activation_changed = False

        try:
            with Session.begin() as session:
                current = _read_lockdown_state(session)
                activation_entry = _read_lockdown_activation(session)
                current_activation = _valid_lockdown_activation(
                    current,
                    activation_entry,
                )
                previous_state = LockdownState() if current is None else current.state
                previous_source = _lockdown_source(current, current_activation)

                if status and only_if_inactive and previous_state.enabled:
                    if take_over_scheduled and current_activation is not None:
                        _persist_lockdown_state(
                            session,
                            current,
                            previous_state,
                            LockdownSource.AUTOMATIC,
                            current.last_disabled_at,
                        )
                        activation_changed = _delete_lockdown_activation(
                            session,
                            activation_entry,
                        )
                        source = LockdownSource.AUTOMATIC
                    else:
                        return LockdownTransition(
                            previous_state=previous_state,
                            state=previous_state,
                            previous_source=previous_source,
                            source=previous_source,
                            outcome=LockdownTransitionOutcome.CONDITION_NOT_MET,
                        )
                    state = previous_state
                    status_changed = False
                else:
                    current_reason = previous_state.reason
                    if not isinstance(reason, _ReasonUnset):
                        next_reason = reason
                    elif status and previous_state.enabled:
                        next_reason = current_reason
                    else:
                        next_reason = None

                    state = LockdownState(enabled=status, reason=next_reason)

                    if state == previous_state:
                        return LockdownTransition(
                            previous_state=previous_state,
                            state=state,
                            previous_source=previous_source,
                            source=previous_source,
                            outcome=LockdownTransitionOutcome.UNCHANGED,
                        )

                    status_changed = state.enabled != previous_state.enabled
                    source = (
                        LockdownSource.AUTOMATIC
                        if state.enabled and previous_source is LockdownSource.AUTOMATIC
                        else (LockdownSource.MANUAL if state.enabled else None)
                    )

                    last_disabled_at = (
                        time.time()
                        if status_changed and not status
                        else (0.0 if current is None else current.last_disabled_at)
                    )
                    _persist_lockdown_state(
                        session,
                        current,
                        state,
                        source,
                        last_disabled_at,
                    )
                    activation_changed = _delete_lockdown_activation(
                        session,
                        activation_entry,
                    )

                    if status_changed and status:
                        task_ids, cancelled_file_tasks = _cancel_pending_file_tasks(
                            session
                        )
        except _LockdownCasConflict:
            attempt = _retry_lockdown_cas(attempt)
            continue

        if status_changed:
            publish_cancelled_file_tasks(task_ids)
            _publish_lockdown_state(state)
        elif state != previous_state:
            _publish_lockdown_state(state)
        if activation_changed:
            _notify_schedule_change()

        return LockdownTransition(
            previous_state=previous_state,
            state=state,
            previous_source=previous_source,
            source=source,
            outcome=LockdownTransitionOutcome.APPLIED,
            cancelled_file_tasks=cancelled_file_tasks,
        )


def apply_automatic_lockdown(
    reason: LockdownReason,
) -> LockdownTransition:
    """Enable or protect a lockdown after an automatic security decision."""

    attempt = 0
    while True:
        task_ids: list[str] = []
        cancelled_file_tasks = 0
        activation_changed = False
        try:
            with Session.begin() as session:
                current = _read_lockdown_state(session)
                activation_entry = _read_lockdown_activation(session)
                current_activation = _valid_lockdown_activation(
                    current,
                    activation_entry,
                )
                previous_state = LockdownState() if current is None else current.state
                previous_source = _lockdown_source(current, current_activation)
                if previous_source in (
                    LockdownSource.AUTOMATIC,
                    LockdownSource.UNKNOWN,
                ):
                    return LockdownTransition(
                        previous_state=previous_state,
                        state=previous_state,
                        previous_source=previous_source,
                        source=previous_source,
                        outcome=LockdownTransitionOutcome.CONDITION_NOT_MET,
                    )

                if previous_state.enabled:
                    state = previous_state
                    status_changed = False
                else:
                    state = LockdownState(enabled=True, reason=reason)
                    status_changed = True

                _persist_lockdown_state(
                    session,
                    current,
                    state,
                    LockdownSource.AUTOMATIC,
                    0.0 if current is None else current.last_disabled_at,
                )
                activation_changed = _delete_lockdown_activation(
                    session,
                    activation_entry,
                )
                if status_changed:
                    task_ids, cancelled_file_tasks = _cancel_pending_file_tasks(session)
        except _LockdownCasConflict:
            attempt = _retry_lockdown_cas(attempt)
            continue

        if status_changed:
            publish_cancelled_file_tasks(task_ids)
            _publish_lockdown_state(state)
        if activation_changed:
            _notify_schedule_change()
        return LockdownTransition(
            previous_state=previous_state,
            state=state,
            previous_source=previous_source,
            source=LockdownSource.AUTOMATIC,
            outcome=LockdownTransitionOutcome.APPLIED,
            cancelled_file_tasks=cancelled_file_tasks,
        )


def apply_scheduled_lockdown(
    activation_id: str,
    expires_at: float | None,
    reason: LockdownReason | None = None,
) -> LockdownTransition:
    """Enable lockdown for one scheduled occurrence if no lockdown is active."""
    attempt = 0
    while True:
        task_ids: list[str] = []
        try:
            with Session.begin() as session:
                current = _read_lockdown_state(session)
                activation_entry = _read_lockdown_activation(session)
                current_activation = _valid_lockdown_activation(
                    current,
                    activation_entry,
                )
                previous_state = LockdownState() if current is None else current.state
                previous_source = _lockdown_source(current, current_activation)
                candidate = _LockdownActivationPayload(
                    activation_id=activation_id,
                    expires_at=expires_at,
                    lockdown_revision=1,
                )
                if expires_at is not None and expires_at <= database_now(session):
                    return LockdownTransition(
                        previous_state=previous_state,
                        state=previous_state,
                        previous_source=previous_source,
                        source=previous_source,
                        outcome=LockdownTransitionOutcome.CONDITION_NOT_MET,
                    )
                if previous_state.enabled:
                    outcome = (
                        LockdownTransitionOutcome.UNCHANGED
                        if current_activation is not None
                        and current_activation.activation_id == activation_id
                        and current_activation.expires_at == expires_at
                        else LockdownTransitionOutcome.CONDITION_NOT_MET
                    )
                    return LockdownTransition(
                        previous_state=previous_state,
                        state=previous_state,
                        previous_source=previous_source,
                        source=previous_source,
                        outcome=outcome,
                    )

                state = LockdownState(enabled=True, reason=reason)
                revision = _persist_lockdown_state(
                    session,
                    current,
                    state,
                    LockdownSource.SCHEDULED,
                    0.0 if current is None else current.last_disabled_at,
                )
                _persist_lockdown_activation(
                    session,
                    activation_entry,
                    candidate.model_copy(update={"lockdown_revision": revision}),
                )
                task_ids, cancelled_file_tasks = _cancel_pending_file_tasks(session)
        except _LockdownCasConflict:
            attempt = _retry_lockdown_cas(attempt)
            continue

        publish_cancelled_file_tasks(task_ids)
        _publish_lockdown_state(state)
        _notify_schedule_change()
        return LockdownTransition(
            previous_state=previous_state,
            state=state,
            previous_source=previous_source,
            source=LockdownSource.SCHEDULED,
            outcome=LockdownTransitionOutcome.APPLIED,
            cancelled_file_tasks=cancelled_file_tasks,
        )


def disable_scheduled_lockdown() -> LockdownTransition:
    """Disable an operator- or schedule-owned lockdown, but never a protected one."""

    attempt = 0
    while True:
        activation_changed = False
        try:
            with Session.begin() as session:
                current = _read_lockdown_state(session)
                activation_entry = _read_lockdown_activation(session)
                current_activation = _valid_lockdown_activation(
                    current,
                    activation_entry,
                )
                previous_state = LockdownState() if current is None else current.state
                previous_source = _lockdown_source(current, current_activation)
                if not previous_state.enabled:
                    return LockdownTransition(
                        previous_state=previous_state,
                        state=previous_state,
                        previous_source=previous_source,
                        source=previous_source,
                        outcome=LockdownTransitionOutcome.UNCHANGED,
                    )
                if previous_source not in (
                    LockdownSource.MANUAL,
                    LockdownSource.SCHEDULED,
                ):
                    return LockdownTransition(
                        previous_state=previous_state,
                        state=previous_state,
                        previous_source=previous_source,
                        source=previous_source,
                        outcome=LockdownTransitionOutcome.CONDITION_NOT_MET,
                    )

                state = LockdownState()
                _persist_lockdown_state(
                    session,
                    current,
                    state,
                    None,
                    database_now(session),
                )
                activation_changed = _delete_lockdown_activation(
                    session,
                    activation_entry,
                )
        except _LockdownCasConflict:
            attempt = _retry_lockdown_cas(attempt)
            continue

        _publish_lockdown_state(state)
        if activation_changed:
            _notify_schedule_change()
        return LockdownTransition(
            previous_state=previous_state,
            state=state,
            previous_source=previous_source,
            source=None,
            outcome=LockdownTransitionOutcome.APPLIED,
        )


def expire_scheduled_lockdown(activation_id: str) -> LockdownTransition:
    """Disable the due lockdown owned by one scheduled occurrence."""
    attempt = 0
    while True:
        try:
            with Session.begin() as session:
                current = _read_lockdown_state(session)
                activation_entry = _read_lockdown_activation(session)
                activation = _valid_lockdown_activation(current, activation_entry)
                previous_state = LockdownState() if current is None else current.state
                previous_source = _lockdown_source(current, activation)
                current_time = database_now(session)
                if (
                    activation is None
                    or activation.activation_id != activation_id
                    or activation.expires_at is None
                    or activation.expires_at > current_time
                ):
                    return LockdownTransition(
                        previous_state=previous_state,
                        state=previous_state,
                        previous_source=previous_source,
                        source=previous_source,
                        outcome=LockdownTransitionOutcome.CONDITION_NOT_MET,
                    )

                state = LockdownState()
                _persist_lockdown_state(
                    session,
                    current,
                    state,
                    None,
                    current_time,
                )
                _delete_lockdown_activation(session, activation_entry)
        except _LockdownCasConflict:
            attempt = _retry_lockdown_cas(attempt)
            continue

        _publish_lockdown_state(state)
        _notify_schedule_change()
        return LockdownTransition(
            previous_state=previous_state,
            state=state,
            previous_source=previous_source,
            source=None,
            outcome=LockdownTransitionOutcome.APPLIED,
        )
