__all__ = [
    "apply_automatic_lockdown",
    "apply_lockdown",
    "apply_scheduled_lockdown",
    "disable_scheduled_lockdown",
    "expire_scheduled_lockdown",
]

import time
from typing import Any, cast

import orjson
from loguru import logger as log
from sqlalchemy import select, update
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session as OrmSession

from include.config.constants import GLOBAL_BROADCAST_EVENT_CHANNEL
from include.database.clock import database_now
from include.database.models.files import FileTask, FileTaskStatus
from include.database.session import Session
from include.domains.documents.file_task_signals import (
    publish_cancelled_file_tasks,
)
from include.domains.operations.lockdown.contracts import (
    LockdownReason,
    LockdownSource,
    LockdownState,
    LockdownTransition,
    LockdownTransitionOutcome,
)
from include.domains.operations.lockdown.state import (
    _delete_lockdown_activation,
    _lockdown_source,
    _LockdownActivationPayload,
    _LockdownCasConflict,
    _persist_lockdown_activation,
    _persist_lockdown_state,
    _read_lockdown_activation,
    _read_lockdown_state,
    _valid_lockdown_activation,
)
from include.providers.manager import ProviderManager

logger = log.bind(name="lockdown")

_LOCKDOWN_CAS_MAX_ATTEMPTS = 8
_LOCKDOWN_CAS_RETRY_BASE_SECONDS = 0.005
_ACTIVE_FILE_TASK_STATUSES = (
    FileTaskStatus.PENDING,
    FileTaskStatus.IN_PROGRESS,
)


class _ReasonUnset:
    pass  # TODO: Use a sentinel type when Python 3.15 comes out


_REASON_UNSET = _ReasonUnset()


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
