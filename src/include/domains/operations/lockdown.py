import math
import time
from dataclasses import dataclass
from typing import Any, cast

import orjson
from loguru import logger as log
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
from include.domains.documents.file_task_signals import publish_cancelled_file_tasks
from include.providers.manager import ProviderManager

logger = log.bind(name="lockdown")

_LOCKDOWN_OWNER = "core"
_LOCKDOWN_STATE_KEY = "lockdown"
_LOCKDOWN_SCHEMA_VERSION = 1
_LEGACY_CACHE_KEY = "system:lockdown"
_LEGACY_LAST_DISABLED_CACHE_KEY = "system:lockdown:last_disabled"


@dataclass(frozen=True, slots=True)
class LockdownState:
    enabled: bool = False
    reason: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.enabled, bool):
            raise TypeError("Lockdown status must be a boolean")
        if self.reason is not None:
            if not isinstance(self.reason, str):
                raise TypeError("Lockdown reason must be a string")
            if not 1 <= len(self.reason) <= 1024:
                raise ValueError("Lockdown reason must contain 1 to 1024 characters")
        if not self.enabled and self.reason is not None:
            raise ValueError("A lockdown reason requires lockdown to be enabled")

    def as_response_data(self) -> dict[str, bool | str | None]:
        return {"status": self.enabled, "reason": self.reason}


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


def _parse_lockdown_state(stored: StoredSystemState) -> _StoredLockdownState:
    if stored.schema_version != _LOCKDOWN_SCHEMA_VERSION:
        raise RuntimeError(
            f"Unsupported lockdown state schema version: {stored.schema_version}"
        )
    payload = stored.payload
    if set(payload) != {"enabled", "reason", "last_disabled_at"}:
        raise RuntimeError("Invalid persisted lockdown state fields")
    enabled = payload["enabled"]
    reason = payload["reason"]
    last_disabled_at = payload["last_disabled_at"]
    if isinstance(last_disabled_at, bool) or not isinstance(
        last_disabled_at, int | float
    ):
        raise RuntimeError("Invalid persisted lockdown disable timestamp")
    last_disabled_at = float(last_disabled_at)
    if not math.isfinite(last_disabled_at) or last_disabled_at < 0:
        raise RuntimeError("Invalid persisted lockdown disable timestamp")
    try:
        state = LockdownState(enabled=enabled, reason=reason)
    except (TypeError, ValueError) as exc:
        raise RuntimeError("Invalid persisted lockdown state") from exc
    return _StoredLockdownState(
        state=state,
        last_disabled_at=last_disabled_at,
        revision=stored.revision,
    )


def _read_lockdown_state(session: OrmSession) -> _StoredLockdownState | None:
    stored = read_system_state(session, _LOCKDOWN_OWNER, _LOCKDOWN_STATE_KEY)
    return None if stored is None else _parse_lockdown_state(stored)


def _lockdown_payload(
    state: LockdownState, last_disabled_at: float
) -> dict[str, bool | str | float | None]:
    return {
        "enabled": state.enabled,
        "reason": state.reason,
        "last_disabled_at": last_disabled_at,
    }


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


def _legacy_lockdown_state(value: Any) -> LockdownState:
    if value in ("1", b"1"):
        return LockdownState(enabled=True)
    try:
        data: dict[str, Any] = orjson.loads(value)
        if set(data) - {"status", "reason"}:
            raise ValueError("Invalid cached lockdown state")
        return LockdownState(enabled=data["status"], reason=data.get("reason"))
    except orjson.JSONDecodeError, KeyError, TypeError, ValueError:
        logger.error("Invalid cached lockdown state; importing a locked state")
        return LockdownState(enabled=True)


def _legacy_last_disabled_at(value: Any) -> float:
    if value is None:
        return 0.0
    try:
        timestamp = float(value)
    except TypeError, ValueError:
        logger.warning("Ignoring invalid cached lockdown disable timestamp")
        return 0.0
    if not math.isfinite(timestamp) or timestamp < 0:
        logger.warning("Ignoring invalid cached lockdown disable timestamp")
        return 0.0
    return timestamp


def initialize_lockdown_state() -> None:
    """Validate durable state and import the legacy cache representation once."""
    with Session() as session:
        if _read_lockdown_state(session) is not None:
            return

    cache = ProviderManager().caching
    cached_state = cache.get(_LEGACY_CACHE_KEY)
    cached_last_disabled = cache.get(_LEGACY_LAST_DISABLED_CACHE_KEY)
    if cached_state is None and cached_last_disabled is None:
        return

    state = (
        LockdownState()
        if cached_state is None
        else _legacy_lockdown_state(cached_state)
    )
    last_disabled_at = _legacy_last_disabled_at(cached_last_disabled)
    with Session.begin() as session:
        imported = create_system_state(
            session,
            _LOCKDOWN_OWNER,
            _LOCKDOWN_STATE_KEY,
            schema_version=_LOCKDOWN_SCHEMA_VERSION,
            payload=_lockdown_payload(state, last_disabled_at),
        )
        if not imported:
            stored = _read_lockdown_state(session)
            if stored is None:
                raise RuntimeError("Failed to initialize durable lockdown state")

    if imported:
        try:
            cache.delete(_LEGACY_CACHE_KEY)
            cache.delete(_LEGACY_LAST_DISABLED_CACHE_KEY)
        except Exception:
            logger.exception("Failed to remove imported legacy lockdown cache keys")


def _publish_lockdown_state(state: LockdownState) -> None:
    message = orjson.dumps(
        {
            "event": "lockdown",
            "data": state.as_response_data(),
        }
    ).decode()
    try:
        ProviderManager().event_bus.publish(GLOBAL_BROADCAST_EVENT_CHANNEL, message)
    except Exception:
        logger.exception("Failed to broadcast lockdown state")


def _cancel_pending_file_tasks(
    session: OrmSession,
) -> tuple[list[str], int]:
    task_ids = list(
        session.scalars(
            select(FileTask.id).where(
                FileTask.status.in_(
                    (FileTaskStatus.PENDING, FileTaskStatus.IN_PROGRESS)
                )
            )
        ).all()
    )
    result = cast(
        CursorResult[Any],
        session.execute(
            update(FileTask)
            .where(
                FileTask.status.in_(
                    (FileTaskStatus.PENDING, FileTaskStatus.IN_PROGRESS)
                )
            )
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
    state = LockdownState(enabled=status, reason=reason)
    if not status and only_if_inactive:
        raise ValueError("only_if_inactive is only valid when enabling lockdown")

    while True:
        task_ids: list[str] = []
        cancelled_file_tasks = 0
        with Session.begin() as session:
            current = _read_lockdown_state(session)
            if status and only_if_inactive and current is not None:
                if current.state.enabled:
                    return LockdownTransition(state=current.state, applied=False)

            last_disabled_at = (
                time.time()
                if not status
                else (0.0 if current is None else current.last_disabled_at)
            )
            payload = _lockdown_payload(state, last_disabled_at)
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
            if not applied:
                continue
            if status:
                task_ids, cancelled_file_tasks = _cancel_pending_file_tasks(session)

        publish_cancelled_file_tasks(task_ids)
        _publish_lockdown_state(state)
        return LockdownTransition(
            state=state,
            applied=True,
            cancelled_file_tasks=cancelled_file_tasks,
        )
