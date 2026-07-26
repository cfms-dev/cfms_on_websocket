import time
from dataclasses import dataclass
from typing import Any, cast

import orjson
from loguru import logger as log
from sqlalchemy import update
from sqlalchemy.engine import CursorResult

from include.config.constants import GLOBAL_BROADCAST_EVENT_CHANNEL
from include.providers.base import CachingProvider
from include.providers.manager import ProviderManager

logger = log.bind(name="lockdown")


@dataclass(frozen=True, slots=True)
class LockdownState:
    enabled: bool = False
    reason: str | None = None

    def __post_init__(self) -> None:
        if not self.enabled and self.reason is not None:
            raise ValueError("A lockdown reason requires lockdown to be enabled")

    def as_response_data(self) -> dict[str, bool | str | None]:
        return {"status": self.enabled, "reason": self.reason}


@dataclass(frozen=True, slots=True)
class LockdownTransition:
    state: LockdownState
    applied: bool
    cancelled_file_tasks: int = 0


class LockdownStateManager:
    _CACHE_KEY = "system:lockdown"
    _LAST_DISABLED_CACHE_KEY = "system:lockdown:last_disabled"

    def __init__(self, cache: CachingProvider | None = None) -> None:
        self._cache = cache

    @property
    def cache(self) -> CachingProvider:
        """Returns the caching provider to use for storing the lockdown state.

        FIXME: I wonder if it is necessary to design the property this way solely for
        testing purposes, given that support for manually specifying a
        CachingProvider serves no purpose other than testing?
        """
        if self._cache is not None:
            return self._cache
        return ProviderManager().caching

    def get_state(self) -> LockdownState:
        cached_state = self.cache.get(self._CACHE_KEY)
        if cached_state is None:
            return LockdownState()

        if cached_state in ("1", b"1"):
            return LockdownState(enabled=True)

        try:
            data: dict[str, Any] = orjson.loads(cached_state)
            enabled = data["status"]
            reason = data.get("reason")
            if not isinstance(enabled, bool) or not (
                reason is None or isinstance(reason, str)
            ):
                raise ValueError("Invalid cached lockdown state")
            return LockdownState(
                enabled=enabled,
                reason=reason,
            )
        except orjson.JSONDecodeError, KeyError, TypeError, ValueError:
            logger.error("Invalid cached lockdown state; failing closed")
            return LockdownState(enabled=True)

    def get_last_disabled_at(self) -> float:
        value = self.cache.get(self._LAST_DISABLED_CACHE_KEY)
        if value is None:
            return 0.0
        try:
            return float(value)
        except TypeError, ValueError:
            logger.warning("Ignoring invalid lockdown disable timestamp")
            return 0.0

    def set_state(self, state: LockdownState) -> LockdownState:
        if state.enabled:
            self.cache.set(self._CACHE_KEY, orjson.dumps(state.as_response_data()))
        else:
            self.cache.delete(self._CACHE_KEY)
        return state

    def enable_if_inactive(
        self, reason: str | None = None
    ) -> tuple[LockdownState, bool]:
        current_state = self.get_state()
        if current_state.enabled:
            return current_state, False

        state = LockdownState(enabled=True, reason=reason)
        applied = self.cache.set(
            self._CACHE_KEY,
            orjson.dumps(state.as_response_data()),
            nx=True,
        )
        if applied:
            return state, True
        return self.get_state(), False

    def enable(self, reason: str | None = None) -> LockdownState:
        return self.set_state(LockdownState(enabled=True, reason=reason))

    def disable(self) -> LockdownState:
        if not self.cache.set(self._LAST_DISABLED_CACHE_KEY, time.time()):
            raise RuntimeError("Failed to record lockdown disable timestamp")
        return self.set_state(LockdownState())


lockdown_state_manager = LockdownStateManager()


def _publish_lockdown_state(state: LockdownState) -> None:
    message = orjson.dumps(
        {
            "event": "lockdown",
            "data": state.as_response_data(),
        }
    ).decode()
    try:
        ProviderManager().event_bus.publish(GLOBAL_BROADCAST_EVENT_CHANNEL, message)
    except Exception:  # the state transition is already committed.
        logger.exception("Failed to broadcast lockdown state")


def _cancel_pending_file_tasks() -> int:
    from include.database.models.files import FileTask
    from include.database.session import Session

    now = time.time()
    with Session.begin() as session:
        result = cast(
            CursorResult[Any],
            session.execute(
                update(FileTask)
                .where(FileTask.status == 0, FileTask.end_time >= now)
                .values(status=2)
            ),
        )
        return result.rowcount or 0


def apply_lockdown(
    status: bool,
    reason: str | None = None,
    *,
    only_if_inactive: bool = False,
) -> LockdownTransition:
    """Apply a lockdown transition and its shared operational side effects."""
    if not status and reason is not None:
        raise ValueError("A lockdown reason requires lockdown to be enabled")
    if not status and only_if_inactive:
        raise ValueError("only_if_inactive is only valid when enabling lockdown")

    cancelled_file_tasks = 0
    if status:
        if only_if_inactive:
            state, applied = lockdown_state_manager.enable_if_inactive(reason)
        else:
            state = lockdown_state_manager.enable(reason)
            applied = True

        if applied:
            cancelled_file_tasks = _cancel_pending_file_tasks()
    else:
        state = lockdown_state_manager.disable()
        applied = True

    if applied:
        _publish_lockdown_state(state)

    return LockdownTransition(
        state=state,
        applied=applied,
        cancelled_file_tasks=cancelled_file_tasks,
    )
