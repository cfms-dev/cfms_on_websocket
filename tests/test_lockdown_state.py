from concurrent.futures import ThreadPoolExecutor

import pytest

from include.domains.operations import lockdown
from include.domains.operations.lockdown import (
    LockdownState,
    LockdownStateManager,
    apply_lockdown,
)
from include.providers.caching.memory import MemoryCachingProvider


def test_lockdown_reason_is_replaced_with_each_lockdown() -> None:
    manager = LockdownStateManager(MemoryCachingProvider())

    manager.enable("First maintenance window")
    assert manager.get_state() == LockdownState(
        enabled=True, reason="First maintenance window"
    )

    manager.disable()
    assert manager.get_state() == LockdownState()

    manager.enable()
    assert manager.get_state() == LockdownState(enabled=True)


def test_lockdown_state_reads_legacy_enabled_flag() -> None:
    cache = MemoryCachingProvider()
    cache.set("system:lockdown", "1")

    assert LockdownStateManager(cache).get_state() == LockdownState(enabled=True)


def test_invalid_cached_state_fails_closed() -> None:
    cache = MemoryCachingProvider()
    cache.set(LockdownStateManager._CACHE_KEY, b"invalid")
    manager = LockdownStateManager(cache)

    assert manager.get_state() == LockdownState(enabled=True)


def test_unlocked_state_rejects_a_reason() -> None:
    with pytest.raises(ValueError, match="reason requires lockdown"):
        LockdownState(reason="Invalid")


def test_enable_if_inactive_preserves_existing_reason() -> None:
    manager = LockdownStateManager(MemoryCachingProvider())

    initial_state, initial_applied = manager.enable_if_inactive("Automatic")
    existing_state, existing_applied = manager.enable_if_inactive("Replacement")

    assert initial_applied is True
    assert initial_state == LockdownState(enabled=True, reason="Automatic")
    assert existing_applied is False
    assert existing_state == initial_state


def test_enable_if_inactive_has_single_concurrent_winner() -> None:
    manager = LockdownStateManager(MemoryCachingProvider())

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(
            executor.map(
                lambda reason: manager.enable_if_inactive(reason),
                [f"reason-{index}" for index in range(16)],
            )
        )

    assert sum(applied for _state, applied in results) == 1
    winning_states = [state for state, applied in results if applied]
    assert manager.get_state() == winning_states[0]


def test_apply_lockdown_runs_shared_side_effects_once(monkeypatch) -> None:
    manager = LockdownStateManager(MemoryCachingProvider())
    broadcasts = []
    cancellations = []
    monkeypatch.setattr(lockdown, "lockdown_state_manager", manager)
    monkeypatch.setattr(
        lockdown,
        "_cancel_pending_file_tasks",
        lambda: cancellations.append(True) or 3,
    )
    monkeypatch.setattr(
        lockdown,
        "_publish_lockdown_state",
        lambda state: broadcasts.append(state),
    )

    first = apply_lockdown(True, "Automatic", only_if_inactive=True)
    second = apply_lockdown(True, "Replacement", only_if_inactive=True)

    assert first.applied is True
    assert first.cancelled_file_tasks == 3
    assert second.applied is False
    assert second.state.reason == "Automatic"
    assert cancellations == [True]
    assert broadcasts == [LockdownState(enabled=True, reason="Automatic")]


def test_apply_lockdown_disable_broadcasts_unlocked_state(monkeypatch) -> None:
    manager = LockdownStateManager(MemoryCachingProvider())
    manager.enable("Manual")
    broadcasts = []
    monkeypatch.setattr(lockdown, "lockdown_state_manager", manager)
    monkeypatch.setattr(
        lockdown,
        "_publish_lockdown_state",
        lambda state: broadcasts.append(state),
    )

    transition = apply_lockdown(False)

    assert transition.state == LockdownState()
    assert transition.applied is True
    assert broadcasts == [LockdownState()]


def test_disable_records_timestamp_before_clearing_lockdown(monkeypatch) -> None:
    class ObservingCache(MemoryCachingProvider):
        reset_marker_at_delete = None

        def delete(self, key: str) -> None:
            if key == LockdownStateManager._CACHE_KEY:
                self.reset_marker_at_delete = self.get(
                    LockdownStateManager._LAST_DISABLED_CACHE_KEY
                )
            super().delete(key)

    cache = ObservingCache()
    manager = LockdownStateManager(cache)
    manager.enable("Automatic")
    monkeypatch.setattr(lockdown.time, "time", lambda: 1234.5)

    manager.disable()

    assert cache.reset_marker_at_delete == 1234.5
    assert manager.get_last_disabled_at() == 1234.5
    assert manager.get_state() == LockdownState()
