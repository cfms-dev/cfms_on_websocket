import pytest

from include.domains.operations.lockdown import (
    LockdownState,
    LockdownStateManager,
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


def test_unlocked_state_rejects_a_reason() -> None:
    with pytest.raises(ValueError, match="reason requires lockdown"):
        LockdownState(reason="Invalid")
