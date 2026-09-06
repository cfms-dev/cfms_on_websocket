from pathlib import Path
from types import SimpleNamespace

import pluggy
import pytest

from include.domains.access.permissions import Permissions
from include.extensions import manager as extension_manager


@pytest.fixture
def builtin_extension(monkeypatch, protected_test_config):
    monkeypatch.chdir(Path(__file__).parents[2] / "src")
    from include.extensions.builtin import _extension

    monkeypatch.setattr(
        _extension,
        "file_deduplication_worker",
        SimpleNamespace(start=lambda: None, stop=lambda: None),
    )
    yield _extension
    _extension.ext_on_shutdown()
    _extension.global_config.stop()


class _FakeServer:
    def __init__(self):
        self.shutdown_calls = 0

    def shutdown(self):
        self.shutdown_calls += 1


class _FakeConnectionHandler:
    username = "admin"

    def __init__(self):
        self.responses = []

    def conclude_request(self, code, data, message):
        self.responses.append((code, data, message))


def test_lifecycle_hooks_are_part_of_the_extension_contract():
    hook_names = set(extension_manager.ServerHookSpecs.__dict__)

    assert "ext_on_startup" in hook_names
    assert "ext_on_shutdown" in hook_names
    assert "ext_before_file_upload_finalize" in hook_names
    assert "ext_on_file_upload_completed" in hook_names
    assert "ext_on_server_start" not in hook_names
    assert "ext_on_server_stop" not in hook_names


def test_builtin_deduplication_hooks_ignore_uploads_without_digest(
    monkeypatch, builtin_extension
):
    scheduled = []
    released = []
    monkeypatch.setattr(
        builtin_extension,
        "schedule_file_deduplication",
        lambda session, file_id: scheduled.append((session, file_id)),
    )
    monkeypatch.setattr(
        builtin_extension,
        "release_file_deduplication",
        lambda file_id: released.append(file_id),
    )

    session = object()
    builtin_extension.ext_before_file_upload_finalize(session, "file", "path", "")
    builtin_extension.ext_on_file_upload_completed("file", "path", "")

    assert scheduled == []
    assert released == []


def test_builtin_deduplication_hooks_schedule_and_release(
    monkeypatch, builtin_extension
):
    scheduled = []
    released = []
    monkeypatch.setattr(
        builtin_extension,
        "schedule_file_deduplication",
        lambda session, file_id: scheduled.append((session, file_id)),
    )
    monkeypatch.setattr(
        builtin_extension,
        "release_file_deduplication",
        lambda file_id: released.append(file_id),
    )

    session = object()
    builtin_extension.ext_before_file_upload_finalize(session, "file", "path", "a" * 64)
    builtin_extension.ext_on_file_upload_completed("file", "path", "a" * 64)

    assert scheduled == [(session, "file")]
    assert released == ["file"]


def test_startup_hook_server_argument_is_optional_for_implementations():
    calls = []
    server = _FakeServer()
    plugin_manager = pluggy.PluginManager("cfms")
    plugin_manager.add_hookspecs(extension_manager.ServerHookSpecs)

    class ServerAwareExtension:
        @extension_manager.hookimpl
        def ext_on_startup(self, server):
            calls.append(server)

    class ServerAgnosticExtension:
        @extension_manager.hookimpl
        def ext_on_startup(self):
            calls.append("started")

    plugin_manager.register(ServerAwareExtension())
    plugin_manager.register(ServerAgnosticExtension())
    plugin_manager.hook.ext_on_startup(server=server)

    assert len(calls) == 2
    assert "started" in calls
    assert server in calls


def test_core_scheduling_wraps_extension_lifecycle(monkeypatch, protected_test_config):
    monkeypatch.chdir(Path(__file__).parents[2] / "src")
    import main as server_main

    events = []
    registry = object()
    provider = SimpleNamespace(
        start=lambda received: events.append(("scheduling_start", received)),
        shutdown=lambda: events.append("scheduling_shutdown"),
    )
    hook = SimpleNamespace(
        ext_on_startup=lambda *, server: events.append(("extensions_start", server)),
        ext_on_shutdown=lambda: events.append("extensions_shutdown"),
    )
    monkeypatch.setattr(server_main, "pm", SimpleNamespace(hook=hook))
    monkeypatch.setattr(
        server_main,
        "ProviderManager",
        lambda: SimpleNamespace(scheduling=provider),
    )
    monkeypatch.setattr(server_main, "collect_scheduled_tasks", lambda: registry)
    server = _FakeServer()

    with server_main._server_lifecycle(server):
        events.append("serving")

    assert events == [
        ("extensions_start", server),
        ("scheduling_start", registry),
        "serving",
        "scheduling_shutdown",
        "extensions_shutdown",
    ]


def test_core_lifecycle_cleans_up_when_scheduling_start_fails(
    monkeypatch, protected_test_config
):
    monkeypatch.chdir(Path(__file__).parents[2] / "src")
    import main as server_main

    events = []

    def fail_start(_registry):
        events.append("scheduling_start")
        raise RuntimeError("scheduling failed")

    provider = SimpleNamespace(
        start=fail_start,
        shutdown=lambda: events.append("scheduling_shutdown"),
    )
    hook = SimpleNamespace(
        ext_on_startup=lambda *, server: events.append("extensions_start"),
        ext_on_shutdown=lambda: events.append("extensions_shutdown"),
    )
    monkeypatch.setattr(server_main, "pm", SimpleNamespace(hook=hook))
    monkeypatch.setattr(
        server_main,
        "ProviderManager",
        lambda: SimpleNamespace(scheduling=provider),
    )
    monkeypatch.setattr(server_main, "collect_scheduled_tasks", object)

    with pytest.raises(RuntimeError, match="scheduling failed"):
        with server_main._server_lifecycle(_FakeServer()):
            pytest.fail("the serving phase must not start")

    assert events == [
        "extensions_start",
        "scheduling_start",
        "scheduling_shutdown",
        "extensions_shutdown",
    ]


def test_builtin_lifecycle_owns_event_driven_worker(monkeypatch, builtin_extension):
    started = []
    stopped = []
    server = _FakeServer()
    monkeypatch.setattr(
        builtin_extension,
        "file_deduplication_worker",
        SimpleNamespace(
            start=lambda: started.append("deduplication"),
            stop=lambda: stopped.append("deduplication"),
        ),
    )
    builtin_extension.ext_on_startup(server)
    with pytest.raises(RuntimeError, match="already active"):
        builtin_extension.ext_on_startup(_FakeServer())
    builtin_extension.ext_on_shutdown()
    builtin_extension.ext_on_shutdown()

    assert started == ["deduplication"]
    assert stopped == ["deduplication", "deduplication"]


def test_builtin_registers_all_system_tasks(builtin_extension):
    assert {
        registration.name
        for registration in builtin_extension.ext_register_scheduled_tasks()
    } == {
        "builtin.permission_cleanup",
        "builtin.upload_cleanup",
        "builtin.auth_throttle_cleanup",
        "builtin.creation_risk_cleanup",
        "builtin.download_risk_cleanup",
    }


def test_scheduling_extension_only_exposes_management_interfaces():
    from include.extensions.scheduling import _extension

    assert set(_extension.ext_register_handlers()) == {
        "list_scheduled_task_types",
        "create_schedule",
        "get_schedule",
        "list_schedules",
        "update_schedule",
        "delete_schedule",
    }
    assert _extension.ext_register_extension_flags() == {"scheduling"}
    assert not hasattr(_extension, "ext_on_startup")
    assert not hasattr(_extension, "ext_on_shutdown")
    assert not hasattr(_extension, "ext_register_scheduled_tasks")


def test_builtin_startup_failure_cleans_worker_and_server_state(
    monkeypatch, builtin_extension
):
    started = []
    stopped = []

    def fail_start():
        raise RuntimeError("worker failed")

    monkeypatch.setattr(
        builtin_extension,
        "file_deduplication_worker",
        SimpleNamespace(
            start=fail_start,
            stop=lambda: stopped.append("deduplication"),
        ),
    )

    with pytest.raises(RuntimeError, match="worker failed"):
        builtin_extension.ext_on_startup(_FakeServer())

    monkeypatch.setattr(
        builtin_extension,
        "file_deduplication_worker",
        SimpleNamespace(
            start=lambda: started.append("deduplication"),
            stop=lambda: stopped.append("deduplication"),
        ),
    )
    builtin_extension.ext_on_startup(_FakeServer())
    builtin_extension.ext_on_shutdown()

    assert started == ["deduplication"]
    assert stopped == ["deduplication", "deduplication"]


def test_builtin_shutdown_handler_stops_active_server(monkeypatch, builtin_extension):
    server = _FakeServer()
    handler = _FakeConnectionHandler()
    user = SimpleNamespace(all_permissions={Permissions.SHUTDOWN})

    monkeypatch.setattr(
        builtin_extension.User,
        "get_existing",
        lambda _session, _username: user,
    )

    builtin_extension.ext_on_startup(server)
    try:
        builtin_extension.RequestShutdownHandler().handle(handler)
    finally:
        builtin_extension.ext_on_shutdown()

    assert handler.responses == [(200, {}, "Server is shutting down")]
    assert server.shutdown_calls == 1


def test_builtin_shutdown_lifecycle_releases_server(builtin_extension):
    first_server = _FakeServer()
    second_server = _FakeServer()

    builtin_extension.ext_on_startup(first_server)
    with pytest.raises(RuntimeError, match="already active"):
        builtin_extension.ext_on_startup(second_server)

    builtin_extension.ext_on_shutdown()
    builtin_extension.ext_on_startup(second_server)
    builtin_extension.ext_on_shutdown()
