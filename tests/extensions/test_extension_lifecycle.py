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
    assert "ext_before_file_upload_commit" in hook_names
    assert "ext_post_file_upload_response" in hook_names
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
    builtin_extension.ext_before_file_upload_commit(session, "file", "path", "")
    builtin_extension.ext_post_file_upload_response("file", "path", "")

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
    builtin_extension.ext_before_file_upload_commit(session, "file", "path", "a" * 64)
    builtin_extension.ext_post_file_upload_response("file", "path", "a" * 64)

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


def test_builtin_lifecycle_owns_deduplication_worker(monkeypatch, builtin_extension):
    started = []
    stopped = []
    server = _FakeServer()
    monkeypatch.setattr(
        builtin_extension,
        "file_deduplication_worker",
        SimpleNamespace(
            start=lambda: started.append(True),
            stop=lambda: stopped.append(True),
        ),
    )

    builtin_extension.ext_on_startup(server)
    with pytest.raises(RuntimeError, match="already active"):
        builtin_extension.ext_on_startup(_FakeServer())
    builtin_extension.ext_on_shutdown()
    builtin_extension.ext_on_shutdown()

    assert started == [True]
    assert stopped == [True, True]


def test_builtin_startup_failure_cleans_worker_and_server_state(
    monkeypatch, builtin_extension
):
    stopped = []

    def fail_start():
        raise RuntimeError("worker failed")

    monkeypatch.setattr(
        builtin_extension,
        "file_deduplication_worker",
        SimpleNamespace(start=fail_start, stop=lambda: stopped.append(True)),
    )

    with pytest.raises(RuntimeError, match="worker failed"):
        builtin_extension.ext_on_startup(_FakeServer())

    monkeypatch.setattr(
        builtin_extension,
        "file_deduplication_worker",
        SimpleNamespace(start=lambda: None, stop=lambda: stopped.append(True)),
    )
    builtin_extension.ext_on_startup(_FakeServer())
    builtin_extension.ext_on_shutdown()

    assert stopped == [True, True]


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
