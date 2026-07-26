from pathlib import Path
from types import SimpleNamespace

import pluggy
import pytest

from include.domains.access.permissions import Permissions
from include.extensions import manager as extension_manager


@pytest.fixture
def builtin_extension(monkeypatch, protected_test_config):
    monkeypatch.chdir(Path(__file__).parents[1] / "src")
    from include.extensions.builtin import _extension

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
    assert "ext_on_server_start" not in hook_names
    assert "ext_on_server_stop" not in hook_names


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
