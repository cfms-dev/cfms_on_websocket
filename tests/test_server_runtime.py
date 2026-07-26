import pytest

from include.extensions import manager as extension_manager
from include.transport.server_runtime import ServerRuntime


class _FakeServer:
    def __init__(self, serve_error: Exception | None = None):
        self.serve_error = serve_error
        self.served = False
        self.shutdown_calls = 0

    def serve_forever(self):
        self.served = True
        if self.serve_error is not None:
            raise self.serve_error

    def shutdown(self):
        self.shutdown_calls += 1


def test_server_runtime_binds_and_requests_shutdown():
    runtime = ServerRuntime()
    server = _FakeServer()

    assert runtime.request_shutdown() is False
    with runtime.bind(server):
        assert runtime.request_shutdown() is True
    assert runtime.request_shutdown() is False
    assert server.shutdown_calls == 1


def test_server_runtime_rejects_nested_bindings():
    runtime = ServerRuntime()

    with runtime.bind(_FakeServer()):
        with pytest.raises(RuntimeError, match="already bound"):
            with runtime.bind(_FakeServer()):
                pass


@pytest.mark.parametrize("serve_error", [None, RuntimeError("serve failed")])
def test_server_extension_lifecycle_always_stops(serve_error):
    calls = []
    runtime = ServerRuntime()
    server = _FakeServer(serve_error)

    if serve_error is None:
        runtime.serve(
            server,
            lambda: calls.append("start"),
            lambda: calls.append("stop"),
        )
    else:
        with pytest.raises(RuntimeError, match="serve failed"):
            runtime.serve(
                server,
                lambda: calls.append("start"),
                lambda: calls.append("stop"),
            )

    assert server.served is True
    assert calls == ["start", "stop"]
    assert runtime.request_shutdown() is False


def test_server_extension_stop_runs_when_start_fails():
    calls = []

    def fail_start():
        calls.append("start")
        raise RuntimeError("start failed")

    runtime = ServerRuntime()

    with pytest.raises(RuntimeError, match="start failed"):
        runtime.serve(
            _FakeServer(),
            fail_start,
            lambda: calls.append("stop"),
        )

    assert calls == ["start", "stop"]
    assert runtime.request_shutdown() is False


def test_lifecycle_hooks_are_part_of_the_extension_contract():
    hook_names = {
        name for name, _method in extension_manager.ServerHookSpecs.__dict__.items()
    }

    assert "ext_on_server_start" in hook_names
    assert "ext_on_server_stop" in hook_names
