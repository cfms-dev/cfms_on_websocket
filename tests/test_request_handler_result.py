from pathlib import Path
from shutil import copyfile
from types import SimpleNamespace

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def _prepare_config(monkeypatch, tmp_path):
    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)


def test_log_handler_result_maps_all_audit_fields(monkeypatch, tmp_path):
    _prepare_config(monkeypatch, tmp_path)

    from include.transport import router
    from include.transport.request_handler import Result

    calls = []

    def fake_log_audit(
        action,
        result,
        username=None,
        target=None,
        data=None,
        remote_address=None,
    ):
        calls.append(
            {
                "action": action,
                "result": result,
                "username": username,
                "target": target,
                "data": data,
                "remote_address": remote_address,
            }
        )

    monkeypatch.setattr(router, "log_audit", fake_log_audit)

    router._log_handler_result(
        "sample_action",
        Result(
            code=207,
            target="target-id",
            data={"changed": True},
            username="actor",
        ),
        "203.0.113.10",
    )

    assert calls == [
        {
            "action": "sample_action",
            "result": 207,
            "username": "actor",
            "target": "target-id",
            "data": {"changed": True},
            "remote_address": "203.0.113.10",
        }
    ]


def test_login_throttled_response_returns_result(monkeypatch, tmp_path):
    _prepare_config(monkeypatch, tmp_path)

    from include.domains.identity.handlers import auth
    from include.domains.identity.handlers.auth import RequestLoginHandler
    from include.transport.request_handler import Result

    responses = []
    handler = SimpleNamespace(
        data={"username": "alice", "password": "secret"},
        stream=SimpleNamespace(connection=SimpleNamespace(_ws=object())),
        conclude_request=lambda **kwargs: responses.append(kwargs),
    )

    monkeypatch.setattr(auth, "get_client_ip", lambda _websocket: "127.0.0.1")
    monkeypatch.setattr(auth.LoginGuard, "check_access", lambda *_args: False)

    result = RequestLoginHandler().handle(handler)

    assert result == Result(code=429, target="alice")
    assert responses == [
        {
            "code": 429,
            "data": {},
            "message": "Too many login attempts. Please try again later.",
        }
    ]
