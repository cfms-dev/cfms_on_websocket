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
    from include.domains.security.guards.login import (
        ThrottleDecision,
        ThrottleScope,
    )
    from include.transport.request_handler import Result

    responses = []
    handler = SimpleNamespace(
        data={"username": "alice", "password": "secret"},
        stream=SimpleNamespace(connection=SimpleNamespace(_ws=object())),
        conclude_request=lambda **kwargs: responses.append(kwargs),
    )

    monkeypatch.setattr(auth, "get_client_ip", lambda _websocket: "127.0.0.1")
    monkeypatch.setattr(
        auth.LoginGuard,
        "evaluate",
        lambda *_args: ThrottleDecision(
            False, ThrottleScope.ACCOUNT, retry_after_seconds=30
        ),
    )

    result = RequestLoginHandler().handle(handler)

    assert result == Result(code=429, target="alice")
    assert responses == [
        {
            "code": 429,
            "data": {"retry_after_seconds": 30},
            "message": "Too many authentication attempts. Please try again later.",
        }
    ]


def _throttled_decision():
    from include.domains.security.guards.login import (
        ThrottleDecision,
        ThrottleScope,
    )

    return ThrottleDecision(False, ThrottleScope.ACCOUNT, retry_after_seconds=45)


def test_totp_validation_uses_authentication_throttle(monkeypatch, tmp_path):
    _prepare_config(monkeypatch, tmp_path)

    from include.domains.security.handlers import two_factor
    from include.domains.security.handlers.two_factor import RequestValidate2FAHandler

    responses = []
    handler = SimpleNamespace(
        username="alice",
        data={"token": "000000"},
        stream=SimpleNamespace(connection=SimpleNamespace(_ws=object())),
        conclude_request=lambda *args, **kwargs: responses.append((args, kwargs)),
    )
    monkeypatch.setattr(two_factor, "get_client_ip", lambda _websocket: "127.0.0.1")
    monkeypatch.setattr(
        two_factor.LoginGuard, "evaluate", lambda *_args: _throttled_decision()
    )

    result = RequestValidate2FAHandler().handle(handler)

    assert result.code == 429
    assert responses == [
        (
            (
                429,
                {"retry_after_seconds": 45},
                "Too many authentication attempts. Please try again later.",
            ),
            {},
        )
    ]


def test_disable_2fa_password_check_uses_authentication_throttle(monkeypatch, tmp_path):
    _prepare_config(monkeypatch, tmp_path)

    from include.domains.security.handlers import two_factor
    from include.domains.security.handlers.two_factor import RequestDisable2FAHandler

    responses = []
    handler = SimpleNamespace(
        username="alice",
        data={"password": "wrong"},
        stream=SimpleNamespace(connection=SimpleNamespace(_ws=object())),
        conclude_request=lambda *args, **kwargs: responses.append((args, kwargs)),
    )
    monkeypatch.setattr(two_factor, "get_client_ip", lambda _websocket: "127.0.0.1")
    monkeypatch.setattr(
        two_factor.LoginGuard, "evaluate", lambda *_args: _throttled_decision()
    )

    result = RequestDisable2FAHandler().handle(handler)

    assert result.code == 429
    assert responses[0][0][0] == 429
    assert responses[0][0][1] == {"retry_after_seconds": 45}


def test_password_change_uses_authentication_throttle(monkeypatch, tmp_path):
    _prepare_config(monkeypatch, tmp_path)

    from include.domains.identity.handlers import users
    from include.domains.identity.handlers.users import RequestSetPasswdHandler

    responses = []
    handler = SimpleNamespace(
        username="",
        token="",
        data={
            "username": "alice",
            "old_passwd": "wrong",
            "new_passwd": "NewPassword123!",
        },
        stream=SimpleNamespace(connection=SimpleNamespace(_ws=object())),
        conclude_request=lambda *args, **kwargs: responses.append((args, kwargs)),
    )
    monkeypatch.setattr(users, "get_client_ip", lambda _websocket: "127.0.0.1")
    monkeypatch.setattr(
        users.LoginGuard, "evaluate", lambda *_args: _throttled_decision()
    )

    result = RequestSetPasswdHandler().handle(handler)

    assert result.code == 429
    assert responses[0][0][0] == 429
    assert responses[0][0][1] == {"retry_after_seconds": 45}
