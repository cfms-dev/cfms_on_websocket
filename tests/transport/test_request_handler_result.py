from pathlib import Path
from shutil import copyfile
from types import SimpleNamespace

import pytest

PROJECT_ROOT = Path(__file__).resolve().parents[2]


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


def test_router_returns_429_before_constructing_rate_limited_handler(
    monkeypatch, tmp_path
):
    _prepare_config(monkeypatch, tmp_path)

    from include.domains.security.guards.request_rate_control import (
        RequestRateControlDecision,
    )
    from include.transport import router

    responses = []

    class FakeConnectionHandler:
        def __init__(self, stream):
            self.stream = stream
            self.action = "limited_action"
            self.data = {}
            self.username = ""
            self.token = ""

        def conclude_request(self, code, data, message):
            responses.append((code, data, message))

    class LimitedHandler:
        rate_limit_cost = 4

        def __init__(self):
            raise AssertionError("A denied handler must not be constructed")

    monkeypatch.setattr(router, "ConnectionHandler", FakeConnectionHandler)
    monkeypatch.setattr(router, "get_client_ip", lambda _websocket: "192.0.2.10")
    monkeypatch.setattr(
        router.LoginGuard,
        "evaluate_subnet_access",
        lambda _ip: SimpleNamespace(allowed=True),
    )
    monkeypatch.setitem(router.available_functions, "limited_action", LimitedHandler)
    monkeypatch.setattr(
        router,
        "check_request_rate",
        lambda *args, **kwargs: RequestRateControlDecision(
            False,
            would_block=True,
            scope="ip",
            limit=12,
            retry_after_seconds=7,
        ),
    )
    stream = SimpleNamespace(connection=SimpleNamespace(_ws=object()))

    router.handle_request(stream)

    assert responses == [
        (
            429,
            {"scope": "ip", "limit": 12, "retry_after_seconds": 7},
            "Too many requests. Please try again later.",
        )
    ]


def test_router_reports_pydantic_request_validation_errors(monkeypatch, tmp_path):
    _prepare_config(monkeypatch, tmp_path)

    from include.transport import router
    from include.transport.request_handler import RequestDataModel

    responses = []

    class InvalidRequest(RequestDataModel):
        value: int

    class PydanticHandler:
        request_model = InvalidRequest
        require_auth = False
        rate_limit_cost = 1

        def handle(self, _handler):
            raise AssertionError("Invalid requests must not reach the handler")

    class FakeConnectionHandler:
        def __init__(self, stream):
            self.stream = stream
            self.action = "pydantic_action"
            self.data = {"value": "1"}
            self.username = ""
            self.token = ""
            self.remote_address = "192.0.2.10"

        def conclude_request(self, code, data, message):
            responses.append((code, data, message))

    monkeypatch.setattr(router, "ConnectionHandler", FakeConnectionHandler)
    monkeypatch.setattr(router, "get_client_ip", lambda _websocket: "192.0.2.10")
    monkeypatch.setattr(
        router.LoginGuard,
        "evaluate_subnet_access",
        lambda _ip: SimpleNamespace(allowed=True),
    )
    monkeypatch.setattr(
        router,
        "check_request_rate",
        lambda *_args, **_kwargs: SimpleNamespace(allowed=True),
    )
    monkeypatch.setattr(
        router.lockdown_state_manager,
        "get_state",
        lambda: SimpleNamespace(enabled=False),
    )
    monkeypatch.setitem(router.available_functions, "pydantic_action", PydanticHandler)
    stream = SimpleNamespace(connection=SimpleNamespace(_ws=object()))

    router.handle_request(stream)

    assert responses == [
        (
            400,
            {"validator": "int_type", "validator_value": None},
            "value: Input should be a valid integer",
        )
    ]


def test_router_keeps_validated_request_data_as_the_original_dict(
    monkeypatch, tmp_path
):
    _prepare_config(monkeypatch, tmp_path)

    from include.transport import router
    from include.transport.request_handler import RequestDataModel

    request_data = {"value": 1}
    handled_data = []

    class ValidRequest(RequestDataModel):
        value: int

    class PydanticHandler:
        request_model = ValidRequest
        require_auth = False
        rate_limit_cost = 1

        def handle(self, handler):
            handled_data.append(handler.data)

    class FakeConnectionHandler:
        def __init__(self, stream):
            self.stream = stream
            self.action = "pydantic_action"
            self.data = request_data
            self.username = ""
            self.token = ""
            self.remote_address = "192.0.2.10"

    hook = SimpleNamespace(
        ext_before_request=lambda **_kwargs: None,
        ext_post_request=lambda **_kwargs: None,
    )
    monkeypatch.setattr(router, "ConnectionHandler", FakeConnectionHandler)
    monkeypatch.setattr(router, "get_client_ip", lambda _websocket: "192.0.2.10")
    monkeypatch.setattr(
        router.LoginGuard,
        "evaluate_subnet_access",
        lambda _ip: SimpleNamespace(allowed=True),
    )
    monkeypatch.setattr(
        router,
        "check_request_rate",
        lambda *_args, **_kwargs: SimpleNamespace(allowed=True),
    )
    monkeypatch.setattr(
        router.lockdown_state_manager,
        "get_state",
        lambda: SimpleNamespace(enabled=False),
    )
    monkeypatch.setattr(router, "pm", SimpleNamespace(hook=hook))
    monkeypatch.setitem(router.available_functions, "pydantic_action", PydanticHandler)
    stream = SimpleNamespace(connection=SimpleNamespace(_ws=object()))

    router.handle_request(stream)

    assert handled_data == [request_data]
    assert handled_data[0] is request_data


def test_request_admission_is_released_when_handler_raises(monkeypatch, tmp_path):
    _prepare_config(monkeypatch, tmp_path)

    from include.transport import router

    released = []
    connection = object()
    stream = SimpleNamespace(connection=connection)
    monkeypatch.setattr(
        router,
        "handle_request",
        lambda _stream: (_ for _ in ()).throw(RuntimeError("failure")),
    )
    monkeypatch.setattr(
        router.admission_controller,
        "release_request",
        lambda released_connection: released.append(released_connection),
    )

    with pytest.raises(RuntimeError, match="failure"):
        router._handle_request_with_admission(stream)

    assert released == [connection]


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


def test_totp_setup_validation_does_not_use_authentication_throttle(
    monkeypatch, tmp_path
):
    _prepare_config(monkeypatch, tmp_path)

    from include.domains.security.handlers import two_factor
    from include.domains.security.handlers.two_factor import RequestValidate2FAHandler

    class FakeUser:
        totp_secret = "secret"
        totp_enabled = False
        valid_token = False

        def verify_totp(self, _token):
            return self.valid_token

        def enable_totp(self):
            self.totp_enabled = True

    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, _model, _username):
            return user

    def unexpected_throttle_call(*_args, **_kwargs):
        raise AssertionError(
            "2FA setup validation must not use authentication throttle"
        )

    user = FakeUser()
    responses = []
    handler = SimpleNamespace(
        username="alice",
        data={"token": "000000"},
        conclude_request=lambda *args, **kwargs: responses.append((args, kwargs)),
    )
    monkeypatch.setattr(two_factor, "Session", FakeSession)
    monkeypatch.setattr(two_factor, "get_client_ip", unexpected_throttle_call)
    monkeypatch.setattr(two_factor.LoginGuard, "evaluate", unexpected_throttle_call)
    monkeypatch.setattr(
        two_factor.LoginGuard, "report_failure", unexpected_throttle_call
    )
    monkeypatch.setattr(
        two_factor.LoginGuard, "report_success", unexpected_throttle_call
    )

    result = RequestValidate2FAHandler().handle(handler)

    assert result.code == 401
    assert responses == [((401, {}, "Invalid verification code"), {})]

    user.valid_token = True
    user.totp_enabled = False
    responses.clear()

    result = RequestValidate2FAHandler().handle(handler)

    assert result.code == 0
    assert responses == [
        (
            (),
            {
                "code": 200,
                "message": "Two-factor authentication enabled successfully",
                "data": {"method": "totp"},
            },
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
