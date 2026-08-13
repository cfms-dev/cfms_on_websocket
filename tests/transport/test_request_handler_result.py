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


def test_router_closes_multiplexer_with_policy_violation_for_denied_ip(
    monkeypatch, tmp_path
):
    _prepare_config(monkeypatch, tmp_path)

    from include.transport import router

    close_calls = []

    class FakeConnection:
        _ws = object()

        def close(self, *args, **kwargs):
            close_calls.append((args, kwargs))

    class FakeStream:
        connection = FakeConnection()

        def send(self, data, frame_type):
            pass

    monkeypatch.setattr(router, "get_client_ip", lambda _websocket: "192.0.2.10")
    monkeypatch.setattr(
        router.LoginGuard,
        "evaluate_subnet_access",
        lambda _ip: SimpleNamespace(allowed=False),
    )

    router.handle_request(FakeStream())

    assert close_calls == [
        ((), {"code": 1008, "reason": "IP address is not permitted"})
    ]


def test_connection_handler_closes_websocket_before_post_disconnect(
    monkeypatch, tmp_path
):
    _prepare_config(monkeypatch, tmp_path)

    from include.transport import router

    events = []

    class FakeWebSocket:
        remote_address = ("192.0.2.10", 12345)
        disconnected = False

        def close(self, *, code=1000, reason=""):
            events.append(("websocket_close", code, reason))
            self.disconnected = True

    class FakeMultiplexer:
        def __init__(self, websocket, *, max_pending_inbound_streams):
            self.websocket = websocket
            self.close_code = 1000
            self.close_reason = ""
            self.close_started = False

        def accept_stream(self):
            self.close(code=1013, reason="inbound overload")
            return None

        def close(self, code=1000, reason=""):
            if self.close_started:
                return
            self.close_started = True
            self.close_code = code
            self.close_reason = reason
            events.append(("logical_close", code, reason))

    class FakeHooks:
        def ext_on_connect(self, *, websocket):
            events.append(("on_connect",))

        def ext_post_disconnect(self):
            assert websocket.disconnected
            events.append(("post_disconnect",))

    class FakeAdmissionController:
        def acquire_connection(self, _ip):
            return SimpleNamespace(allowed=True)

        def release_connection(self, _ip):
            assert websocket.disconnected
            events.append(("release_connection",))

    websocket = FakeWebSocket()
    monkeypatch.setattr(router, "get_client_ip", lambda _websocket: "192.0.2.10")
    monkeypatch.setattr(router, "get_client_cert_subject", lambda _websocket: None)
    monkeypatch.setattr(router, "MultiplexedConnection", FakeMultiplexer)
    monkeypatch.setattr(
        router.AdmissionControlPolicy,
        "from_config",
        lambda: SimpleNamespace(max_pending_streams_per_connection=16),
    )
    monkeypatch.setattr(router, "admission_controller", FakeAdmissionController())
    monkeypatch.setattr(router, "pm", SimpleNamespace(hook=FakeHooks()))

    router.handle_connection(websocket)

    assert events == [
        ("on_connect",),
        ("logical_close", 1013, "inbound overload"),
        ("websocket_close", 1013, "inbound overload"),
        ("post_disconnect",),
        ("release_connection",),
    ]


def test_router_reports_safe_pydantic_request_validation_errors(monkeypatch, tmp_path):
    _prepare_config(monkeypatch, tmp_path)

    import orjson
    from pydantic import Field, field_validator

    from include.transport import router
    from include.transport.connection import send_conclusion
    from include.transport.multiplexing import FrameType
    from include.transport.request_handler import RequestDataModel

    sent_frames = []

    class NestedRequest(RequestDataModel):
        secret: int
        count: int = Field(gt=10)
        label: str

        @field_validator("label")
        @classmethod
        def reject_label(cls, _value: str) -> str:
            raise ValueError("label is reserved")

    class InvalidRequest(RequestDataModel):
        item: NestedRequest

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
            self.data = {
                "item": {
                    "secret": "correct-horse-battery-staple",
                    "count": 1,
                    "label": "private-label",
                },
                "extra": "private-extra",
            }
            self.username = ""
            self.token = ""
            self.remote_address = "192.0.2.10"

        def conclude_request(self, code, data, message):
            send_conclusion(self.stream, code, data, message)

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
    stream = SimpleNamespace(
        connection=SimpleNamespace(_ws=object()),
        send=lambda data, frame_type: sent_frames.append((data, frame_type)),
    )

    router.handle_request(stream)

    assert len(sent_frames) == 1
    response_data, frame_type = sent_frames[0]
    assert frame_type is FrameType.CONCLUSION
    assert b"correct-horse-battery-staple" not in response_data
    assert b"private-label" not in response_data
    assert b"private-extra" not in response_data

    response = orjson.loads(response_data)
    assert isinstance(response.pop("timestamp"), float)
    assert response == {
        "code": 400,
        "data": {
            "errors": [
                {
                    "type": "int_type",
                    "loc": ["item", "secret"],
                    "msg": "Input should be a valid integer",
                },
                {
                    "type": "greater_than",
                    "loc": ["item", "count"],
                    "msg": "Input should be greater than 10",
                },
                {
                    "type": "value_error",
                    "loc": ["item", "label"],
                    "msg": "Value error, label is reserved",
                },
                {
                    "type": "extra_forbidden",
                    "loc": ["extra"],
                    "msg": "Extra inputs are not permitted",
                },
            ]
        },
        "message": "Invalid request data",
    }


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


def test_disable_2fa_request_requires_a_credential(monkeypatch, tmp_path):
    _prepare_config(monkeypatch, tmp_path)

    from pydantic import ValidationError

    from include.domains.security.handlers.two_factor import RequestDisable2FAHandler

    RequestDisable2FAHandler.request_model.model_validate({"password": "secret"})

    with pytest.raises(ValidationError):
        RequestDisable2FAHandler.request_model.model_validate({})
    with pytest.raises(ValidationError):
        RequestDisable2FAHandler.request_model.model_validate({"password": None})


@pytest.mark.parametrize("old_passwd", ["", "wrong"])
def test_password_change_uses_authentication_throttle(
    monkeypatch, tmp_path, old_passwd
):
    _prepare_config(monkeypatch, tmp_path)

    from include.domains.identity.handlers import users
    from include.domains.identity.handlers.users import RequestSetPasswdHandler
    from include.transport.request_handler import Result

    responses = []
    handler = SimpleNamespace(
        username="",
        token="",
        data={
            "username": "alice",
            "old_passwd": old_passwd,
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

    assert result == Result(code=429, target="alice")
    assert responses == [
        (
            (),
            {
                "code": 429,
                "data": {"retry_after_seconds": 45},
                "message": "Too many authentication attempts. Please try again later.",
            },
        )
    ]


class _PasswordUser:
    def __init__(
        self,
        password,
        *,
        permissions=(),
        status=None,
        token_valid=True,
    ):
        self.password = password
        self.all_permissions = set(permissions)
        self.status = status
        self.token_valid = token_valid
        self.password_update = None

    def is_token_valid(self, _token):
        return self.token_valid

    def verify_password(self, password):
        return password == self.password

    def set_password(self, password, force_update_after_login=False):
        self.password = password
        self.password_update = (password, force_update_after_login)


class _PasswordSession:
    def __init__(self, users):
        self.users = users
        self.get_calls = []
        self.commit_count = 0

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return None

    def get(self, _model, username):
        self.get_calls.append(username)
        return self.users.get(username)

    def commit(self):
        self.commit_count += 1


def _password_request(data, *, username="", token=""):
    responses = []
    handler = SimpleNamespace(
        username=username,
        token=token,
        data=data,
        stream=SimpleNamespace(connection=SimpleNamespace(_ws=object())),
        conclude_request=lambda **kwargs: responses.append(kwargs),
    )
    return handler, responses


def _allow_password_authentication(monkeypatch, users):
    from include.domains.security.guards.login import ThrottleDecision

    monkeypatch.setattr(users, "get_client_ip", lambda _websocket: "127.0.0.1")
    monkeypatch.setattr(
        users.LoginGuard, "evaluate", lambda *_args: ThrottleDecision(True)
    )
    monkeypatch.setattr(users.LoginGuard, "report_failure", lambda *_args: None)
    monkeypatch.setattr(
        users.LoginGuard, "report_success", lambda *_args, **_kwargs: None
    )


def test_password_change_wrong_credentials_do_not_disclose_user_existence(
    monkeypatch, tmp_path
):
    _prepare_config(monkeypatch, tmp_path)

    from include.domains.identity.handlers import users
    from include.domains.identity.handlers.users import RequestSetPasswdHandler
    from include.transport.request_handler import Result

    _allow_password_authentication(monkeypatch, users)
    verified_users = []

    def verify(user, password):
        verified_users.append(user)
        return user is not None and user.verify_password(password)

    monkeypatch.setattr(users, "verify_password_or_dummy", verify)
    outcomes = []
    existing = _PasswordUser("correct-password")
    for target in (existing, None):
        session = _PasswordSession({"alice": target} if target else {})
        monkeypatch.setattr(users, "Session", lambda: session)
        handler, responses = _password_request(
            {
                "username": "alice",
                "old_passwd": "wrong-password",
                "new_passwd": "NewPassword123!",
                "bypass_passwd_requirements": True,
            }
        )

        result = RequestSetPasswdHandler().handle(handler)
        outcomes.append((result, responses, session.commit_count))

    expected_result = Result(code=401, target="alice")
    expected_response = {
        "code": 401,
        "data": {},
        "message": "Invalid credentials",
    }
    assert outcomes == [
        (expected_result, [expected_response], 0),
        (expected_result, [expected_response], 0),
    ]
    assert verified_users == [existing, None]


@pytest.mark.parametrize(
    ("operator", "token", "expected_code", "expected_message"),
    [
        (None, "", 400, "Operator is required when setting other user password"),
        (_PasswordUser("unused"), "", 400, "Given an operator, token is required"),
        (
            _PasswordUser("unused", token_valid=False),
            "token",
            401,
            "Invalid user or token",
        ),
        (
            _PasswordUser("unused"),
            "token",
            403,
            "You do not have permission to set user password",
        ),
    ],
)
def test_password_reset_rejects_unauthorized_operator_before_target_lookup(
    monkeypatch,
    tmp_path,
    operator,
    token,
    expected_code,
    expected_message,
):
    _prepare_config(monkeypatch, tmp_path)

    from include.domains.identity.handlers import users
    from include.domains.identity.handlers.users import RequestSetPasswdHandler

    operator_username = "operator" if operator is not None else ""
    records = {"operator": operator} if operator is not None else {}
    records["alice"] = _PasswordUser("old-password")
    session = _PasswordSession(records)
    monkeypatch.setattr(users, "Session", lambda: session)
    handler, responses = _password_request(
        {"username": "alice", "new_passwd": "NewPassword123!"},
        username=operator_username,
        token=token,
    )

    result = RequestSetPasswdHandler().handle(handler)

    assert result.code == expected_code
    assert result.target == "alice"
    assert result.username == ("operator" if expected_code == 403 else None)
    assert result.data is None
    assert responses == [
        {"code": expected_code, "data": {}, "message": expected_message}
    ]
    assert "alice" not in session.get_calls
    assert session.commit_count == 0


def test_password_reset_reports_missing_target_after_operator_authorization(
    monkeypatch, tmp_path
):
    _prepare_config(monkeypatch, tmp_path)

    from include.domains.access.permissions import Permissions
    from include.domains.identity.handlers import users
    from include.domains.identity.handlers.users import RequestSetPasswdHandler
    from include.transport.request_handler import Result

    operator = _PasswordUser("unused", permissions={Permissions.SUPER_SET_PASSWD})
    session = _PasswordSession({"operator": operator})
    monkeypatch.setattr(users, "Session", lambda: session)
    handler, responses = _password_request(
        {"username": "missing", "new_passwd": "NewPassword123!"},
        username="operator",
        token="token",
    )

    result = RequestSetPasswdHandler().handle(handler)

    assert result == Result(code=404, target="missing", username="operator")
    assert result.data is None
    assert responses == [{"code": 404, "data": {}, "message": "User does not exist"}]
    assert session.get_calls == ["operator", "missing"]
    assert session.commit_count == 0


def test_self_password_change_commits_and_attributes_audit_to_target(
    monkeypatch, tmp_path
):
    _prepare_config(monkeypatch, tmp_path)

    from include.database.models.identity import UserStatus
    from include.domains.access.permissions import Permissions
    from include.domains.identity.handlers import users
    from include.domains.identity.handlers.users import RequestSetPasswdHandler
    from include.transport.request_handler import Result

    _allow_password_authentication(monkeypatch, users)
    user = _PasswordUser(
        "OldPassword123!",
        permissions={Permissions.SET_PASSWD},
        status=UserStatus.ACTIVE,
    )
    session = _PasswordSession({"alice": user})
    monkeypatch.setattr(users, "Session", lambda: session)
    handler, responses = _password_request(
        {
            "username": "alice",
            "old_passwd": "OldPassword123!",
            "new_passwd": "NewPassword456!",
        }
    )

    result = RequestSetPasswdHandler().handle(handler)

    assert result == Result(code=200, target="alice", username="alice")
    assert result.data is None
    assert responses == [
        {"code": 200, "data": {}, "message": "Password set successfully"}
    ]
    assert user.password_update == ("NewPassword456!", False)
    assert session.commit_count == 1


def test_self_password_change_rejects_privileged_flags_after_authentication(
    monkeypatch, tmp_path
):
    _prepare_config(monkeypatch, tmp_path)

    from include.domains.identity.handlers import users
    from include.domains.identity.handlers.users import RequestSetPasswdHandler
    from include.transport.request_handler import Result

    _allow_password_authentication(monkeypatch, users)
    user = _PasswordUser("OldPassword123!")
    session = _PasswordSession({"alice": user})
    monkeypatch.setattr(users, "Session", lambda: session)
    handler, responses = _password_request(
        {
            "username": "alice",
            "old_passwd": "OldPassword123!",
            "new_passwd": "NewPassword456!",
            "bypass_passwd_requirements": True,
            "force_update_after_login": True,
        }
    )

    result = RequestSetPasswdHandler().handle(handler)

    assert result == Result(code=400, target="alice", username="alice")
    assert result.data is None
    assert responses == [
        {
            "code": 400,
            "data": {
                "bypass_passwd_requirements": True,
                "force_update_after_login": True,
            },
            "message": (
                "The following options cannot be set to True when changing your "
                "own password: bypass_passwd_requirements, force_update_after_login"
            ),
        }
    ]
    assert user.password_update is None
    assert session.commit_count == 0


def test_privileged_password_reset_can_bypass_policy_and_force_expiration(
    monkeypatch, tmp_path
):
    _prepare_config(monkeypatch, tmp_path)

    from include.domains.access.permissions import Permissions
    from include.domains.identity.handlers import users
    from include.domains.identity.handlers.users import RequestSetPasswdHandler
    from include.transport.request_handler import Result

    operator = _PasswordUser("unused", permissions={Permissions.SUPER_SET_PASSWD})
    target = _PasswordUser("OldPassword123!")
    session = _PasswordSession({"operator": operator, "alice": target})
    monkeypatch.setattr(users, "Session", lambda: session)
    monkeypatch.setattr(
        users,
        "check_passwd_requirements",
        lambda *_args: (_ for _ in ()).throw(
            AssertionError("Password policy must be bypassed")
        ),
    )
    handler, responses = _password_request(
        {
            "username": "alice",
            "new_passwd": "short",
            "bypass_passwd_requirements": True,
            "force_update_after_login": True,
        },
        username="operator",
        token="token",
    )

    result = RequestSetPasswdHandler().handle(handler)

    assert result == Result(code=200, target="alice", username="operator")
    assert result.data is None
    assert responses == [
        {"code": 200, "data": {}, "message": "Password set successfully"}
    ]
    assert target.password_update == ("short", True)
    assert session.commit_count == 1
