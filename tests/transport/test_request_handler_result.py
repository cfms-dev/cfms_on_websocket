import uuid
from types import SimpleNamespace

import jwt
import pytest
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError

from include.domains.identity.tokens import TokenPurpose

pytestmark = pytest.mark.unit
TARGET_USER_ID = uuid.UUID("aabbccdd-0000-4000-8000-000000000001")


def _allow_routed_request(monkeypatch, router):
    hook = SimpleNamespace(
        ext_before_request=lambda **_kwargs: None,
        ext_post_request=lambda **_kwargs: None,
    )
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


def _capture_pool_overload(monkeypatch, router, retry_after_seconds):
    responses = []
    released = []
    monkeypatch.setattr(
        router.AdmissionControlPolicy,
        "from_config",
        classmethod(
            lambda cls, config=None: SimpleNamespace(
                busy_retry_after_seconds=retry_after_seconds
            )
        ),
    )
    monkeypatch.setattr(
        router,
        "send_conclusion",
        lambda *args: responses.append(args),
    )
    monkeypatch.setattr(
        router.admission_controller,
        "release_request",
        lambda connection: released.append(connection),
    )
    return responses, released


def test_log_handler_result_maps_all_audit_fields(monkeypatch):
    from include.transport import router
    from include.transport.request_handler import Result

    calls = []

    def fake_log_audit(
        action,
        result,
        user_id=None,
        target=None,
        data=None,
        remote_address=None,
    ):
        calls.append(
            {
                "action": action,
                "result": result,
                "user_id": user_id,
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
            user_id="actor",
        ),
        "203.0.113.10",
    )

    assert calls == [
        {
            "action": "sample_action",
            "result": 207,
            "user_id": "actor",
            "target": "target-id",
            "data": {"changed": True},
            "remote_address": "203.0.113.10",
        }
    ]


def test_router_returns_429_before_constructing_rate_limited_handler(monkeypatch):
    from include.domains.security.guards.request_rate_control import (
        RequestRateControlDecision,
    )
    from include.transport import router

    responses = []

    class FakeConnectionHandler:
        def __init__(self, stream):
            self.stream = stream
            self.request = {}
            self.action = "limited_action"
            self.data = {}
            self.user_id = ""
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

    assert [response[:-1] for response in responses] == [
        (429, {"scope": "ip", "limit": 12, "retry_after_seconds": 7})
    ]


def test_router_closes_multiplexer_with_policy_violation_for_denied_ip(monkeypatch):
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


def test_connection_handler_closes_websocket_before_post_disconnect(monkeypatch):
    from include.transport import router

    events = []

    class FakeWebSocket:
        remote_address = ("192.0.2.10", 12345)
        socket = object()
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


def test_router_reports_safe_pydantic_request_validation_errors(monkeypatch):
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
        requires_auth = False
        rate_limit_cost = 1

        def handle(self, _handler, request):
            raise AssertionError("Invalid requests must not reach the handler")

    class FakeConnectionHandler:
        def __init__(self, stream):
            self.stream = stream
            self.request = {}
            self.action = "pydantic_action"
            self.data = {
                "item": {
                    "secret": "correct-horse-battery-staple",
                    "count": 1,
                    "label": "private-label",
                },
                "extra": "private-extra",
            }
            self.user_id = ""
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
    assert response["code"] == 400
    assert set(response["data"]) == {"errors"}
    assert [
        {key: value for key, value in error.items() if key != "msg"}
        for error in response["data"]["errors"]
    ] == [
        {"type": "int_type", "loc": ["item", "secret"]},
        {"type": "greater_than", "loc": ["item", "count"]},
        {"type": "value_error", "loc": ["item", "label"]},
        {"type": "extra_forbidden", "loc": ["extra"]},
    ]


@pytest.mark.parametrize(
    "target",
    [
        None,
        TokenPurpose.AUTH,
        TokenPurpose.AUTH | TokenPurpose.POST_AUTH,
        TokenPurpose.POST_AUTH,
        TokenPurpose.ESCALATION,
        True,
        2.5,
        str(int(TokenPurpose.GENERAL)),
    ],
)
def test_router_rejects_exchange_without_valid_target(monkeypatch, target):
    from include.transport import router

    data = {"method": "totp", "data": {"token": "unused"}}
    if target is not None:
        data["target_purpose"] = target
    responses = []

    class FakeConnectionHandler:
        def __init__(self, stream):
            self.stream = stream
            self.request = {}
            self.action = "exchange_token"
            self.data = data
            self.user_id = None
            self.token = None

        def conclude_request(self, code, data, message):
            responses.append((code, data))

    _allow_routed_request(monkeypatch, router)
    monkeypatch.setattr(router, "ConnectionHandler", FakeConnectionHandler)

    router.handle_request(SimpleNamespace(connection=SimpleNamespace(_ws=object())))

    assert len(responses) == 1
    code, response_data = responses[0]
    assert code == 400
    assert [(item["type"], item["loc"]) for item in response_data["errors"]] == [
        ("missing" if target is None else "literal_error", ("target_purpose",))
    ]
    assert all("input" not in item for item in response_data["errors"])


@pytest.mark.parametrize("mutate_in_hook", [False, True])
def test_router_passes_validated_model_and_keeps_original_dict(
    monkeypatch, mutate_in_hook
):
    from pydantic import model_validator

    from include.transport import router
    from include.transport.request_handler import RequestDataModel

    request_data = {"value": 1}
    handled_data = []
    validated_requests = []
    handled_requests = []

    class ValidRequest(RequestDataModel):
        value: int
        label: str = "default"

        @model_validator(mode="after")
        def record_validation(self):
            validated_requests.append(self)
            return self

    class PydanticHandler:
        request_model = ValidRequest
        requires_auth = False
        rate_limit_cost = 1

        def handle(self, handler, request):
            handled_data.append(handler.data)
            handled_requests.append(request)

    class FakeConnectionHandler:
        def __init__(self, stream):
            self.stream = stream
            self.request = {}
            self.action = "pydantic_action"
            self.data = request_data
            self.user_id = ""
            self.token = ""
            self.remote_address = "192.0.2.10"

    def before_request(*, request_handler, connection_handler):
        if mutate_in_hook:
            connection_handler.data["value"] = 2

    hook = SimpleNamespace(
        ext_before_request=before_request,
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
    assert len(validated_requests) == len(handled_requests) == 1
    assert handled_requests[0] is validated_requests[0]
    assert isinstance(handled_requests[0], ValidRequest)
    assert handled_requests[0].value == 1
    assert handled_requests[0].label == "default"
    assert request_data == {"value": 2 if mutate_in_hook else 1}


def test_request_admission_is_released_when_handler_raises(monkeypatch):
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


def test_authentication_pool_timeout_returns_retryable_503(monkeypatch):
    from include.transport import router

    class FakeConnectionHandler:
        def __init__(self, _stream):
            self.request = {
                "token": jwt.encode(
                    {"sub": "12345678-1234-4234-9234-123456789abc"},
                    "s" * 64,
                    algorithm="HS256",
                )
            }
            self.action = "authenticated_action"
            self.data = {}
            self.user_id = "alice"
            self.token = "token"
            self.remote_address = "192.0.2.10"

    def unavailable_session():
        raise SQLAlchemyTimeoutError("database pool exhausted")

    monkeypatch.setattr(router, "ConnectionHandler", FakeConnectionHandler)
    _allow_routed_request(monkeypatch, router)
    monkeypatch.setattr(router, "Session", unavailable_session)
    responses, released = _capture_pool_overload(monkeypatch, router, 3)
    connection = SimpleNamespace(_ws=object())
    stream = SimpleNamespace(connection=connection)

    router._handle_request_with_admission(stream)

    assert [response[:-1] for response in responses] == [
        (stream, 503, {"scope": "database_pool", "retry_after_seconds": 3})
    ]
    assert released == [connection]


def test_handler_pool_timeout_bypasses_generic_500_and_returns_503(monkeypatch):
    from include.transport import router

    reported_errors = []

    class FakeConnectionHandler:
        def __init__(self, _stream):
            self.request = {}
            self.action = "pool_timeout_action"
            self.data = {}
            self.user_id = ""
            self.token = ""
            self.remote_address = "192.0.2.10"

        def conclude_request(self, *_args, **_kwargs):
            raise AssertionError(
                "request should be concluded by the pool timeout handler"
            )

        def report_error(self, error):
            reported_errors.append(error)

    class PoolTimeoutHandler:
        request_model = SimpleNamespace(model_validate=lambda _data: None)
        requires_auth = False
        rate_limit_cost = 1

        def handle(self, _handler, request):
            raise SQLAlchemyTimeoutError("database pool exhausted")

    monkeypatch.setattr(router, "ConnectionHandler", FakeConnectionHandler)
    _allow_routed_request(monkeypatch, router)
    monkeypatch.setitem(
        router.available_functions, "pool_timeout_action", PoolTimeoutHandler
    )
    responses, released = _capture_pool_overload(monkeypatch, router, 2)
    connection = SimpleNamespace(_ws=object())
    stream = SimpleNamespace(connection=connection)

    router._handle_request_with_admission(stream)

    assert [response[:-1] for response in responses] == [
        (stream, 503, {"scope": "database_pool", "retry_after_seconds": 2})
    ]
    assert reported_errors == []
    assert released == [connection]


def test_non_pool_handler_failure_keeps_generic_500_response(monkeypatch):
    from include.transport import router

    reported_errors = []

    class FakeConnectionHandler:
        def __init__(self, _stream):
            self.request = {}
            self.action = "failing_action"
            self.data = {}
            self.user_id = ""
            self.token = ""
            self.remote_address = "192.0.2.10"

        def conclude_request(self, *_args, **_kwargs):
            raise AssertionError("generic failure should use report_error")

        def report_error(self, error, code=500):
            reported_errors.append((error, code))

    class FailingHandler:
        request_model = SimpleNamespace(model_validate=lambda _data: None)
        requires_auth = False
        rate_limit_cost = 1

        def handle(self, _handler, request):
            raise RuntimeError("handler failed")

    monkeypatch.setattr(router, "ConnectionHandler", FakeConnectionHandler)
    _allow_routed_request(monkeypatch, router)
    monkeypatch.setitem(router.available_functions, "failing_action", FailingHandler)
    stream = SimpleNamespace(connection=SimpleNamespace(_ws=object()))

    router.handle_request(stream)

    assert len(reported_errors) == 1
    error, code = reported_errors[0]
    assert isinstance(error, RuntimeError)
    assert str(error) == "handler failed"
    assert code == 500


def test_login_throttled_response_returns_result(monkeypatch):
    from include.domains.identity.handlers import auth
    from include.domains.identity.handlers.auth import RequestLoginHandler
    from include.domains.security.guards.login import (
        ThrottleDecision,
        ThrottleScope,
    )
    from include.transport.request_handler import Result

    responses = []
    handler = SimpleNamespace(
        user_id=None,
        data={
            "method": "password",
            "credential": {"username": "alice", "password": "secret"},
        },
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

    result = RequestLoginHandler().handle(
        handler, RequestLoginHandler.request_model.model_validate(handler.data)
    )

    assert result == Result(code=429, target="alice")
    assert [(response["code"], response["data"]) for response in responses] == [
        (429, {"retry_after_seconds": 30})
    ]


def _throttled_decision():
    from include.domains.security.guards.login import (
        ThrottleDecision,
        ThrottleScope,
    )

    return ThrottleDecision(False, ThrottleScope.ACCOUNT, retry_after_seconds=45)


def test_disable_2fa_password_check_uses_authentication_throttle(monkeypatch):
    from contextlib import nullcontext

    from include.domains.access.permissions import Permissions
    from include.domains.security.handlers import two_factor
    from include.domains.security.handlers.two_factor import RequestDisable2FAHandler

    responses = []
    handler = SimpleNamespace(
        user_id="alice",
        data={"password": "wrong"},
        stream=SimpleNamespace(connection=SimpleNamespace(_ws=object())),
        conclude_request=lambda *args, **kwargs: responses.append((args, kwargs)),
    )
    monkeypatch.setattr(two_factor, "get_client_ip", lambda _websocket: "127.0.0.1")
    monkeypatch.setattr(
        two_factor.LoginGuard, "evaluate", lambda *_args: _throttled_decision()
    )

    monkeypatch.setattr(
        two_factor,
        "Session",
        lambda: nullcontext(
            SimpleNamespace(
                get=lambda *_: SimpleNamespace(
                    id="alice",
                    username="alice",
                    all_permissions={Permissions.CONFIGURE_AUTH_METHODS},
                )
            )
        ),
    )

    result = RequestDisable2FAHandler().handle(
        handler, RequestDisable2FAHandler.request_model.model_validate(handler.data)
    )

    assert result.code == 429
    assert responses[0][0][0] == 429
    assert responses[0][0][1] == {"retry_after_seconds": 45}


def test_disable_2fa_request_accepts_a_credential(monkeypatch):
    from include.domains.security.handlers.two_factor import RequestDisable2FAHandler

    request = RequestDisable2FAHandler.request_model.model_validate(
        {"password": "secret"}
    )

    assert request.password == "secret"


@pytest.mark.parametrize(
    "request_data", [{}, {"password": None}], ids=["missing", "null"]
)
def test_disable_2fa_request_requires_a_credential(monkeypatch, request_data):
    from pydantic import ValidationError

    from include.domains.security.handlers.two_factor import RequestDisable2FAHandler

    with pytest.raises(ValidationError, match="password"):
        RequestDisable2FAHandler.request_model.model_validate(request_data)
