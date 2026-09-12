import asyncio
import datetime
import socket
import ssl
import threading
from contextlib import asynccontextmanager
from types import SimpleNamespace

import httpx2 as httpx
import jwt
import pluggy
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, Depends, FastAPI, Request
from starlette import convertors as starlette_convertors

from include.domains.access.permissions import Permissions
from include.extensions import manager as extension_manager


@pytest.fixture
def http_api_modules(monkeypatch, protected_test_config):
    monkeypatch.chdir(protected_test_config.src_dir)
    from include.extensions.http_api import (
        application,
        config,
        contracts,
        runtime,
        security,
    )

    return SimpleNamespace(
        application=application,
        config=config,
        contracts=contracts,
        runtime=runtime,
        security=security,
    )


def _allow_all_subnets(monkeypatch, application) -> None:
    monkeypatch.setattr(
        application.LoginGuard,
        "evaluate_subnet_access",
        classmethod(lambda _cls, _address: SimpleNamespace(allowed=True)),
    )


@asynccontextmanager
async def _http_client(
    app,
    *,
    client: tuple[str, int] = ("testclient", 50000),
    raise_app_exceptions: bool = True,
):
    transport = httpx.ASGITransport(
        app=app,
        client=client,
        raise_app_exceptions=raise_app_exceptions,
    )
    async with httpx.AsyncClient(
        transport=transport,
        base_url="http://testserver",
    ) as test_client:
        yield test_client


def _install_http_plugins(monkeypatch, modules, registrations_by_owner):
    core_pm = pluggy.PluginManager("cfms")
    core_pm.add_hookspecs(extension_manager.ServerHookSpecs)
    core_pm.add_hookspecs(modules.contracts.HttpApiHookSpecs)
    metadata = []

    def make_plugin(registrations):
        class Plugin:
            @modules.contracts.http_hookimpl
            def ext_register_http_routers(self):
                return registrations

        return Plugin()

    for owner, registrations in registrations_by_owner:
        metadata.append(SimpleNamespace(identifier=owner))
        core_pm.register(make_plugin(registrations), name=owner)
    monkeypatch.setattr(modules.application, "pm", core_pm)
    monkeypatch.setattr(
        modules.application,
        "get_loaded_extension_metadata",
        lambda: tuple(metadata),
    )


def test_sample_http_configuration_is_valid(http_api_modules):
    policy = http_api_modules.config.HttpApiPolicy.from_config(
        http_api_modules.security.global_config
    )

    assert policy.host == "localhost"
    assert policy.port == 5105
    assert policy.request_header_timeout_seconds == 10.0
    assert policy.request_body_timeout_seconds == 30.0
    assert policy.cors_allowed_origins == ()


def test_http_extension_adds_hook_spec_to_core_manager(http_api_modules):
    from include.extensions.http_api import _extension

    assert hasattr(extension_manager.pm.hook, "ext_register_http_routers")
    assert _extension.http_hookimpl is extension_manager.hookimpl


def test_http_extension_shutdown_does_not_reload_changed_config(
    monkeypatch, http_api_modules
):
    from include.extensions.http_api import _extension

    class FakeRuntime:
        def __init__(self):
            self.started_policy = None
            self.shutdown_calls = 0

        def start(self, _app, policy):
            self.started_policy = policy

        def shutdown(self):
            self.shutdown_calls += 1

    config = {"extensions": {"http_api": {"shutdown_timeout_seconds": 1.0}}}
    runtime = FakeRuntime()
    monkeypatch.setattr(_extension, "global_config", config)
    monkeypatch.setattr(_extension, "_runtime", runtime)
    monkeypatch.setattr(_extension, "build_http_application", lambda policy: policy)

    _extension.ext_on_startup()
    config["extensions"]["http_api"]["shutdown_timeout_seconds"] = 2.0
    _extension.ext_on_shutdown()

    assert runtime.started_policy.shutdown_timeout_seconds == 1.0
    assert runtime.shutdown_calls == 1


@pytest.mark.parametrize(
    "section",
    [
        {"unknown": True},
        {"ssl_certfile": "cert.pem"},
        {"ssl_keyfile": "key.pem"},
        {"cors_allowed_origins": ["*"]},
        {"host": " "},
        {"port": 0},
        {"request_header_timeout_seconds": 0},
        {"request_body_timeout_seconds": -1.0},
        {"request_body_timeout_seconds": "30"},
    ],
)
def test_invalid_http_configuration_is_rejected(http_api_modules, section):
    config = {"extensions": {"http_api": section}}

    with pytest.raises(Exception, match="Invalid extensions.http_api"):
        http_api_modules.config.HttpApiPolicy.from_config(config)


@pytest.mark.parametrize(
    "origin",
    [
        " https://ui.example",
        "https://ui.example ",
        "https://ui.example/",
        "https://ui.example/path",
        "https://user@ui.example",
        "https://user:password@ui.example",
        "https://ui.example:",
        "https://ui.example?",
        "https://ui.example?mode=cors",
        "https://ui.example#fragment",
        "https://ui.example\\path",
    ],
)
def test_cors_origin_rejects_non_origin_url_components(http_api_modules, origin):
    config = {"extensions": {"http_api": {"cors_allowed_origins": [origin]}}}

    with pytest.raises(
        http_api_modules.config.ConfigValidationError,
        match="contains invalid origin",
    ):
        http_api_modules.config.HttpApiPolicy.from_config(config)


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        ("HTTPS://UI.Example:443", "https://ui.example"),
        ("http://UI.Example:80", "http://ui.example"),
        ("https://UI.Example:8443", "https://ui.example:8443"),
        ("https://bücher.example", "https://xn--bcher-kva.example"),
        ("https://[2001:0DB8::1]:443", "https://[2001:db8::1]"),
    ],
)
def test_cors_origin_is_normalized(http_api_modules, configured, expected):
    policy = http_api_modules.config.HttpApiPolicy(cors_allowed_origins=(configured,))

    assert policy.cors_allowed_origins == (expected,)


def test_cors_origin_rejects_duplicates_after_normalization(http_api_modules):
    config = {
        "extensions": {
            "http_api": {
                "cors_allowed_origins": [
                    "https://ui.example",
                    "HTTPS://UI.EXAMPLE:443",
                ]
            }
        }
    }

    with pytest.raises(
        http_api_modules.config.ConfigValidationError,
        match="must not contain duplicates",
    ):
        http_api_modules.config.HttpApiPolicy.from_config(config)


@pytest.mark.asyncio
async def test_normalized_cors_origin_matches_browser_header(
    monkeypatch, http_api_modules
):
    modules = http_api_modules
    _allow_all_subnets(monkeypatch, modules.application)
    _install_http_plugins(monkeypatch, modules, [])
    policy = modules.config.HttpApiPolicy(
        cors_allowed_origins=("HTTPS://UI.Example:443",)
    )
    app = modules.application.build_http_application(policy)

    async with _http_client(app, client=("127.0.0.1", 5000)) as client:
        response = await client.get(
            "/healthz", headers={"Origin": "https://ui.example"}
        )

    assert response.status_code == 200
    assert response.headers["Access-Control-Allow-Origin"] == "https://ui.example"


@pytest.mark.asyncio
async def test_registered_router_is_http_only_and_docs_are_disabled(
    monkeypatch, http_api_modules
):
    modules = http_api_modules
    _allow_all_subnets(monkeypatch, modules.application)
    router = APIRouter(prefix="/example")

    @router.get("/value")
    def value():
        return {"value": 42}

    registration = modules.contracts.HttpRouterRegistration("consumer", router)
    _install_http_plugins(monkeypatch, modules, [("consumer", (registration,))])
    app = modules.application.build_http_application(modules.config.HttpApiPolicy())

    async with _http_client(app, client=("127.0.0.1", 5000)) as client:
        assert (await client.get("/api/v1/example/value")).json() == {"value": 42}
        assert (await client.get("/healthz")).json() == {"status": "ok"}
        assert (await client.get("/api/v1/openapi.json")).status_code == 404
        assert (await client.get("/api/v1/docs")).status_code == 404

    websocket_actions = set()
    for result in extension_manager.pm.hook.ext_register_handlers():
        websocket_actions.update(result)
    assert "value" not in websocket_actions


@pytest.mark.asyncio
async def test_docs_use_fixed_api_paths_when_enabled(monkeypatch, http_api_modules):
    modules = http_api_modules
    _allow_all_subnets(monkeypatch, modules.application)
    _install_http_plugins(monkeypatch, modules, [])
    policy = modules.config.HttpApiPolicy(docs_enabled=True)
    app = modules.application.build_http_application(policy)

    async with _http_client(app, client=("127.0.0.1", 5000)) as client:
        assert (await client.get("/api/v1/openapi.json")).status_code == 200
        assert (await client.get("/api/v1/docs")).status_code == 200


@pytest.mark.parametrize("invalid_router", [object(), APIRouter()])
def test_invalid_router_registration_fails_startup(
    monkeypatch, http_api_modules, invalid_router
):
    modules = http_api_modules
    registration = modules.contracts.HttpRouterRegistration("consumer", invalid_router)
    _install_http_plugins(monkeypatch, modules, [("consumer", (registration,))])

    with pytest.raises((TypeError, ValueError)):
        modules.application.build_http_application(modules.config.HttpApiPolicy())


def test_unknown_router_owner_fails_startup(monkeypatch, http_api_modules):
    modules = http_api_modules
    router = APIRouter(prefix="/example")
    registration = modules.contracts.HttpRouterRegistration("missing", router)
    _install_http_plugins(monkeypatch, modules, [("consumer", (registration,))])

    with pytest.raises(ValueError, match="is not a loaded extension"):
        modules.application.build_http_application(modules.config.HttpApiPolicy())


def test_duplicate_method_and_final_path_fails_startup(monkeypatch, http_api_modules):
    modules = http_api_modules
    first = APIRouter(prefix="/example")
    second = APIRouter(prefix="/example")
    first.get("/value")(lambda: None)
    second.get("/value")(lambda: None)
    registrations = (
        modules.contracts.HttpRouterRegistration("first", first),
        modules.contracts.HttpRouterRegistration("second", second),
    )
    _install_http_plugins(
        monkeypatch,
        modules,
        [("first", (registrations[0],)), ("second", (registrations[1],))],
    )

    with pytest.raises(ValueError, match="Duplicate HTTP route GET"):
        modules.application.build_http_application(modules.config.HttpApiPolicy())


@pytest.mark.parametrize(
    ("first_path", "second_path"),
    [
        ("/{user_id}", "/{username}"),
        ("/{user_id:int}", "/{number:int}"),
    ],
)
def test_equivalent_parameterized_routes_fail_startup_across_extensions(
    monkeypatch, http_api_modules, first_path, second_path
):
    modules = http_api_modules
    first = APIRouter(prefix="/users")
    second = APIRouter(prefix="/users")
    first.get(first_path)(lambda: None)
    second.get(second_path)(lambda: None)
    registrations = (
        modules.contracts.HttpRouterRegistration("first", first),
        modules.contracts.HttpRouterRegistration("second", second),
    )
    _install_http_plugins(
        monkeypatch,
        modules,
        [("first", (registrations[0],)), ("second", (registrations[1],))],
    )

    with pytest.raises(ValueError) as exc_info:
        modules.application.build_http_application(modules.config.HttpApiPolicy())

    message = str(exc_info.value)
    assert f"Duplicate HTTP route GET /api/v1/users{second_path}" in message
    assert f"/api/v1/users{first_path}" in message
    assert "'first'" in message
    assert "'second'" in message


def test_equivalent_custom_converter_regex_fails_startup(monkeypatch, http_api_modules):
    modules = http_api_modules

    class AliasConvertor(starlette_convertors.Convertor[str]):
        regex = "[^/]+"

        def convert(self, value: str) -> str:
            return value

        def to_string(self, value: str) -> str:
            return value

    monkeypatch.setitem(
        starlette_convertors.CONVERTOR_TYPES, "test_alias", AliasConvertor()
    )
    first = APIRouter(prefix="/users")
    second = APIRouter(prefix="/users")
    first.get("/{username}")(lambda: None)
    second.get("/{alias:test_alias}")(lambda: None)
    registrations = (
        modules.contracts.HttpRouterRegistration("first", first),
        modules.contracts.HttpRouterRegistration("second", second),
    )
    _install_http_plugins(
        monkeypatch,
        modules,
        [("first", (registrations[0],)), ("second", (registrations[1],))],
    )

    with pytest.raises(ValueError, match="Duplicate HTTP route GET"):
        modules.application.build_http_application(modules.config.HttpApiPolicy())


def test_dynamic_route_cannot_shadow_later_static_route_across_extensions(
    monkeypatch, http_api_modules
):
    modules = http_api_modules
    dynamic = APIRouter(prefix="/users")
    static = APIRouter(prefix="/users")
    dynamic.get("/{username}")(lambda username: {"username": username})
    static.get("/me")(lambda: {"handler": "static"})
    registrations = (
        modules.contracts.HttpRouterRegistration("dynamic", dynamic),
        modules.contracts.HttpRouterRegistration("static", static),
    )
    _install_http_plugins(
        monkeypatch,
        modules,
        [("dynamic", (registrations[0],)), ("static", (registrations[1],))],
    )

    with pytest.raises(ValueError) as exc_info:
        modules.application.build_http_application(modules.config.HttpApiPolicy())

    message = str(exc_info.value)
    assert "Shadowed HTTP route GET /api/v1/users/me" in message
    assert "/api/v1/users/{username}" in message
    assert "'dynamic'" in message
    assert "'static'" in message


@pytest.mark.asyncio
async def test_static_route_before_dynamic_route_keeps_both_reachable(
    monkeypatch, http_api_modules
):
    modules = http_api_modules
    _allow_all_subnets(monkeypatch, modules.application)
    static = APIRouter(prefix="/users")
    dynamic = APIRouter(prefix="/users")
    static.get("/me")(lambda: {"handler": "static"})
    dynamic.get("/{username}")(
        lambda username: {"handler": "dynamic", "username": username}
    )
    registrations = (
        modules.contracts.HttpRouterRegistration("static", static),
        modules.contracts.HttpRouterRegistration("dynamic", dynamic),
    )
    _install_http_plugins(
        monkeypatch,
        modules,
        [("static", (registrations[0],)), ("dynamic", (registrations[1],))],
    )

    app = modules.application.build_http_application(modules.config.HttpApiPolicy())

    async with _http_client(app, client=("127.0.0.1", 5000)) as client:
        assert (await client.get("/api/v1/users/me")).json() == {"handler": "static"}
        assert (await client.get("/api/v1/users/alice")).json() == {
            "handler": "dynamic",
            "username": "alice",
        }


@pytest.mark.asyncio
async def test_dynamic_converter_that_does_not_match_static_path_is_allowed(
    monkeypatch, http_api_modules
):
    modules = http_api_modules
    _allow_all_subnets(monkeypatch, modules.application)
    dynamic = APIRouter(prefix="/users")
    static = APIRouter(prefix="/users")
    dynamic.get("/{user_id:int}")(
        lambda user_id: {"handler": "dynamic", "user_id": user_id}
    )
    static.get("/me")(lambda: {"handler": "static"})
    registrations = (
        modules.contracts.HttpRouterRegistration("dynamic", dynamic),
        modules.contracts.HttpRouterRegistration("static", static),
    )
    _install_http_plugins(
        monkeypatch,
        modules,
        [("dynamic", (registrations[0],)), ("static", (registrations[1],))],
    )

    app = modules.application.build_http_application(modules.config.HttpApiPolicy())

    async with _http_client(app, client=("127.0.0.1", 5000)) as client:
        assert (await client.get("/api/v1/users/42")).json() == {
            "handler": "dynamic",
            "user_id": 42,
        }
        assert (await client.get("/api/v1/users/me")).json() == {"handler": "static"}


@pytest.mark.asyncio
async def test_different_converters_keep_reachable_routes_distinct(
    monkeypatch, http_api_modules
):
    modules = http_api_modules
    _allow_all_subnets(monkeypatch, modules.application)
    integer = APIRouter(prefix="/users")
    string = APIRouter(prefix="/users")
    integer.get("/{user_id:int}")(
        lambda user_id: {"handler": "integer", "value": user_id}
    )
    string.get("/{username}")(lambda username: {"handler": "string", "value": username})
    registrations = (
        modules.contracts.HttpRouterRegistration("integer", integer),
        modules.contracts.HttpRouterRegistration("string", string),
    )
    _install_http_plugins(
        monkeypatch,
        modules,
        [("integer", (registrations[0],)), ("string", (registrations[1],))],
    )

    app = modules.application.build_http_application(modules.config.HttpApiPolicy())

    async with _http_client(app, client=("127.0.0.1", 5000)) as client:
        assert (await client.get("/api/v1/users/42")).json() == {
            "handler": "integer",
            "value": 42,
        }
        assert (await client.get("/api/v1/users/alice")).json() == {
            "handler": "string",
            "value": "alice",
        }


@pytest.mark.asyncio
async def test_equivalent_route_patterns_with_different_methods_are_allowed(
    monkeypatch, http_api_modules
):
    modules = http_api_modules
    _allow_all_subnets(monkeypatch, modules.application)
    get_router = APIRouter(prefix="/users")
    post_router = APIRouter(prefix="/users")
    get_router.get("/{user_id}")(lambda user_id: {"method": "GET", "id": user_id})
    post_router.post("/{username}")(lambda username: {"method": "POST", "id": username})
    registrations = (
        modules.contracts.HttpRouterRegistration("reader", get_router),
        modules.contracts.HttpRouterRegistration("writer", post_router),
    )
    _install_http_plugins(
        monkeypatch,
        modules,
        [("reader", (registrations[0],)), ("writer", (registrations[1],))],
    )

    app = modules.application.build_http_application(modules.config.HttpApiPolicy())

    async with _http_client(app, client=("127.0.0.1", 5000)) as client:
        assert (await client.get("/api/v1/users/alice")).json() == {
            "method": "GET",
            "id": "alice",
        }
        assert (await client.post("/api/v1/users/alice")).json() == {
            "method": "POST",
            "id": "alice",
        }


def test_router_cannot_replace_enabled_docs(monkeypatch, http_api_modules):
    modules = http_api_modules
    router = APIRouter(prefix="/docs")
    router.get("")(lambda: None)
    registration = modules.contracts.HttpRouterRegistration("consumer", router)
    _install_http_plugins(monkeypatch, modules, [("consumer", (registration,))])

    with pytest.raises(ValueError, match="Duplicate HTTP route GET /api/v1/docs"):
        modules.application.build_http_application(
            modules.config.HttpApiPolicy(docs_enabled=True)
        )


@pytest.mark.asyncio
async def test_body_limit_and_exception_boundary_do_not_echo_sensitive_data(
    monkeypatch, http_api_modules
):
    modules = http_api_modules
    _allow_all_subnets(monkeypatch, modules.application)
    router = APIRouter(prefix="/example")

    @router.post("/echo")
    async def echo():
        raise RuntimeError("failure")

    registration = modules.contracts.HttpRouterRegistration("consumer", router)
    _install_http_plugins(monkeypatch, modules, [("consumer", (registration,))])
    policy = modules.config.HttpApiPolicy(
        max_request_body_bytes=4,
        cors_allowed_origins=("https://ui.example",),
    )
    app = modules.application.build_http_application(policy)

    headers = {"Origin": "https://ui.example"}
    async with _http_client(
        app,
        raise_app_exceptions=False,
        client=("127.0.0.1", 5000),
    ) as client:
        oversized = await client.post(
            "/api/v1/example/echo", content=b"12345", headers=headers
        )
        assert oversized.status_code == 413

        failure = await client.post(
            "/api/v1/example/echo",
            content=b"key",
            headers={
                **headers,
                "Authorization": "Bearer highly-sensitive-token",
            },
        )
        disallowed_origin = await client.post(
            "/api/v1/example/echo",
            content=b"12345",
            headers={"Origin": "https://other.example"},
        )

    assert oversized.headers["Access-Control-Allow-Origin"] == "https://ui.example"
    assert oversized.headers["Connection"] == "close"
    assert failure.status_code == 500
    assert failure.headers["Access-Control-Allow-Origin"] == "https://ui.example"
    payload = failure.json()
    assert set(payload) == {"detail", "log_id"}
    assert "highly-sensitive-token" not in failure.text
    assert "key" not in failure.text
    assert disallowed_origin.status_code == 413
    assert "Access-Control-Allow-Origin" not in disallowed_origin.headers


@pytest.mark.asyncio
async def test_body_limit_counts_chunked_body_before_endpoint_runs(
    monkeypatch, http_api_modules
):
    modules = http_api_modules
    _allow_all_subnets(monkeypatch, modules.application)
    router = APIRouter(prefix="/example")
    calls = 0

    @router.post("/ignore")
    def ignore_body():
        nonlocal calls
        calls += 1
        return {"ok": True}

    async def stream_chunks(*chunks):
        for chunk in chunks:
            yield chunk

    registration = modules.contracts.HttpRouterRegistration("consumer", router)
    _install_http_plugins(monkeypatch, modules, [("consumer", (registration,))])
    app = modules.application.build_http_application(
        modules.config.HttpApiPolicy(max_request_body_bytes=4)
    )

    async with _http_client(app, client=("127.0.0.1", 5000)) as client:
        accepted = await client.post(
            "/api/v1/example/ignore",
            content=stream_chunks(b"12", b"34"),
        )
        rejected = await client.post(
            "/api/v1/example/ignore",
            content=stream_chunks(b"123", b"45"),
        )

    assert accepted.status_code == 200
    assert rejected.status_code == 413
    assert rejected.headers["Connection"] == "close"
    assert calls == 1


@pytest.mark.asyncio
async def test_body_receive_timeout_closes_connection_before_endpoint_runs(
    monkeypatch, http_api_modules
):
    modules = http_api_modules
    _allow_all_subnets(monkeypatch, modules.application)
    router = APIRouter(prefix="/example")
    calls = 0

    @router.post("/ignore")
    def ignore_body():
        nonlocal calls
        calls += 1
        return {"ok": True}

    registration = modules.contracts.HttpRouterRegistration("consumer", router)
    _install_http_plugins(monkeypatch, modules, [("consumer", (registration,))])
    app = modules.application.build_http_application(
        modules.config.HttpApiPolicy(request_body_timeout_seconds=0.05)
    )

    async def slow_body():
        yield b"first chunk"
        await asyncio.Event().wait()

    transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 5000))
    async with httpx.AsyncClient(
        transport=transport, base_url="http://testserver"
    ) as client:
        response = await client.post("/api/v1/example/ignore", content=slow_body())

    assert response.status_code == 408
    assert response.json() == {"detail": "Request body timeout"}
    assert response.headers["Connection"] == "close"
    assert calls == 0


@pytest.mark.parametrize("content_length", ["-1", "not-a-number"])
@pytest.mark.asyncio
async def test_invalid_content_length_is_rejected(
    monkeypatch, http_api_modules, content_length
):
    modules = http_api_modules
    _allow_all_subnets(monkeypatch, modules.application)
    _install_http_plugins(monkeypatch, modules, [])
    app = modules.application.build_http_application(modules.config.HttpApiPolicy())

    async with _http_client(app, client=("127.0.0.1", 5000)) as client:
        response = await client.get(
            "/healthz", headers={"Content-Length": content_length}
        )

    assert response.status_code == 400
    assert response.json() == {"detail": "Invalid Content-Length"}


@pytest.mark.asyncio
async def test_banned_client_is_rejected(monkeypatch, http_api_modules):
    modules = http_api_modules
    monkeypatch.setattr(
        modules.application.LoginGuard,
        "evaluate_subnet_access",
        classmethod(lambda _cls, _address: SimpleNamespace(allowed=False)),
    )
    _install_http_plugins(monkeypatch, modules, [])
    app = modules.application.build_http_application(
        modules.config.HttpApiPolicy(
            cors_allowed_origins=("https://ui.example",),
        )
    )

    async with _http_client(app, client=("127.0.0.1", 5000)) as client:
        response = await client.get(
            "/healthz", headers={"Origin": "https://ui.example"}
        )
        disallowed_origin = await client.get(
            "/healthz", headers={"Origin": "https://other.example"}
        )

    assert response.status_code == 403
    assert response.headers["Access-Control-Allow-Origin"] == "https://ui.example"
    assert response.headers["Connection"] == "close"
    assert disallowed_origin.status_code == 403
    assert "Access-Control-Allow-Origin" not in disallowed_origin.headers


@pytest.mark.asyncio
async def test_banned_cors_preflight_is_rejected_before_body_and_cors(
    monkeypatch, http_api_modules
):
    modules = http_api_modules
    monkeypatch.setattr(
        modules.application.LoginGuard,
        "evaluate_subnet_access",
        classmethod(lambda _cls, _address: SimpleNamespace(allowed=False)),
    )
    _install_http_plugins(monkeypatch, modules, [])
    app = modules.application.build_http_application(
        modules.config.HttpApiPolicy(
            max_request_body_bytes=4,
            cors_allowed_origins=("https://ui.example",),
        )
    )

    async with _http_client(app, client=("127.0.0.1", 5000)) as client:
        response = await client.request(
            "OPTIONS",
            "/healthz",
            content=b"12345",
            headers={
                "Origin": "https://ui.example",
                "Access-Control-Request-Method": "GET",
            },
        )

    assert response.status_code == 403
    assert response.json() == {"detail": "Forbidden"}
    assert response.headers["Access-Control-Allow-Origin"] == "https://ui.example"
    assert "Origin" in response.headers["Vary"]


@pytest.mark.asyncio
async def test_oversized_cors_preflight_is_rejected_before_cors(
    monkeypatch, http_api_modules
):
    modules = http_api_modules
    _allow_all_subnets(monkeypatch, modules.application)
    _install_http_plugins(monkeypatch, modules, [])
    app = modules.application.build_http_application(
        modules.config.HttpApiPolicy(
            max_request_body_bytes=4,
            cors_allowed_origins=("https://ui.example",),
        )
    )

    async with _http_client(app, client=("127.0.0.1", 5000)) as client:
        response = await client.request(
            "OPTIONS",
            "/healthz",
            content=b"12345",
            headers={
                "Origin": "https://ui.example",
                "Access-Control-Request-Method": "GET",
            },
        )

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large"}
    assert response.headers["Access-Control-Allow-Origin"] == "https://ui.example"
    assert "Origin" in response.headers["Vary"]


@pytest.mark.asyncio
async def test_admitted_cors_preflight_reaches_cors_middleware(
    monkeypatch, http_api_modules
):
    modules = http_api_modules
    _allow_all_subnets(monkeypatch, modules.application)
    _install_http_plugins(monkeypatch, modules, [])
    app = modules.application.build_http_application(
        modules.config.HttpApiPolicy(
            max_request_body_bytes=4,
            cors_allowed_origins=("https://ui.example",),
        )
    )

    async with _http_client(app, client=("127.0.0.1", 5000)) as client:
        response = await client.request(
            "OPTIONS",
            "/healthz",
            content=b"1234",
            headers={
                "Origin": "https://ui.example",
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "Authorization, Content-Type",
            },
        )

    assert response.status_code == 200
    assert response.text == "OK"
    assert response.headers["Access-Control-Allow-Origin"] == "https://ui.example"
    assert "GET" in response.headers["Access-Control-Allow-Methods"]
    allowed_headers = {
        value.strip().lower()
        for value in response.headers["Access-Control-Allow-Headers"].split(",")
    }
    assert {"authorization", "content-type"}.issubset(allowed_headers)


@pytest.mark.asyncio
async def test_invalid_peer_address_is_rejected(monkeypatch, http_api_modules):
    modules = http_api_modules
    _install_http_plugins(monkeypatch, modules, [])
    app = modules.application.build_http_application(modules.config.HttpApiPolicy())

    async with _http_client(app) as client:
        response = await client.get("/healthz")

    assert response.status_code == 403


@pytest.mark.asyncio
async def test_trusted_proxy_resolution_uses_rightmost_untrusted_address(
    monkeypatch, http_api_modules
):
    security = http_api_modules.security
    monkeypatch.setattr(
        security,
        "global_config",
        {"server": {"trusted_proxy_networks": ["10.0.0.0/8"]}},
    )
    app = FastAPI()

    @app.get("/")
    def address(request: Request):
        return {"address": security.get_http_client_address(request)}

    async with _http_client(app, client=("10.0.0.2", 5000)) as client:
        response = await client.get(
            "/",
            headers={"X-Forwarded-For": "192.0.2.1, 198.51.100.7, 10.0.0.1"},
        )

    assert response.json() == {"address": "198.51.100.7"}


def _session_factory(user):
    class FakeSession:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def get(self, _model, username):
            return user if user is not None and user.username == username else None

    return FakeSession


@pytest.mark.parametrize(
    ("token_kind", "status_code"),
    [
        ("missing", 401),
        ("malformed", 401),
        ("wrong_signature", 401),
        ("expired", 401),
        ("disabled", 401),
        ("valid", 200),
    ],
)
@pytest.mark.asyncio
async def test_bearer_authentication_fully_validates_user_token(
    monkeypatch, http_api_modules, token_kind, status_code
):
    security = http_api_modules.security
    user = SimpleNamespace(
        username="alice",
        all_permissions={Permissions.SEARCH},
        all_groups={"user"},
    )
    secret = "correct-secret-with-at-least-32-bytes"
    now = datetime.datetime.now(datetime.UTC)
    valid_token = jwt.encode(
        {"username": "alice", "exp": now + datetime.timedelta(minutes=5)},
        secret,
        algorithm="HS256",
    )
    expired_token = jwt.encode(
        {"username": "alice", "exp": now - datetime.timedelta(minutes=5)},
        secret,
        algorithm="HS256",
    )
    wrong_token = jwt.encode(
        {"username": "alice", "exp": now + datetime.timedelta(minutes=5)},
        "wrong-secret-with-at-least-32-bytes!!",
        algorithm="HS256",
    )

    def validate(token):
        if token_kind == "disabled":
            return False
        try:
            jwt.decode(token, secret, algorithms=["HS256"])
        except jwt.InvalidTokenError:
            return False
        return True

    user.is_token_valid = validate
    monkeypatch.setattr(security, "Session", _session_factory(user))
    app = FastAPI()

    @app.get("/")
    def endpoint(principal=Depends(security.require_http_principal)):
        return {"username": principal.username}

    headers = {}
    if token_kind == "malformed":
        headers["Authorization"] = "Bearer not-a-token"
    elif token_kind == "wrong_signature":
        headers["Authorization"] = f"Bearer {wrong_token}"
    elif token_kind == "expired":
        headers["Authorization"] = f"Bearer {expired_token}"
    elif token_kind in {"disabled", "valid"}:
        headers["Authorization"] = f"Bearer {valid_token}"

    async with _http_client(app) as client:
        response = await client.get("/", headers=headers)

    assert response.status_code == status_code
    if status_code == 401:
        assert response.headers["WWW-Authenticate"] == "Bearer"


@pytest.mark.asyncio
async def test_permission_and_rate_limit_dependencies(monkeypatch, http_api_modules):
    security = http_api_modules.security
    principal = http_api_modules.contracts.HttpPrincipal(
        username="alice",
        permissions=frozenset({Permissions.SEARCH}),
        groups=frozenset({"user"}),
    )
    app = FastAPI()
    app.dependency_overrides[security.get_optional_http_principal] = lambda: principal
    app.dependency_overrides[security.require_http_principal] = lambda: principal
    monkeypatch.setattr(
        security,
        "check_request_rate",
        lambda *_args, **_kwargs: SimpleNamespace(allowed=False, retry_after_seconds=7),
    )

    @app.get(
        "/limited",
        dependencies=[Depends(security.http_rate_limit("consumer", "list"))],
    )
    def limited():
        return {}

    @app.get("/forbidden")
    def forbidden(
        _principal=Depends(
            security.require_http_permissions(Permissions.MANAGE_SYSTEM)
        ),
    ):
        return {}

    async with _http_client(app) as client:
        limited_response = await client.get("/limited")
        forbidden_response = await client.get("/forbidden")

    assert limited_response.status_code == 429
    assert limited_response.headers["Retry-After"] == "7"
    assert forbidden_response.status_code == 403


def _write_self_signed_certificate(tmp_path):
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.datetime.now(datetime.UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("localhost")]),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )
    cert_path = tmp_path / "cert.pem"
    key_path = tmp_path / "key.pem"
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    return cert_path, key_path


def _reserve_ipv4_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


@pytest.mark.parametrize(
    ("request_bytes", "expected_status", "expected_body", "subnet_allowed"),
    [
        pytest.param(
            b"POST /healthz HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n",
            413,
            b'{"detail":"Request body too large"}',
            True,
            id="declared-body-too-large",
        ),
        pytest.param(
            b"POST /healthz HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Transfer-Encoding: chunked\r\n"
            b"\r\n"
            b"5\r\n12345\r\n",
            413,
            b'{"detail":"Request body too large"}',
            True,
            id="streamed-body-too-large",
        ),
        pytest.param(
            b"POST /healthz HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\n",
            403,
            b'{"detail":"Forbidden"}',
            False,
            id="subnet-forbidden",
        ),
    ],
)
def test_real_tls_early_rejection_closes_unread_body_and_releases_concurrency(
    monkeypatch,
    http_api_modules,
    tmp_path,
    request_bytes,
    expected_status,
    expected_body,
    subnet_allowed,
):
    modules = http_api_modules
    cert_path, key_path = _write_self_signed_certificate(tmp_path)
    port = _reserve_ipv4_port()
    monkeypatch.setattr(
        modules.runtime,
        "global_config",
        {
            "server": {
                "ssl_certfile": str(cert_path),
                "ssl_keyfile": str(key_path),
            },
            "security": {"require_client_cert": False},
        },
    )
    monkeypatch.setattr(
        modules.application.LoginGuard,
        "evaluate_subnet_access",
        classmethod(lambda _cls, _address: SimpleNamespace(allowed=subnet_allowed)),
    )
    _install_http_plugins(monkeypatch, modules, [])
    policy = modules.config.HttpApiPolicy(
        host="127.0.0.1",
        port=port,
        ssl_certfile=str(cert_path),
        ssl_keyfile=str(key_path),
        max_concurrency=1,
        max_request_body_bytes=4,
        startup_timeout_seconds=5.0,
        shutdown_timeout_seconds=5.0,
    )
    app = modules.application.build_http_application(policy)
    client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    client_context.check_hostname = False
    client_context.verify_mode = ssl.CERT_NONE
    runtime = modules.runtime.HttpApiRuntime()

    runtime.start(app, policy)
    try:
        with (
            socket.create_connection(("127.0.0.1", port), timeout=5.0) as connection,
            client_context.wrap_socket(
                connection, server_hostname="localhost"
            ) as rejected_connection,
        ):
            rejected_connection.settimeout(2.0)
            rejected_connection.sendall(request_bytes)
            response_bytes = bytearray()
            while expected_body not in response_bytes:
                chunk = rejected_connection.recv(4096)
                assert chunk
                response_bytes.extend(chunk)

            assert f"HTTP/1.1 {expected_status} ".encode() in response_bytes
            assert b"connection: close\r\n" in response_bytes.lower()
            disconnected = False
            try:
                rejected_connection.sendall(b"1")
            except OSError:
                disconnected = True
            else:
                disconnected = rejected_connection.recv(1) == b""
            assert disconnected

        _allow_all_subnets(monkeypatch, modules.application)
        with httpx.Client(verify=False, trust_env=False, timeout=5.0) as client:
            recovered = client.get(f"https://127.0.0.1:{port}/healthz")
        assert recovered.status_code == 200
    finally:
        runtime.shutdown()


def test_real_tls_listener_reclaims_slow_headers_and_releases_port(
    monkeypatch, http_api_modules, tmp_path
):
    modules = http_api_modules
    cert_path, key_path = _write_self_signed_certificate(tmp_path)
    port = _reserve_ipv4_port()
    monkeypatch.setattr(
        modules.runtime,
        "global_config",
        {
            "server": {
                "ssl_certfile": str(cert_path),
                "ssl_keyfile": str(key_path),
            },
            "security": {"require_client_cert": False},
        },
    )
    policy = modules.config.HttpApiPolicy(
        host="127.0.0.1",
        port=port,
        ssl_certfile=str(cert_path),
        ssl_keyfile=str(key_path),
        max_concurrency=1,
        request_header_timeout_seconds=0.25,
        startup_timeout_seconds=5.0,
        shutdown_timeout_seconds=5.0,
    )
    app = FastAPI()

    @app.get("/healthz")
    def healthcheck():
        return {"status": "ok"}

    runtime = modules.runtime.HttpApiRuntime()
    assert runtime._create_ssl_context(policy).minimum_version == ssl.TLSVersion.TLSv1_3
    runtime.start(app, policy)
    try:
        assert runtime._active is not None
        assert runtime._active.thread.daemon is False
        with httpx.Client(verify=False, trust_env=False, timeout=5.0) as client:
            response = client.get(f"https://127.0.0.1:{port}/healthz")
        assert response.json() == {"status": "ok"}

        client_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client_context.check_hostname = False
        client_context.verify_mode = ssl.CERT_NONE
        with (
            socket.create_connection(("127.0.0.1", port), timeout=5.0) as connection,
            client_context.wrap_socket(
                connection, server_hostname="localhost"
            ) as held_connection,
            httpx.Client(verify=False, trust_env=False, timeout=5.0) as client,
        ):
            assert held_connection.version() == "TLSv1.3"
            rejected = client.get(f"https://127.0.0.1:{port}/healthz")
            assert rejected.status_code == 503
            held_connection.settimeout(2.0)
            assert held_connection.recv(1) == b""

        with httpx.Client(verify=False, trust_env=False, timeout=5.0) as client:
            recovered = client.get(f"https://127.0.0.1:{port}/healthz")
        assert recovered.status_code == 200

        with (
            socket.create_connection(("127.0.0.1", port), timeout=5.0) as connection,
            client_context.wrap_socket(
                connection, server_hostname="localhost"
            ) as dripping_connection,
        ):
            dripping_connection.settimeout(2.0)
            dripping_connection.sendall(
                b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n"
            )
            response_bytes = bytearray()
            while b'{"status":"ok"}' not in response_bytes:
                response_bytes.extend(dripping_connection.recv(4096))
            assert b"HTTP/1.1 200 OK" in response_bytes

            dripping_connection.sendall(b"G")
            dripping_connection.settimeout(0.05)
            disconnected = False
            for _ in range(20):
                try:
                    disconnected = dripping_connection.recv(1) == b""
                except TimeoutError:
                    try:
                        dripping_connection.sendall(b"X")
                    except OSError:
                        continue
                if disconnected:
                    break
            assert disconnected

        with httpx.Client(verify=False, trust_env=False, timeout=5.0) as client:
            recovered = client.get(f"https://127.0.0.1:{port}/healthz")
        assert recovered.status_code == 200
    finally:
        runtime.shutdown()
        runtime.shutdown()

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", port))


def test_listener_bind_failure_is_propagated(monkeypatch, http_api_modules, tmp_path):
    modules = http_api_modules
    cert_path, key_path = _write_self_signed_certificate(tmp_path)
    monkeypatch.setattr(
        modules.runtime,
        "global_config",
        {
            "server": {
                "ssl_certfile": str(cert_path),
                "ssl_keyfile": str(key_path),
            },
            "security": {"require_client_cert": False},
        },
    )
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen()
        port = listener.getsockname()[1]
        policy = modules.config.HttpApiPolicy(
            host="127.0.0.1",
            port=port,
            ssl_certfile=str(cert_path),
            ssl_keyfile=str(key_path),
            startup_timeout_seconds=5.0,
            shutdown_timeout_seconds=5.0,
        )
        runtime = modules.runtime.HttpApiRuntime()

        with pytest.raises(RuntimeError, match="Failed to start"):
            runtime.start(FastAPI(), policy)

    assert runtime._active is None
    runtime.shutdown()


def test_runtime_uses_exact_concurrency_and_rounded_shutdown_limits(
    monkeypatch, http_api_modules
):
    modules = http_api_modules
    instances = []

    class FakeServer:
        def __init__(self, config, startup_event):
            self.config = config
            self.started = False
            self.force_exit = False
            self._startup_event = startup_event
            self._exit_event = threading.Event()
            instances.append(self)

        @property
        def should_exit(self):
            return self._exit_event.is_set()

        @should_exit.setter
        def should_exit(self, value):
            if value:
                self._exit_event.set()

        def run(self):
            self.started = True
            self._startup_event.set()
            self._exit_event.wait(2.0)

    monkeypatch.setattr(modules.runtime, "_SignallingServer", FakeServer)
    policy = modules.config.HttpApiPolicy(
        max_concurrency=1,
        startup_timeout_seconds=1.0,
        shutdown_timeout_seconds=0.1,
    )
    runtime = modules.runtime.HttpApiRuntime()

    runtime.start(FastAPI(), policy)
    server = instances[0]
    assert server.config.limit_concurrency == 2
    assert server.config.request_header_timeout_seconds == 10.0
    assert server.config.http is modules.runtime._RequestHeaderTimeoutH11Protocol
    assert server.config.timeout_graceful_shutdown == 1
    runtime.shutdown()

    assert runtime._active is None


def test_post_start_failure_is_reported_and_clears_active(
    monkeypatch, http_api_modules
):
    modules = http_api_modules
    crash_event = threading.Event()
    errors = []

    class FakeLogger:
        def info(self, _message):
            return None

        def opt(self, **_kwargs):
            return self

        def error(self, message):
            errors.append(message)

    class FakeServer:
        def __init__(self, _config, startup_event):
            self.started = False
            self.should_exit = False
            self.force_exit = False
            self._startup_event = startup_event

        def run(self):
            self.started = True
            self._startup_event.set()
            crash_event.wait(2.0)
            raise RuntimeError("post-start crash")

    monkeypatch.setattr(modules.runtime, "_SignallingServer", FakeServer)
    monkeypatch.setattr(modules.runtime, "logger", FakeLogger())
    runtime = modules.runtime.HttpApiRuntime()
    runtime.start(FastAPI(), modules.config.HttpApiPolicy())
    active = runtime._active
    assert active is not None

    crash_event.set()
    active.thread.join(2.0)

    assert not active.thread.is_alive()
    assert isinstance(active.failure, RuntimeError)
    assert runtime._active is None
    assert errors == ["HTTP API server stopped unexpectedly after startup"]


def test_shutdown_force_exit_gets_a_second_join(monkeypatch, http_api_modules):
    modules = http_api_modules
    instances = []

    class FakeServer:
        def __init__(self, _config, startup_event):
            self.started = False
            self.should_exit = False
            self._force_exit = False
            self._startup_event = startup_event
            self._exit_event = threading.Event()
            instances.append(self)

        @property
        def force_exit(self):
            return self._force_exit

        @force_exit.setter
        def force_exit(self, value):
            self._force_exit = value
            if value:
                self._exit_event.set()

        def run(self):
            self.started = True
            self._startup_event.set()
            self._exit_event.wait(5.0)

    monkeypatch.setattr(modules.runtime, "_SignallingServer", FakeServer)
    monkeypatch.setattr(modules.runtime, "_SERVER_STOP_MARGIN_SECONDS", 0.01)
    runtime = modules.runtime.HttpApiRuntime()
    runtime.start(
        FastAPI(),
        modules.config.HttpApiPolicy(shutdown_timeout_seconds=0.01),
    )

    runtime.shutdown()

    assert instances[0].force_exit is True
    assert runtime._active is None


def test_startup_timeout_requests_shutdown_and_cleans_thread(
    monkeypatch, http_api_modules
):
    modules = http_api_modules

    class FakeServer:
        def __init__(self, _config, _startup_event):
            self.started = False
            self.force_exit = False
            self._exit_event = threading.Event()

        @property
        def should_exit(self):
            return self._exit_event.is_set()

        @should_exit.setter
        def should_exit(self, value):
            if value:
                self._exit_event.set()

        def run(self):
            self._exit_event.wait(1.0)

    monkeypatch.setattr(modules.runtime, "_SignallingServer", FakeServer)
    policy = modules.config.HttpApiPolicy(
        startup_timeout_seconds=0.01,
        shutdown_timeout_seconds=1.0,
    )
    runtime = modules.runtime.HttpApiRuntime()

    with pytest.raises(RuntimeError, match="Timed out"):
        runtime.start(FastAPI(), policy)

    assert runtime._active is None
