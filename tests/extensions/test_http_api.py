import datetime
import socket
import ssl
import threading
from types import SimpleNamespace

import httpx
import jwt
import pluggy
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from fastapi import APIRouter, Depends, FastAPI, Request
from fastapi.testclient import TestClient

from include.domains.access.permissions import Permissions
from include.extensions import manager as extension_manager
from include.extensions.http_api import application, contracts, runtime, security


@pytest.fixture
def http_api_modules(monkeypatch, protected_test_config):
    monkeypatch.chdir(protected_test_config.src_dir)
    from include.extensions.http_api import (
        config,
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
    assert policy.cors_allowed_origins == ()


def test_http_extension_adds_hook_spec_to_core_manager(http_api_modules):
    from include.extensions.http_api import _extension

    assert hasattr(extension_manager.pm.hook, "ext_register_http_routers")
    assert _extension.http_hookimpl is extension_manager.hookimpl


@pytest.mark.parametrize(
    "section",
    [
        {"unknown": True},
        {"ssl_certfile": "cert.pem"},
        {"ssl_keyfile": "key.pem"},
        {"cors_allowed_origins": ["*"]},
        {"host": " "},
        {"port": 0},
    ],
)
def test_invalid_http_configuration_is_rejected(http_api_modules, section):
    config = {"extensions": {"http_api": section}}

    with pytest.raises(Exception, match="Invalid extensions.http_api"):
        http_api_modules.config.HttpApiPolicy.from_config(config)


def test_registered_router_is_http_only_and_docs_are_disabled(
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

    with TestClient(app) as client:
        assert client.get("/api/v1/example/value").json() == {"value": 42}
        assert client.get("/healthz").json() == {"status": "ok"}
        assert client.get("/api/v1/openapi.json").status_code == 404
        assert client.get("/api/v1/docs").status_code == 404

    websocket_actions = set()
    for result in extension_manager.pm.hook.ext_register_handlers():
        websocket_actions.update(result)
    assert "value" not in websocket_actions


def test_docs_use_fixed_api_paths_when_enabled(monkeypatch, http_api_modules):
    modules = http_api_modules
    _allow_all_subnets(monkeypatch, modules.application)
    _install_http_plugins(monkeypatch, modules, [])
    policy = modules.config.HttpApiPolicy(docs_enabled=True)
    app = modules.application.build_http_application(policy)

    with TestClient(app) as client:
        assert client.get("/api/v1/openapi.json").status_code == 200
        assert client.get("/api/v1/docs").status_code == 200


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


def test_body_limit_and_exception_boundary_do_not_echo_sensitive_data(
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
    policy = modules.config.HttpApiPolicy(max_request_body_bytes=4)
    app = modules.application.build_http_application(policy)

    with TestClient(app, raise_server_exceptions=False) as client:
        oversized = client.post("/api/v1/example/echo", content=b"12345")
        assert oversized.status_code == 413

        failure = client.post(
            "/api/v1/example/echo",
            content=b"key",
            headers={"Authorization": "Bearer highly-sensitive-token"},
        )

    assert failure.status_code == 500
    payload = failure.json()
    assert set(payload) == {"detail", "log_id"}
    assert "highly-sensitive-token" not in failure.text
    assert "key" not in failure.text


def test_banned_client_is_rejected(monkeypatch, http_api_modules):
    modules = http_api_modules
    monkeypatch.setattr(
        modules.application.LoginGuard,
        "evaluate_subnet_access",
        classmethod(lambda _cls, _address: SimpleNamespace(allowed=False)),
    )
    _install_http_plugins(monkeypatch, modules, [])
    app = modules.application.build_http_application(modules.config.HttpApiPolicy())

    with TestClient(app) as client:
        response = client.get("/healthz")

    assert response.status_code == 403


def test_trusted_proxy_resolution_uses_rightmost_untrusted_address(
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

    with TestClient(app, client=("10.0.0.2", 5000)) as client:
        response = client.get(
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
def test_bearer_authentication_fully_validates_user_token(
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

    with TestClient(app) as client:
        response = client.get("/", headers=headers)

    assert response.status_code == status_code
    if status_code == 401:
        assert response.headers["WWW-Authenticate"] == "Bearer"


def test_permission_and_rate_limit_dependencies(monkeypatch, http_api_modules):
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

    with TestClient(app) as client:
        limited_response = client.get("/limited")
        forbidden_response = client.get("/forbidden")

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


def test_real_tls_listener_becomes_ready_and_releases_port(
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
    finally:
        runtime.shutdown(5.0)
        runtime.shutdown(5.0)

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
    runtime.shutdown(5.0)


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
