import base64
import hashlib
from types import SimpleNamespace
from unittest.mock import create_autospec
from urllib.parse import parse_qs, urlsplit

import orjson
import pytest

from include.extensions.oidc_sso import _extension as extension
from include.providers.caching import memory

pytestmark = pytest.mark.unit


class _Connection:
    def __init__(self, data):
        self.data = data
        self.response = None

    def conclude_request(self, code, data, message):
        self.response = {"code": code, "data": data, "message": message}

    def report_error(self, error, *, context):
        pytest.fail(f"{context}: {error!r}")


@pytest.fixture
def oidc_context(monkeypatch):
    config = {
        "extensions": {
            "oidc_sso": {
                "issuer": "https://new.example/",
                "client_id": "new-client",
                "client_secret": "private-client-secret",
                "redirect_uri": "https://client.example/callback",
                "state_ttl_seconds": 90,
            }
        },
        "sso": {
            "oidc": {
                "issuer": "https://legacy.example",
                "client_id": "legacy-client",
                "redirect_uri": "https://legacy.example/callback",
            }
        },
    }
    metadata = {
        "issuer": "https://new.example",
        "authorization_endpoint": "https://new.example/authorize",
        "token_endpoint": "https://new.example/token",
        "jwks_uri": "https://new.example/jwks",
    }
    response = create_autospec(
        extension.requests.Response, instance=True, spec_set=True
    )
    response.raise_for_status.return_value = None
    response.json.return_value = metadata
    discovery = create_autospec(extension.requests.get, return_value=response)
    caching = memory.MemoryCachingProvider()
    clock = SimpleNamespace(now=1_700_000_000.0)
    fixed_time = SimpleNamespace(time=lambda: clock.now)
    monkeypatch.setattr(extension, "global_config", config)
    monkeypatch.setattr(
        extension, "ProviderManager", lambda: SimpleNamespace(caching=caching)
    )
    monkeypatch.setattr(extension.requests, "get", discovery)
    monkeypatch.setattr(extension, "time", fixed_time)
    monkeypatch.setattr(memory, "time", fixed_time)
    return SimpleNamespace(
        config=config,
        metadata=metadata,
        discovery=discovery,
        caching=caching,
        clock=clock,
    )


@pytest.mark.parametrize(
    "requested_redirect", [None, "https://client.example/callback"]
)
def test_oidc_start_uses_extension_namespace_and_persists_pkce_state(
    oidc_context, requested_redirect
):
    data = {} if requested_redirect is None else {"redirect_uri": requested_redirect}
    handler_type = extension.ext_register_handlers()["sso_oidc_start"]
    connection = _Connection(
        handler_type.request_model.model_validate(data).model_dump(exclude_unset=True)
    )

    result = handler_type().handle(connection)

    assert result is not None
    assert result.code == 200
    assert connection.response["code"] == 200
    data = connection.response["data"]
    assert set(data) == {"authorization_url", "state", "expires_in"}
    assert data["expires_in"] == 90
    url = urlsplit(data["authorization_url"])
    assert (url.scheme, url.netloc, url.path) == (
        "https",
        "new.example",
        "/authorize",
    )
    query = parse_qs(url.query)
    assert query["client_id"] == ["new-client"]
    assert query["redirect_uri"] == ["https://client.example/callback"]
    assert query["scope"] == ["openid profile email"]
    assert query["state"] == [data["state"]]
    assert query["code_challenge_method"] == ["S256"]
    assert "client_secret" not in query
    assert "code_verifier" not in query
    oidc_context.discovery.assert_called_once_with(
        "https://new.example/.well-known/openid-configuration",
        timeout=extension.DEFAULT_HTTP_TIMEOUT_SECONDS,
    )
    stored = oidc_context.caching.get(extension.STATE_CACHE_PREFIX + data["state"])
    assert stored is not None
    state = orjson.loads(stored)
    assert state["state"] == data["state"]
    assert state["redirect_uri"] == "https://client.example/callback"
    assert state["created_at"] == 1_700_000_000.0
    assert query["nonce"] == [state["nonce"]]
    challenge = (
        base64.urlsafe_b64encode(
            hashlib.sha256(state["code_verifier"].encode("ascii")).digest()
        )
        .rstrip(b"=")
        .decode("ascii")
    )
    assert query["code_challenge"] == [challenge]
    assert state["code_verifier"] not in data["authorization_url"]
    assert "private-client-secret" not in repr(connection.response)
    oidc_context.clock.now = 1_700_000_091.0
    assert (
        oidc_context.caching.get(extension.STATE_CACHE_PREFIX + data["state"]) is None
    )


@pytest.mark.parametrize("missing", ["issuer", "client_id", "redirect_uri"])
def test_oidc_start_rejects_missing_configuration_before_http(oidc_context, missing):
    del oidc_context.config["extensions"]["oidc_sso"][missing]
    connection = _Connection({})

    result = extension.RequestOIDCStartHandler().handle(connection)

    assert result is not None
    assert result.code == 400
    assert connection.response["code"] == 400
    assert connection.response["data"] == {}
    assert missing in connection.response["message"]
    oidc_context.discovery.assert_not_called()


def test_oidc_start_does_not_read_legacy_configuration(oidc_context):
    del oidc_context.config["extensions"]["oidc_sso"]
    connection = _Connection({})

    result = extension.RequestOIDCStartHandler().handle(connection)

    assert result is not None
    assert result.code == 400
    assert connection.response == {
        "code": 400,
        "data": {},
        "message": "OIDC SSO configuration is missing: issuer, client_id, redirect_uri",
    }
    oidc_context.discovery.assert_not_called()


@pytest.mark.parametrize("ttl", [0, -1])
def test_oidc_start_rejects_nonpositive_state_ttl(oidc_context, ttl):
    oidc_context.config["extensions"]["oidc_sso"]["state_ttl_seconds"] = ttl
    connection = _Connection({})

    result = extension.RequestOIDCStartHandler().handle(connection)

    assert result is not None
    assert result.code == 400
    assert connection.response == {
        "code": 400,
        "data": {},
        "message": "OIDC state_ttl_seconds must be positive",
    }
    oidc_context.discovery.assert_not_called()


def test_oidc_start_rejects_redirect_uri_override(oidc_context):
    connection = _Connection({"redirect_uri": "https://other.example/callback"})

    result = extension.RequestOIDCStartHandler().handle(connection)

    assert result is not None
    assert result.code == 400
    assert connection.response == {
        "code": 400,
        "data": {},
        "message": "OIDC redirect_uri must match the configured redirect URI",
    }
    oidc_context.discovery.assert_not_called()


def test_oidc_start_rejects_discovery_issuer_mismatch(oidc_context):
    oidc_context.metadata["issuer"] = "https://other.example"
    connection = _Connection({})

    result = extension.RequestOIDCStartHandler().handle(connection)

    assert result is not None
    assert result.code == 400
    assert connection.response == {
        "code": 400,
        "data": {},
        "message": "OIDC discovery issuer does not match config",
    }
    oidc_context.discovery.assert_called_once()
