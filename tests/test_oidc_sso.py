import importlib
import os
from pathlib import Path
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import jwt
import orjson
import pytest

from include.exceptions.misc import UserNotActiveError


@pytest.fixture(scope="module")
def oidc():
    old_cwd = os.getcwd()
    src_dir = Path(__file__).resolve().parents[1] / "src"
    os.chdir(src_dir)
    try:
        module = importlib.import_module("include.extensions.oidc_sso._extension")
    finally:
        os.chdir(old_cwd)
    yield module
    try:
        from sqlalchemy.orm import close_all_sessions

        from include.database.session import engine

        close_all_sessions()
        engine.dispose()
    except Exception:
        pass


class DummyConfig:
    def __init__(self, oidc_config):
        self._oidc_config = oidc_config

    def get(self, key, default=None):
        if key == "sso":
            return {"oidc": self._oidc_config}
        return default


class DummyHandler:
    def __init__(self, data):
        self.data = data
        self.responses = []

    def conclude_request(self, code, data=None, message=""):
        self.responses.append(
            {
                "code": code,
                "data": data if data is not None else {},
                "message": message,
            }
        )

    def report_error(self, exc, code=500, context=None, send_to_client=True):
        if send_to_client:
            self.conclude_request(code, {"error": type(exc).__name__}, context or "")
        return "log-id"


def _enabled_config(**overrides):
    config = {
        "enabled": True,
        "issuer": "https://issuer.example",
        "client_id": "cfms-client",
        "client_secret": "secret",
        "redirect_uri": "https://client.example/callback",
        "username_claim": "preferred_username",
        "auto_provision": False,
        "default_groups": ["user"],
    }
    config.update(overrides)
    return config


def _metadata():
    return {
        "issuer": "https://issuer.example",
        "authorization_endpoint": "https://issuer.example/authorize",
        "token_endpoint": "https://issuer.example/token",
        "jwks_uri": "https://issuer.example/jwks",
    }


def _install_memory_cache(monkeypatch, oidc):
    cache = {}

    def cache_get(key):
        item = cache.get(key)
        if item is None:
            return None
        return item["value"]

    def cache_set(key, value, ttl=None, nx=False):
        if nx and key in cache:
            return False
        cache[key] = {"value": value, "ttl": ttl}
        return True

    def cache_delete(key):
        cache.pop(key, None)

    monkeypatch.setattr(oidc, "_cache_get", cache_get)
    monkeypatch.setattr(oidc, "_cache_set", cache_set)
    monkeypatch.setattr(oidc, "_cache_delete", cache_delete)
    return cache


def test_oidc_extension_registers_handlers_whitelist_and_enabled_flag(
    monkeypatch, oidc
):
    handlers = oidc.ext_register_handlers()

    assert handlers["sso_oidc_start"] is oidc.RequestOIDCStartHandler
    assert handlers["sso_oidc_callback"] is oidc.RequestOIDCCallbackHandler
    assert oidc.ext_register_whitelisted_actions() == {
        "sso_oidc_start",
        "sso_oidc_callback",
    }

    monkeypatch.setattr(oidc, "global_config", DummyConfig(_enabled_config()))
    assert oidc.ext_register_extension_flags() == {"oidc_sso"}

    monkeypatch.setattr(
        oidc, "global_config", DummyConfig(_enabled_config(enabled=False))
    )
    assert oidc.ext_register_extension_flags() == set()


def test_oidc_start_creates_authorization_url_and_state(monkeypatch, oidc):
    monkeypatch.setattr(oidc, "global_config", DummyConfig(_enabled_config()))
    monkeypatch.setattr(oidc, "_fetch_discovery_document", lambda issuer: _metadata())
    cache = _install_memory_cache(monkeypatch, oidc)

    handler = DummyHandler({})
    result = oidc.RequestOIDCStartHandler().handle(handler)

    assert result.code == 200
    response = handler.responses[-1]
    data = response["data"]
    assert response["code"] == 200
    assert data["expires_in"] == 300

    parsed = urlparse(data["authorization_url"])
    query = parse_qs(parsed.query)
    assert f"{parsed.scheme}://{parsed.netloc}{parsed.path}" == (
        "https://issuer.example/authorize"
    )
    assert query["client_id"] == ["cfms-client"]
    assert query["redirect_uri"] == ["https://client.example/callback"]
    assert query["response_type"] == ["code"]
    assert query["scope"] == ["openid profile email"]
    assert query["state"] == [data["state"]]
    assert query["code_challenge_method"] == ["S256"]
    assert query["nonce"]

    state_entry = cache[oidc.STATE_CACHE_PREFIX + data["state"]]
    state_data = orjson.loads(state_entry["value"])
    assert state_entry["ttl"] == 300
    assert state_data["state"] == data["state"]
    assert state_data["nonce"] == query["nonce"][0]
    assert state_data["redirect_uri"] == "https://client.example/callback"
    assert state_data["code_verifier"]


def test_oidc_start_rejects_redirect_uri_override(monkeypatch, oidc):
    monkeypatch.setattr(oidc, "global_config", DummyConfig(_enabled_config()))
    handler = DummyHandler({"redirect_uri": "https://attacker.example/callback"})

    result = oidc.RequestOIDCStartHandler().handle(handler)

    assert result.code == 400
    assert handler.responses[-1] == {
        "code": 400,
        "data": {},
        "message": "OIDC redirect_uri must match the configured redirect URI",
    }


def test_oidc_callback_success_uses_existing_login_response(monkeypatch, oidc):
    user = SimpleNamespace(username="alice", last_login=None)
    session_events = []
    monkeypatch.setattr(oidc, "global_config", DummyConfig(_enabled_config()))
    monkeypatch.setattr(oidc.time, "time", lambda: 123.0)
    monkeypatch.setattr(oidc, "_pop_state", lambda state: {"nonce": "nonce"})
    monkeypatch.setattr(oidc, "_get_provider_metadata", lambda cfg: _metadata())
    monkeypatch.setattr(
        oidc, "_exchange_code_for_token", lambda cfg, metadata, code, state: {}
    )
    monkeypatch.setattr(
        oidc,
        "_validate_id_token",
        lambda cfg, metadata, token, expected_nonce: {"preferred_username": "alice"},
    )
    monkeypatch.setattr(oidc, "_resolve_or_create_user", lambda cfg, claims: user)
    monkeypatch.setattr(oidc, "issue_login_token", lambda resolved_user: "token")

    def build_login_success_data(session, resolved_user, token):
        session_events.append(("build", resolved_user.last_login))
        return {"token": "cfms-token"}

    monkeypatch.setattr(oidc, "build_login_success_data", build_login_success_data)

    class DummySession:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return None

        def get(self, model, ident):
            assert ident == "alice"
            return user

        def commit(self):
            session_events.append(("commit", user.last_login))
            del user.username

    monkeypatch.setattr(oidc, "Session", DummySession)

    handler = DummyHandler({"state": "state", "code": "code"})
    result = oidc.RequestOIDCCallbackHandler().handle(handler)

    assert result.code == 200
    assert result.target == "alice"
    assert user.last_login == 123.0
    assert session_events == [("build", None), ("commit", 123.0)]
    assert handler.responses[-1] == {
        "code": 200,
        "data": {"token": "cfms-token"},
        "message": "Login successful",
    }


def test_oidc_callback_rejects_expired_state(monkeypatch, oidc):
    monkeypatch.setattr(oidc, "global_config", DummyConfig(_enabled_config()))
    monkeypatch.setattr(oidc, "_pop_state", lambda state: None)

    handler = DummyHandler({"state": "expired", "code": "code"})
    result = oidc.RequestOIDCCallbackHandler().handle(handler)

    assert result.code == 401
    assert handler.responses[-1]["message"] == "Invalid or expired OIDC state"


def test_oidc_callback_rejects_unknown_user(monkeypatch, oidc):
    monkeypatch.setattr(oidc, "global_config", DummyConfig(_enabled_config()))
    monkeypatch.setattr(oidc, "_pop_state", lambda state: {"nonce": "nonce"})
    monkeypatch.setattr(oidc, "_get_provider_metadata", lambda cfg: _metadata())
    monkeypatch.setattr(
        oidc, "_exchange_code_for_token", lambda cfg, metadata, code, state: {}
    )
    monkeypatch.setattr(
        oidc,
        "_validate_id_token",
        lambda cfg, metadata, token, expected_nonce: {"preferred_username": "alice"},
    )
    monkeypatch.setattr(oidc, "_resolve_or_create_user", lambda cfg, claims: None)

    handler = DummyHandler({"state": "state", "code": "code"})
    result = oidc.RequestOIDCCallbackHandler().handle(handler)

    assert result.code == 401
    assert handler.responses[-1]["message"] == "SSO user is not allowed"


def test_oidc_callback_rejects_disabled_user(monkeypatch, oidc):
    user = SimpleNamespace(username="alice")
    monkeypatch.setattr(oidc, "global_config", DummyConfig(_enabled_config()))
    monkeypatch.setattr(oidc, "_pop_state", lambda state: {"nonce": "nonce"})
    monkeypatch.setattr(oidc, "_get_provider_metadata", lambda cfg: _metadata())
    monkeypatch.setattr(
        oidc, "_exchange_code_for_token", lambda cfg, metadata, code, state: {}
    )
    monkeypatch.setattr(
        oidc,
        "_validate_id_token",
        lambda cfg, metadata, token, expected_nonce: {"preferred_username": "alice"},
    )
    monkeypatch.setattr(oidc, "_resolve_or_create_user", lambda cfg, claims: user)
    monkeypatch.setattr(
        oidc,
        "issue_login_token",
        lambda resolved_user: (_ for _ in ()).throw(UserNotActiveError()),
    )

    class DummySession:
        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc_value, traceback):
            return None

        def get(self, model, ident):
            return user

    monkeypatch.setattr(oidc, "Session", DummySession)

    handler = DummyHandler({"state": "state", "code": "code"})
    result = oidc.RequestOIDCCallbackHandler().handle(handler)

    assert result.code == 4003
    assert handler.responses[-1]["message"] == "User account is not active"


def test_validate_id_token_checks_signature_audience_issuer_and_nonce(
    monkeypatch, oidc
):
    class DummyKey:
        key = "public-key"

    class DummyJWKClient:
        def __init__(self, jwks_uri):
            assert jwks_uri == "https://issuer.example/jwks"

        def get_signing_key_from_jwt(self, token):
            assert token == "id-token"
            return DummyKey()

    def decode(token, key, algorithms, audience, issuer, options):
        assert token == "id-token"
        assert key == "public-key"
        assert algorithms == ["RS256"]
        assert audience == "cfms-client"
        assert issuer == "https://issuer.example"
        assert options["require"] == ["exp", "iat", "iss", "sub", "aud"]
        return {
            "iss": issuer,
            "aud": audience,
            "sub": "subject",
            "iat": 1,
            "exp": 2,
            "nonce": "expected",
            "preferred_username": "alice",
        }

    monkeypatch.setattr(oidc.jwt, "PyJWKClient", DummyJWKClient)
    monkeypatch.setattr(oidc.jwt, "decode", decode)

    claims = oidc._validate_id_token(
        {"client_id": "cfms-client"},
        _metadata(),
        {"id_token": "id-token"},
        "expected",
    )

    assert claims["preferred_username"] == "alice"


def test_validate_id_token_rejects_nonce_mismatch(monkeypatch, oidc):
    class DummyKey:
        key = "public-key"

    class DummyJWKClient:
        def __init__(self, jwks_uri):
            pass

        def get_signing_key_from_jwt(self, token):
            return DummyKey()

    monkeypatch.setattr(oidc.jwt, "PyJWKClient", DummyJWKClient)
    monkeypatch.setattr(
        oidc.jwt,
        "decode",
        lambda *args, **kwargs: {
            "iss": "https://issuer.example",
            "aud": "cfms-client",
            "sub": "subject",
            "iat": 1,
            "exp": 2,
            "nonce": "wrong",
        },
    )

    try:
        oidc._validate_id_token(
            {"client_id": "cfms-client"},
            _metadata(),
            {"id_token": "id-token"},
            "expected",
        )
    except oidc.OIDCAuthenticationError as exc:
        assert str(exc) == "OIDC nonce validation failed"
    else:
        raise AssertionError("Expected nonce mismatch to be rejected")


def test_validate_id_token_surfaces_audience_or_issuer_errors(monkeypatch, oidc):
    class DummyKey:
        key = "public-key"

    class DummyJWKClient:
        def __init__(self, jwks_uri):
            pass

        def get_signing_key_from_jwt(self, token):
            return DummyKey()

    def decode(*args, **kwargs):
        raise jwt.InvalidAudienceError("Audience doesn't match")

    monkeypatch.setattr(oidc.jwt, "PyJWKClient", DummyJWKClient)
    monkeypatch.setattr(oidc.jwt, "decode", decode)

    try:
        oidc._validate_id_token(
            {"client_id": "cfms-client"},
            _metadata(),
            {"id_token": "id-token"},
            "expected",
        )
    except jwt.InvalidAudienceError:
        pass
    else:
        raise AssertionError("Expected PyJWT audience errors to surface")
