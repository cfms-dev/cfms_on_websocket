"""
OIDC SSO extension for CFMS, providing OpenID Connect Single Sign-On support.

This extension was primarily written by a large language model and was created for
experimental purposes. We make no guarantees regarding the functional reliability
of this extension.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from typing import Any

import jwt
import orjson
import requests
from authlib.integrations.requests_client import OAuth2Session
from loguru import logger as log

from include.config.settings import global_config
from include.database.models.identity import User, UserGroup
from include.database.session import Session
from include.domains.identity.commands.users import create_user
from include.domains.identity.sessions import (
    build_login_success_data,
    issue_login_token,
)
from include.exceptions.misc import UserNotActiveError
from include.extensions.manager import hookimpl
from include.providers.manager import ProviderManager
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler, Result

logger = log.bind(name="oidc_sso")

STATE_CACHE_PREFIX = "oidc_sso:state:"
METADATA_CACHE_PREFIX = "oidc_sso:metadata:"
DEFAULT_STATE_TTL_SECONDS = 300
DEFAULT_HTTP_TIMEOUT_SECONDS = 10
DEFAULT_SCOPE = "openid profile email"


class OIDCConfigurationError(ValueError):
    pass


class OIDCAuthenticationError(ValueError):
    pass


def _as_plain(value: Any) -> Any:
    if hasattr(value, "unwrap"):
        return value.unwrap()
    return value


def _get_oidc_config() -> dict[str, Any]:
    sso_cfg = _as_plain(global_config.get("sso", {})) or {}
    oidc_cfg = _as_plain(sso_cfg.get("oidc", {})) or {}

    issuer = str(oidc_cfg.get("issuer", "")).rstrip("/")
    client_id = str(oidc_cfg.get("client_id", ""))
    redirect_uri = str(oidc_cfg.get("redirect_uri", ""))

    return {
        "enabled": bool(oidc_cfg.get("enabled", False)),
        "issuer": issuer,
        "client_id": client_id,
        "client_secret": str(oidc_cfg.get("client_secret", "")),
        "redirect_uri": redirect_uri,
        "username_claim": str(oidc_cfg.get("username_claim", "preferred_username")),
        "auto_provision": bool(oidc_cfg.get("auto_provision", False)),
        "default_groups": list(oidc_cfg.get("default_groups", ["user"])),
        "state_ttl_seconds": int(
            oidc_cfg.get("state_ttl_seconds", DEFAULT_STATE_TTL_SECONDS)
        ),
        "scope": str(oidc_cfg.get("scope", DEFAULT_SCOPE)),
    }


def _require_enabled_config() -> dict[str, Any]:
    cfg = _get_oidc_config()
    if not cfg["enabled"]:
        raise OIDCConfigurationError("OIDC SSO is disabled")

    missing = [
        name for name in ("issuer", "client_id", "redirect_uri") if not cfg.get(name)
    ]
    if missing:
        raise OIDCConfigurationError(
            "OIDC SSO configuration is missing: " + ", ".join(missing)
        )

    if cfg["state_ttl_seconds"] <= 0:
        raise OIDCConfigurationError("OIDC state_ttl_seconds must be positive")

    return cfg


def _cache_get(key: str) -> Any:
    return ProviderManager().caching.get(key)


def _cache_set(key: str, value: Any, ttl: float, nx: bool = False) -> bool:
    return ProviderManager().caching.set(key, value, ttl=ttl, nx=nx)


def _cache_delete(key: str) -> None:
    ProviderManager().caching.delete(key)


def _load_cached_json(key: str) -> dict[str, Any] | None:
    raw = _cache_get(key)
    if raw is None:
        return None
    if isinstance(raw, (bytes, bytearray, memoryview)):
        raw = bytes(raw)
    try:
        return orjson.loads(raw)
    except orjson.JSONDecodeError:
        _cache_delete(key)
        return None


def _store_json(key: str, value: dict[str, Any], ttl: float, nx: bool = False) -> bool:
    return _cache_set(key, orjson.dumps(value).decode("utf-8"), ttl=ttl, nx=nx)


def _fetch_discovery_document(issuer: str) -> dict[str, Any]:
    response = requests.get(
        f"{issuer}/.well-known/openid-configuration",
        timeout=DEFAULT_HTTP_TIMEOUT_SECONDS,
    )
    response.raise_for_status()
    metadata = response.json()
    if not isinstance(metadata, dict):
        raise OIDCConfigurationError("OIDC discovery document is invalid")
    return metadata


def _get_provider_metadata(cfg: dict[str, Any]) -> dict[str, Any]:
    cache_key = (
        METADATA_CACHE_PREFIX
        + hashlib.sha256(cfg["issuer"].encode("utf-8")).hexdigest()
    )
    cached = _load_cached_json(cache_key)
    if cached is not None:
        return cached

    metadata = _fetch_discovery_document(cfg["issuer"])
    metadata_issuer = str(metadata.get("issuer", "")).rstrip("/")
    if metadata_issuer != cfg["issuer"]:
        raise OIDCConfigurationError("OIDC discovery issuer does not match config")

    required = ("authorization_endpoint", "token_endpoint", "jwks_uri")
    missing = [field for field in required if not metadata.get(field)]
    if missing:
        raise OIDCConfigurationError(
            "OIDC discovery document is missing: " + ", ".join(missing)
        )

    _store_json(cache_key, metadata, ttl=3600)
    return metadata


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _new_pkce_verifier() -> str:
    return _base64url(secrets.token_bytes(32))


def _pkce_challenge(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return _base64url(digest)


def _state_cache_key(state: str) -> str:
    return STATE_CACHE_PREFIX + state


def _save_state(cfg: dict[str, Any], state_data: dict[str, Any]) -> bool:
    return _store_json(
        _state_cache_key(state_data["state"]),
        state_data,
        ttl=cfg["state_ttl_seconds"],
        nx=True,
    )


def _pop_state(state: str) -> dict[str, Any] | None:
    cache_key = _state_cache_key(state)
    state_data = _load_cached_json(cache_key)
    _cache_delete(cache_key)
    return state_data


def _make_oauth_client(cfg: dict[str, Any], redirect_uri: str) -> OAuth2Session:
    token_auth_method = "client_secret_basic" if cfg["client_secret"] else "none"
    return OAuth2Session(
        client_id=cfg["client_id"],
        client_secret=cfg["client_secret"] or None,
        scope=cfg["scope"],
        redirect_uri=redirect_uri,
        token_endpoint_auth_method=token_auth_method,
    )


def _create_authorization_url(
    cfg: dict[str, Any],
    metadata: dict[str, Any],
    redirect_uri: str,
) -> tuple[str, dict[str, Any]]:
    for _attempt in range(3):
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)
        code_verifier = _new_pkce_verifier()

        client = _make_oauth_client(cfg, redirect_uri)
        authorization_url, returned_state = client.create_authorization_url(
            metadata["authorization_endpoint"],
            state=state,
            nonce=nonce,
            code_challenge=_pkce_challenge(code_verifier),
            code_challenge_method="S256",
        )
        state_data = {
            "state": returned_state,
            "nonce": nonce,
            "code_verifier": code_verifier,
            "redirect_uri": redirect_uri,
            "created_at": time.time(),
        }
        if _save_state(cfg, state_data):
            return authorization_url, state_data

    raise OIDCConfigurationError("Could not allocate a unique OIDC state")


def _exchange_code_for_token(
    cfg: dict[str, Any],
    metadata: dict[str, Any],
    code: str,
    state_data: dict[str, Any],
) -> dict[str, Any]:
    client = _make_oauth_client(cfg, state_data["redirect_uri"])
    token = client.fetch_token(
        metadata["token_endpoint"],
        code=code,
        grant_type="authorization_code",
        redirect_uri=state_data["redirect_uri"],
        code_verifier=state_data["code_verifier"],
    )
    return dict(token)


def _validate_id_token(
    cfg: dict[str, Any],
    metadata: dict[str, Any],
    token: dict[str, Any],
    expected_nonce: str,
) -> dict[str, Any]:
    id_token = token.get("id_token")
    if not id_token:
        raise OIDCAuthenticationError("OIDC provider did not return an ID token")

    jwks_client = jwt.PyJWKClient(metadata["jwks_uri"])
    signing_key = jwks_client.get_signing_key_from_jwt(id_token)
    supported_algs = metadata.get("id_token_signing_alg_values_supported") or ["RS256"]
    algorithms = [alg for alg in supported_algs if alg != "none"]
    claims = jwt.decode(
        id_token,
        signing_key.key,
        algorithms=algorithms,
        audience=cfg["client_id"],
        issuer=metadata["issuer"],
        options={"require": ["exp", "iat", "iss", "sub", "aud"]},
    )

    if claims.get("nonce") != expected_nonce:
        raise OIDCAuthenticationError("OIDC nonce validation failed")

    audience = claims.get("aud")
    if isinstance(audience, list) and len(audience) > 1:
        if claims.get("azp") != cfg["client_id"]:
            raise OIDCAuthenticationError("OIDC authorized party validation failed")

    return claims


def _resolve_or_create_user(cfg: dict[str, Any], claims: dict[str, Any]) -> User | None:
    username = claims.get(cfg["username_claim"])
    if not isinstance(username, str) or not username:
        raise OIDCAuthenticationError(
            f"OIDC claim '{cfg['username_claim']}' is missing"
        )

    with Session() as session:
        user = session.get(User, username)
        if user is not None:
            return user

    if not cfg["auto_provision"]:
        return None

    default_groups = cfg["default_groups"]
    with Session() as session:
        existing_groups = {
            group_name
            for (group_name,) in session.query(UserGroup.group_name)
            .filter(UserGroup.group_name.in_(default_groups))
            .all()
        }
    missing_groups = set(default_groups) - existing_groups
    if missing_groups:
        raise OIDCConfigurationError(
            "OIDC auto_provision references missing groups: "
            + ", ".join(sorted(missing_groups))
        )

    now = time.time()
    create_user(
        username=username,
        password=secrets.token_urlsafe(48),
        nickname=claims.get("name") or username,
        groups=[
            {"group_name": group_name, "start_time": now, "end_time": None}
            for group_name in default_groups
        ],
        permissions=[],
    )

    with Session() as session:
        return session.get(User, username)


class RequestOIDCStartHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "redirect_uri": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler) -> Result | None:
        try:
            cfg = _require_enabled_config()
            redirect_uri = handler.data.get("redirect_uri") or cfg["redirect_uri"]
            metadata = _get_provider_metadata(cfg)
            authorization_url, state_data = _create_authorization_url(
                cfg, metadata, redirect_uri
            )
        except OIDCConfigurationError as exc:
            handler.conclude_request(400, {}, str(exc))
            return Result(code=400)
        except Exception as exc:
            logger.exception("Failed to start OIDC SSO")
            handler.report_error(exc, context="Failed to start OIDC SSO")
            return None

        handler.conclude_request(
            200,
            {
                "authorization_url": authorization_url,
                "state": state_data["state"],
                "expires_in": cfg["state_ttl_seconds"],
            },
            "OIDC authorization URL created",
        )
        return Result(code=200)


class RequestOIDCCallbackHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "state": {"type": "string", "minLength": 1},
            "code": {"type": "string", "minLength": 1},
            "redirect_uri": {"type": "string", "minLength": 1},
            "error": {"type": "string", "minLength": 1},
            "error_description": {"type": "string"},
        },
        "required": ["state"],
        "additionalProperties": False,
    }

    def handle(self, handler: ConnectionHandler) -> Result | None:
        state = handler.data["state"]
        error = handler.data.get("error")
        if error:
            message = handler.data.get("error_description") or error
            handler.conclude_request(401, {"error": error}, message)
            return Result(code=401)

        code = handler.data.get("code")
        if not code:
            handler.conclude_request(400, {}, "OIDC authorization code is required")
            return Result(code=400)

        try:
            cfg = _require_enabled_config()
            state_data = _pop_state(state)
            if state_data is None:
                handler.conclude_request(401, {}, "Invalid or expired OIDC state")
                return Result(code=401)

            if handler.data.get("redirect_uri"):
                state_redirect_uri = state_data["redirect_uri"]
                if handler.data["redirect_uri"] != state_redirect_uri:
                    handler.conclude_request(401, {}, "OIDC redirect_uri mismatch")
                    return Result(code=401)

            metadata = _get_provider_metadata(cfg)
            oidc_token = _exchange_code_for_token(cfg, metadata, code, state_data)
            claims = _validate_id_token(cfg, metadata, oidc_token, state_data["nonce"])
            user = _resolve_or_create_user(cfg, claims)
            if user is None:
                handler.conclude_request(401, {}, "SSO user is not allowed")
                return Result(code=401)

            with Session() as session:
                user = User.get_existing(session, user.username)
                token = issue_login_token(user)
                data = build_login_success_data(session, user, token)
        except UserNotActiveError:
            handler.conclude_request(4003, {}, "User account is not active")
            return Result(code=4003)
        except (OIDCConfigurationError, OIDCAuthenticationError, jwt.PyJWTError) as exc:
            handler.conclude_request(401, {}, str(exc))
            return Result(code=401)
        except Exception as exc:
            logger.exception("Failed to complete OIDC SSO")
            handler.report_error(exc, context="Failed to complete OIDC SSO")
            return None

        handler.conclude_request(200, data, "Login successful")
        return Result(code=200, target=user.username, username=user.username)


@hookimpl
def ext_register_handlers() -> dict[str, type[RequestHandler]]:
    return {
        "sso_oidc_start": RequestOIDCStartHandler,
        "sso_oidc_callback": RequestOIDCCallbackHandler,
    }


@hookimpl
def ext_register_whitelisted_actions() -> set[str]:
    return {"sso_oidc_start", "sso_oidc_callback"}
