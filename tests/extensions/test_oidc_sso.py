import base64
import datetime
import hashlib
from types import SimpleNamespace
from unittest.mock import create_autospec
from urllib.parse import parse_qs, urlsplit

import jwt
import orjson
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

import include.database.models  # noqa: F401
from include.database.models import identity as identity_models
from include.database.models.auth import (
    UserPasswordCredential,
)
from include.database.models.identity import User, UserGroup, UserStatus
from include.database.session import Base
from include.domains.identity.auth import auth_registry, flows
from include.domains.identity.auth.providers import totp
from include.domains.identity.auth.types import AuthPurpose
from include.domains.identity.commands import users as user_commands
from include.domains.identity.commands.auth_policies import replace_auth_policy
from include.domains.identity.handlers import auth
from include.domains.identity.handlers.auth import RequestLoginHandler
from include.extensions.oidc_sso import _extension as extension
from include.extensions.oidc_sso.credentials import bind_oidc_identity
from include.extensions.oidc_sso.models import OIDCBase, UserOidcCredential
from include.providers.caching import memory


class _Connection:
    def __init__(self, data):
        self.data = data
        self.user_id = None
        self.stream = SimpleNamespace(
            connection=SimpleNamespace(
                _ws=SimpleNamespace(
                    remote_address=("127.0.0.1", 1), request=SimpleNamespace(headers={})
                )
            )
        )
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
@pytest.mark.unit
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
@pytest.mark.unit
def test_oidc_start_rejects_missing_configuration_before_http(oidc_context, missing):
    del oidc_context.config["extensions"]["oidc_sso"][missing]
    connection = _Connection({})

    result = extension.RequestOIDCStartHandler().handle(connection)

    assert result is not None
    assert result.code == 400
    assert connection.response["code"] == 400
    assert connection.response["data"] == {}
    oidc_context.discovery.assert_not_called()


@pytest.mark.unit
def test_oidc_start_does_not_read_legacy_configuration(oidc_context):
    del oidc_context.config["extensions"]["oidc_sso"]
    connection = _Connection({})

    result = extension.RequestOIDCStartHandler().handle(connection)

    assert result is not None
    assert result.code == 400
    assert connection.response["code"] == 400
    assert connection.response["data"] == {}
    oidc_context.discovery.assert_not_called()


@pytest.mark.parametrize("ttl", [0, -1])
@pytest.mark.unit
def test_oidc_start_rejects_nonpositive_state_ttl(oidc_context, ttl):
    oidc_context.config["extensions"]["oidc_sso"]["state_ttl_seconds"] = ttl
    connection = _Connection({})

    result = extension.RequestOIDCStartHandler().handle(connection)

    assert result is not None
    assert result.code == 400
    assert connection.response["code"] == 400
    assert connection.response["data"] == {}
    oidc_context.discovery.assert_not_called()


@pytest.mark.unit
def test_oidc_start_rejects_redirect_uri_override(oidc_context):
    connection = _Connection({"redirect_uri": "https://other.example/callback"})

    result = extension.RequestOIDCStartHandler().handle(connection)

    assert result is not None
    assert result.code == 400
    assert connection.response["code"] == 400
    assert connection.response["data"] == {}
    oidc_context.discovery.assert_not_called()


@pytest.mark.unit
def test_oidc_start_rejects_discovery_issuer_mismatch(oidc_context):
    oidc_context.metadata["issuer"] = "https://other.example"
    connection = _Connection({})

    result = extension.RequestOIDCStartHandler().handle(connection)

    assert result is not None
    assert result.code == 400
    assert connection.response["code"] == 400
    assert connection.response["data"] == {}
    oidc_context.discovery.assert_called_once()


@pytest.fixture(scope="module")
def oidc_signing_keys():
    return (
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
        rsa.generate_private_key(public_exponent=65537, key_size=2048),
    )


@pytest.fixture
def oidc_callback_context(
    monkeypatch, oidc_context, oidc_signing_keys, sqlite_engine_factory
):
    database = sqlite_engine_factory()
    Base.metadata.create_all(database)
    OIDCBase.metadata.create_all(database)
    sessions = sessionmaker(bind=database)
    monkeypatch.setattr(extension, "Session", sessions)
    monkeypatch.setattr(auth, "Session", sessions)
    monkeypatch.setattr(
        flows.LoginGuard, "evaluate", lambda *a: SimpleNamespace(allowed=True)
    )
    monkeypatch.setattr(flows.LoginGuard, "report_success", lambda *a, **kw: None)
    monkeypatch.setattr(flows.LoginGuard, "report_failure", lambda *a, **kw: None)
    monkeypatch.setattr(identity_models, "time", extension.time)
    monkeypatch.setattr(
        auth_registry,
        "_providers",
        {**auth_registry._providers, "oidc": extension.OIDCAuthProvider()},
    )
    monkeypatch.setattr(user_commands, "Session", sessions)
    with sessions.begin() as session:
        session.add(
            User(
                username="alice",
                secret_key="local-user-secret-with-at-least-32-bytes",
                created_time=0.0,
                last_login=10.0,
            )
        )

    with sessions.begin() as session:
        user = session.scalar(select(User).where(User.username == "alice"))
        credential = bind_oidc_identity(
            session, user, "https://new.example", "provider-subject-alice"
        )
        replace_auth_policy(
            session,
            user,
            AuthPurpose.LOGIN,
            [
                [
                    {
                        "method": "oidc",
                        "credential_ids": [credential.id],
                    }
                ]
            ],
            expected_revision=0,
        )

    oidc_context.clock.now = datetime.datetime.now(datetime.UTC).timestamp()
    start = _Connection({})
    assert extension.RequestOIDCStartHandler().handle(start).code == 200
    state = start.response["data"]["state"]
    cached_state = orjson.loads(
        oidc_context.caching.get(extension.STATE_CACHE_PREFIX + state)
    )
    signing_key, wrong_signing_key = oidc_signing_keys
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(signing_key.public_key(), as_dict=True)
    jwk.update(kid="provider-key", use="sig", alg="RS256")
    jwks_fetch = create_autospec(
        jwt.PyJWKClient.fetch_data, return_value={"keys": [jwk]}
    )
    monkeypatch.setattr(jwt.PyJWKClient, "fetch_data", jwks_fetch)
    context = SimpleNamespace(
        sessions=sessions,
        config=oidc_context.config,
        clock=oidc_context.clock,
        caching=oidc_context.caching,
        state_key=extension.STATE_CACHE_PREFIX + state,
        request_data={"state": state, "code": "authorization-code"},
        cached_state=cached_state,
        claims={
            "iss": "https://new.example",
            "sub": "provider-subject-alice",
            "aud": "new-client",
            "iat": int(oidc_context.clock.now) - 60,
            "exp": int(oidc_context.clock.now) + 300,
            "nonce": cached_state["nonce"],
            "preferred_username": "alice",
        },
        signing_key=signing_key,
        wrong_signing_key=wrong_signing_key,
        algorithm="RS256",
        include_id_token=True,
        token_requests=[],
        jwks_fetch=jwks_fetch,
    )

    def token_response(_session, request, **_kwargs):
        context.token_requests.append(request)
        token = {
            "access_token": "provider-access-token",
            "token_type": "Bearer",
        }
        if context.include_id_token:
            token["id_token"] = jwt.encode(
                context.claims,
                context.signing_key,
                algorithm=context.algorithm,
                headers={"kid": "provider-key"},
            )
        response = extension.requests.Response()
        response.status_code = 200
        response.url = request.url
        response.request = request
        response._content = orjson.dumps(token)
        return response

    monkeypatch.setattr(
        extension.requests.Session,
        "send",
        create_autospec(extension.requests.Session.send, side_effect=token_response),
    )
    return context


@pytest.mark.component
@pytest.mark.parametrize("redirect_uri", [None, "https://client.example/callback"])
@pytest.mark.parametrize("entrypoint", ["callback", "login"])
def test_oidc_callback_issues_local_token_and_commits_login(
    oidc_callback_context, redirect_uri, entrypoint
):
    context = oidc_callback_context
    request_data = context.request_data.copy()
    if redirect_uri is not None:
        request_data["redirect_uri"] = redirect_uri
    connection = _Connection(request_data)

    if entrypoint == "callback":
        result = extension.RequestOIDCCallbackHandler().handle(connection)
    else:
        connection.data = {"method": "oidc", "credential": request_data}
        result = RequestLoginHandler().handle(connection)

    assert (result.code, result.target) == (200, "alice")
    assert connection.response["code"] == 200
    data = connection.response["data"]
    with context.sessions() as session:
        user = session.scalar(select(User).where(User.username == "alice"))
        assert user.last_login == context.clock.now
        assert user.is_token_valid(data["token"])
        payload = jwt.decode(data["token"], user.secret_key, algorithms=["HS256"])
        assert payload["sub"] == str(user.id)
        assert result.user_id == user.id
        assert data["exp"] == payload["exp"]
    assert context.caching.get(context.state_key) is None
    assert len(context.token_requests) == 1
    request = context.token_requests[0]
    assert (request.method, request.url) == ("POST", "https://new.example/token")
    body = parse_qs(request.body)
    assert body["grant_type"] == ["authorization_code"]
    assert body["code"] == ["authorization-code"]
    assert body["redirect_uri"] == ["https://client.example/callback"]
    assert body["code_verifier"] == [context.cached_state["code_verifier"]]
    assert "provider-access-token" not in repr(connection.response)
    assert context.cached_state["code_verifier"] not in repr(connection.response)


@pytest.mark.component
@pytest.mark.parametrize("state_kind", ["missing", "expired"])
def test_oidc_callback_rejects_unavailable_state_before_token_exchange(
    oidc_callback_context, state_kind
):
    context = oidc_callback_context
    data = context.request_data.copy()
    if state_kind == "missing":
        data["state"] = "unknown-state"
    else:
        context.clock.now += 91
    connection = _Connection(data)

    result = extension.RequestOIDCCallbackHandler().handle(connection)

    assert result.code == 401
    assert connection.response["code"] == 401
    assert connection.response["data"] == {}
    assert context.token_requests == []
    context.jwks_fetch.assert_not_called()
    with context.sessions() as session:
        assert (
            session.scalar(select(User).where(User.username == "alice")).last_login
            == 10.0
        )


@pytest.mark.component
def test_oidc_callback_consumes_state_before_rejecting_redirect_mismatch(
    oidc_callback_context,
):
    context = oidc_callback_context
    connection = _Connection(
        {**context.request_data, "redirect_uri": "https://other.example/callback"}
    )

    result = extension.RequestOIDCCallbackHandler().handle(connection)

    assert result.code == 401
    assert connection.response["code"] == 401
    assert connection.response["data"] == {}
    assert context.caching.get(context.state_key) is None
    assert context.token_requests == []
    with context.sessions() as session:
        assert (
            session.scalar(select(User).where(User.username == "alice")).last_login
            == 10.0
        )


@pytest.mark.component
def test_oidc_callback_rejects_state_reuse_after_success(oidc_callback_context):
    context = oidc_callback_context
    first = _Connection(context.request_data)
    assert extension.RequestOIDCCallbackHandler().handle(first).code == 200
    last_login = context.clock.now
    context.clock.now += 1
    replay = _Connection(context.request_data)

    result = extension.RequestOIDCCallbackHandler().handle(replay)

    assert result.code == 401
    assert replay.response["code"] == 401
    assert replay.response["data"] == {}
    assert len(context.token_requests) == 1
    with context.sessions() as session:
        assert (
            session.scalar(select(User).where(User.username == "alice")).last_login
            == last_login
        )


@pytest.mark.component
@pytest.mark.parametrize("claim", ["exp", "iat", "iss", "sub", "aud"])
def test_oidc_callback_rejects_id_token_missing_required_claim(
    oidc_callback_context, claim
):
    context = oidc_callback_context
    del context.claims[claim]
    connection = _Connection(context.request_data)

    result = extension.RequestOIDCCallbackHandler().handle(connection)

    assert result.code == 401
    assert connection.response["code"] == 401
    assert connection.response["data"] == {}
    assert context.caching.get(context.state_key) is None
    with context.sessions() as session:
        assert (
            session.scalar(select(User).where(User.username == "alice")).last_login
            == 10.0
        )


@pytest.mark.component
@pytest.mark.parametrize(
    "invalid_token",
    [
        "missing-id-token",
        "wrong-signature",
        "expired",
        "future-issued-at",
        "wrong-issuer",
        "wrong-audience",
        "wrong-nonce",
        "missing-nonce",
        "unsigned",
    ],
)
def test_oidc_callback_rejects_invalid_id_token_without_issuing_local_token(
    oidc_callback_context, invalid_token
):
    context = oidc_callback_context
    if invalid_token == "missing-id-token":
        context.include_id_token = False
    elif invalid_token == "wrong-signature":
        context.signing_key = context.wrong_signing_key
    elif invalid_token == "expired":
        context.claims["exp"] = int(context.clock.now) - 60
    elif invalid_token == "future-issued-at":
        context.claims["iat"] = int(context.clock.now) + 300
    elif invalid_token == "wrong-issuer":
        context.claims["iss"] = "https://other.example"
    elif invalid_token == "wrong-audience":
        context.claims["aud"] = "other-client"
    elif invalid_token == "wrong-nonce":
        context.claims["nonce"] = "wrong-nonce"
    elif invalid_token == "missing-nonce":
        del context.claims["nonce"]
    else:
        context.signing_key = None
        context.algorithm = "none"
    connection = _Connection(context.request_data)

    result = extension.RequestOIDCCallbackHandler().handle(connection)

    assert result.code == 401
    assert connection.response["code"] == 401
    assert connection.response["data"] == {}
    assert context.caching.get(context.state_key) is None
    with context.sessions() as session:
        assert (
            session.scalar(select(User).where(User.username == "alice")).last_login
            == 10.0
        )


@pytest.mark.component
@pytest.mark.parametrize(
    ("authorized_party", "expected_code"),
    [(None, 401), ("other-client", 401), ("new-client", 200)],
)
def test_oidc_callback_requires_matching_authorized_party_for_multiple_audiences(
    oidc_callback_context, authorized_party, expected_code
):
    context = oidc_callback_context
    context.claims["aud"] = ["new-client", "another-client"]
    if authorized_party is not None:
        context.claims["azp"] = authorized_party
    connection = _Connection(context.request_data)

    result = extension.RequestOIDCCallbackHandler().handle(connection)

    assert result.code == expected_code
    assert connection.response["code"] == expected_code
    with context.sessions() as session:
        user = session.scalar(select(User).where(User.username == "alice"))
        if expected_code == 200:
            assert user.last_login == context.clock.now
            assert user.is_token_valid(connection.response["data"]["token"])
        else:
            assert connection.response["data"] == {}
            assert user.last_login == 10.0


@pytest.mark.component
def test_oidc_callback_rejects_unknown_user_when_provisioning_is_disabled(
    oidc_callback_context,
):
    context = oidc_callback_context
    context.claims["preferred_username"] = "unknown-user"
    context.claims["sub"] = "unknown-subject"
    connection = _Connection(context.request_data)

    result = extension.RequestOIDCCallbackHandler().handle(connection)

    assert result.code == 401
    assert connection.response["code"] == 401
    assert connection.response["data"] == {}
    with context.sessions() as session:
        assert (
            session.scalar(select(User).where(User.username == "unknown-user")) is None
        )
        assert (
            session.scalar(select(User).where(User.username == "alice")).last_login
            == 10.0
        )


@pytest.mark.component
@pytest.mark.parametrize("username", [None, "", 42])
def test_oidc_callback_rejects_invalid_username_claim(oidc_callback_context, username):
    context = oidc_callback_context
    context.config["extensions"]["oidc_sso"]["auto_provision"] = True
    context.claims["sub"] = "unbound-subject"
    if username is None:
        del context.claims["preferred_username"]
    else:
        context.claims["preferred_username"] = username
    connection = _Connection(context.request_data)

    result = extension.RequestOIDCCallbackHandler().handle(connection)

    assert result.code == 401
    assert connection.response["code"] == 401
    assert connection.response["data"] == {}
    with context.sessions() as session:
        assert (
            session.scalar(select(User).where(User.username == "alice")).last_login
            == 10.0
        )


@pytest.mark.component
def test_oidc_callback_provisions_user_with_configured_group_and_commits_login(
    oidc_callback_context,
):
    context = oidc_callback_context
    context.config["extensions"]["oidc_sso"]["auto_provision"] = True
    context.claims.update(
        preferred_username="new-user", sub="new-subject", name="New User"
    )
    with context.sessions.begin() as session:
        session.add(UserGroup(group_name="user"))
    connection = _Connection(context.request_data)

    result = extension.RequestOIDCCallbackHandler().handle(connection)

    assert (result.code, result.target) == (200, "new-user")
    data = connection.response["data"]
    assert data["groups"] == ["user"]
    assert data["nickname"] == "New User"
    with context.sessions() as session:
        user = session.scalar(select(User).where(User.username == "new-user"))
        assert result.user_id == user.id
        assert user.status == UserStatus.ACTIVE
        assert user.last_login == context.clock.now
        assert user.all_groups == {"user"}
        assert user.is_token_valid(data["token"])
        assert session.get(UserPasswordCredential, user.id) is None
        binding = session.scalar(
            select(UserOidcCredential).where(UserOidcCredential.user_id == user.id)
        )
        assert binding.subject == "new-subject"


@pytest.mark.component
def test_oidc_callback_does_not_provision_user_when_default_group_is_missing(
    oidc_callback_context,
):
    context = oidc_callback_context
    context.config["extensions"]["oidc_sso"]["auto_provision"] = True
    context.claims["preferred_username"] = "new-user"
    context.claims["sub"] = "new-subject"
    connection = _Connection(context.request_data)

    result = extension.RequestOIDCCallbackHandler().handle(connection)

    assert result.code == 401
    assert connection.response["code"] == 401
    assert connection.response["data"] == {}
    with context.sessions() as session:
        assert session.scalar(select(User).where(User.username == "new-user")) is None
        assert (
            session.scalar(select(User).where(User.username == "alice")).last_login
            == 10.0
        )


@pytest.mark.component
def test_oidc_callback_rejects_inactive_user_without_updating_login(
    oidc_callback_context,
):
    context = oidc_callback_context
    with context.sessions.begin() as session:
        session.scalar(
            select(User).where(User.username == "alice")
        ).status = UserStatus.DISABLED
    connection = _Connection(context.request_data)

    result = extension.RequestOIDCCallbackHandler().handle(connection)

    assert result.code == 4003
    assert connection.response["code"] == 4003
    assert connection.response["data"] == {"reason": None}
    with context.sessions() as session:
        assert (
            session.scalar(select(User).where(User.username == "alice")).last_login
            == 10.0
        )


@pytest.mark.component
@pytest.mark.parametrize("auto_provision", [False, True])
def test_oidc_unknown_subject_cannot_claim_existing_username(
    oidc_callback_context, auto_provision
):
    context = oidc_callback_context
    context.config["extensions"]["oidc_sso"]["auto_provision"] = auto_provision
    context.claims["sub"] = "unbound-subject"
    connection = _Connection(context.request_data)
    assert extension.RequestOIDCCallbackHandler().handle(connection).code == 401
    assert "token" not in connection.response["data"]
    with context.sessions() as session:
        assert len(session.scalars(select(UserOidcCredential)).all()) == 1
        assert (
            session.scalar(select(User).where(User.username == "alice")).last_login
            == 10.0
        )


@pytest.mark.component
def test_bound_oidc_identity_survives_username_claim_change(oidc_callback_context):
    context = oidc_callback_context
    context.claims.pop("preferred_username")
    with context.sessions.begin() as session:
        session.scalar(
            select(User).where(User.username == "alice")
        ).username = "renamed"
    connection = _Connection(context.request_data)
    result = extension.RequestOIDCCallbackHandler().handle(connection)
    assert (result.code, result.target) == (200, "renamed")


@pytest.mark.component
def test_oidc_binding_does_not_bypass_login_policy(oidc_callback_context):
    context = oidc_callback_context
    with context.sessions.begin() as session:
        user = session.scalar(select(User).where(User.username == "alice"))
        replace_auth_policy(session, user, AuthPurpose.LOGIN, [], expected_revision=1)
    connection = _Connection(context.request_data)
    assert extension.RequestOIDCCallbackHandler().handle(connection).code == 401
    assert "token" not in connection.response["data"]


@pytest.mark.component
def test_oidc_returns_auth_context_when_local_totp_is_required(
    oidc_callback_context, monkeypatch
):
    import pyotp

    from include.domains.identity.commands.credentials import (
        enable_login_totp,
        setup_totp,
    )
    from include.domains.identity.handlers import auth as auth_handlers
    from include.domains.identity.tokens import Token, TokenPurpose

    context = oidc_callback_context
    with context.sessions.begin() as session:
        user = session.scalar(select(User).where(User.username == "alice"))
        credential, _ = setup_totp(session, user)
        enable_login_totp(session, user, credential)
        signing_key = user.secret_key
        secret = credential.secret
    connection = _Connection(context.request_data)
    assert extension.RequestOIDCCallbackHandler().handle(connection).code == 202
    token = Token.from_raw(connection.response["data"]["token"], signing_key)
    assert token.purpose == TokenPurpose.AUTH
    assert token.auth_context.evidence[0].method == "oidc"
    assert connection.response["data"]["methods"] == ["totp"]
    with context.sessions() as session:
        assert (
            session.scalar(select(User).where(User.username == "alice")).last_login
            == 10.0
        )
    monkeypatch.setattr(totp, "DatabaseSession", context.sessions)
    monkeypatch.setattr(auth_handlers, "Session", context.sessions)
    monkeypatch.setattr(auth_handlers, "get_client_ip", lambda ws: "127.0.0.1")
    monkeypatch.setattr(
        auth_handlers.LoginGuard, "evaluate", lambda *a: SimpleNamespace(allowed=True)
    )
    monkeypatch.setattr(
        auth_handlers.LoginGuard, "report_success", lambda *a, **k: None
    )
    responses = []
    complete = SimpleNamespace(
        user_id=token.sub,
        token=token,
        data={
            "method": "totp",
            "data": {"token": pyotp.TOTP(secret).now()},
            "target_purpose": 2,
        },
        stream=SimpleNamespace(connection=SimpleNamespace(_ws=None)),
        conclude_request=lambda **response: responses.append(response),
    )
    assert auth_handlers.RequestCompleteMFAHandler().handle(complete).code == 200
    assert (
        Token.from_raw(responses[0]["data"]["token"], signing_key).purpose
        == TokenPurpose.GENERAL
    )


@pytest.mark.component
def test_oidc_provider_never_accepts_client_reported_identity(oidc_callback_context):
    with oidc_callback_context.sessions() as session:
        user = session.scalar(select(User).where(User.username == "alice"))
        result = extension.OIDCAuthProvider().verify(
            session,
            user,
            {
                "issuer": "https://new.example",
                "subject": "provider-subject-alice",
            },
            {},
        )
        assert not result.success
