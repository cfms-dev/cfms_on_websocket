import time
from pathlib import Path
from shutil import copyfile
from types import SimpleNamespace

import orjson
import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[3]


class FakeHandler:
    def __init__(self, data, username="admin"):
        self.data = data
        self.username = username
        self.token = "token"
        self.responses = []
        self.stream = SimpleNamespace(
            connection=SimpleNamespace(
                _ws=SimpleNamespace(remote_address=("127.0.0.1", 1))
            )
        )

    def conclude_request(self, code, data=None, message=""):
        self.responses.append({"code": code, "data": data or {}, "message": message})


@pytest.fixture
def security_admin_context(monkeypatch, tmp_path):
    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)

    import include.database.models  # noqa: F401
    from include.config.constants import LOGIN_GUARD_EVENT_CHANNEL
    from include.database.models.comments import Comment
    from include.database.models.identity import User, UserPermission
    from include.database.models.security import (
        AccountThrottle,
        BannedSubnet,
        LoginThrottle,
        TrafficThrottle,
    )
    from include.database.session import Base
    from include.domains.access.permissions import Permissions
    from include.domains.security.guards import login
    from include.domains.security.handlers import access_control
    from include.providers.caching.memory import MemoryCachingProvider
    from include.providers.events.local import LocalEventBusProvider

    engine = create_engine(f"sqlite:///{tmp_path / 'security-admin.db'}")
    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine)
    monkeypatch.setattr(access_control, "Session", test_session)
    monkeypatch.setattr(login, "Session", test_session)
    monkeypatch.setattr(access_control, "get_client_ip", lambda _ws: "203.0.113.10")
    event_bus = LocalEventBusProvider()
    provider = SimpleNamespace(caching=MemoryCachingProvider(), event_bus=event_bus)
    monkeypatch.setattr(access_control, "ProviderManager", lambda: provider)
    monkeypatch.setattr(login, "ProviderManager", lambda: provider)
    monkeypatch.setattr(access_control.time, "time", lambda: 1_700_000_000.0)
    published_events = []
    event_bus.subscribe(LOGIN_GUARD_EVENT_CHANNEL, login.LoginGuard.handle_event)
    event_bus.subscribe(LOGIN_GUARD_EVENT_CHANNEL, published_events.append)
    monkeypatch.setattr(login.LoginGuard, "_banned_rules", [])
    monkeypatch.setattr(login.LoginGuard, "_networks_loaded", True)

    with test_session.begin() as session:
        admin = User(username="admin", pass_hash="hash", created_time=0.0)
        admin.rights.extend(
            UserPermission(
                username="admin",
                permission=permission,
                granted=True,
                start_time=0.0,
            )
            for permission in (
                Permissions.LIST_BANNED_SUBNETS,
                Permissions.MANAGE_BANNED_SUBNETS,
                Permissions.LIST_AUTH_LOCKOUTS,
                Permissions.UNLOCK_AUTH_LOCKOUTS,
            )
        )
        session.add(admin)
        session.add(User(username="viewer", pass_hash="hash", created_time=0.0))

    yield SimpleNamespace(
        handlers=access_control,
        login=login,
        Session=test_session,
        BannedSubnet=BannedSubnet,
        AccountThrottle=AccountThrottle,
        LoginThrottle=LoginThrottle,
        TrafficThrottle=TrafficThrottle,
        Comment=Comment,
        published_events=published_events,
    )
    engine.dispose()


def _call(handler_class, data, username="admin"):
    connection = FakeHandler(data, username=username)
    result = handler_class().handle(connection)
    assert connection.responses
    return result, connection.responses[-1]


def test_banned_subnet_crud_and_filters(security_admin_context):
    handlers = security_admin_context.handlers
    now = handlers.time.time()
    create_result, created = _call(
        handlers.RequestCreateBannedSubnetHandler,
        {
            "subnet": "192.0.2.9/24",
            "reason": "incident",
            "starts_at": now - 10,
            "expires_at": now + 300,
        },
    )
    assert created["code"] == 200
    assert created["data"]["subnet"] == "192.0.2.0/24"
    assert created["data"]["reason"] == "incident"
    assert created["data"]["status"] == "active"
    assert create_result.data["reason_change"] == {
        "previous": None,
        "current": "incident",
    }

    _, duplicate = _call(
        handlers.RequestCreateBannedSubnetHandler,
        {"subnet": "192.0.2.1/24", "starts_at": now - 1},
    )
    assert duplicate["code"] == 409

    _, listed = _call(
        handlers.RequestListBannedSubnetsHandler,
        {"status": "active", "page_size": 1},
    )
    assert [item["subnet"] for item in listed["data"]["items"]] == ["192.0.2.0/24"]

    update_result, updated = _call(
        handlers.RequestUpdateBannedSubnetHandler,
        {"subnet": "192.0.2.7/24", "reason": None, "expires_at": None},
    )
    assert updated["code"] == 200
    assert updated["data"]["reason"] is None
    assert updated["data"]["expires_at"] is None
    assert update_result.data["reason_change"] == {
        "previous": "incident",
        "current": None,
    }

    _, deleted = _call(
        handlers.RequestDeleteBannedSubnetHandler,
        {"subnet": "192.0.2.99/24"},
    )
    assert deleted["code"] == 200
    with security_admin_context.Session() as session:
        assert session.get(security_admin_context.BannedSubnet, "192.0.2.0/24") is None


def test_banned_subnets_reuse_equal_reason_comments(security_admin_context):
    handlers = security_admin_context.handlers
    for subnet in ("192.0.2.0/24", "198.51.100.0/24"):
        _, response = _call(
            handlers.RequestCreateBannedSubnetHandler,
            {"subnet": subnet, "reason": "shared incident"},
        )
        assert response["code"] == 200

    with security_admin_context.Session() as session:
        rows = session.scalars(
            select(security_admin_context.BannedSubnet).order_by(
                security_admin_context.BannedSubnet.subnet
            )
        ).all()
        assert rows[0].reason_comment_id == rows[1].reason_comment_id
        assert rows[0].reason == rows[1].reason == "shared incident"
        comments = session.scalars(select(security_admin_context.Comment)).all()
        assert len(comments) == 1

    _, updated = _call(
        handlers.RequestUpdateBannedSubnetHandler,
        {"subnet": "192.0.2.0/24", "reason": None},
    )
    assert updated["data"]["reason"] is None
    with security_admin_context.Session() as session:
        retained = session.get(security_admin_context.BannedSubnet, "198.51.100.0/24")
        assert retained is not None
        assert retained.reason == "shared incident"


def test_banned_subnet_reason_only_update_skips_guard_refresh(
    security_admin_context,
):
    handlers = security_admin_context.handlers
    _, created = _call(
        handlers.RequestCreateBannedSubnetHandler,
        {"subnet": "192.0.2.0/24", "reason": "initial"},
    )
    assert created["code"] == 200
    security_admin_context.published_events.clear()

    result, updated = _call(
        handlers.RequestUpdateBannedSubnetHandler,
        {"subnet": "192.0.2.0/24", "reason": "corrected"},
    )

    assert updated["data"]["reason"] == "corrected"
    assert result.data["reason_change"] == {
        "previous": "initial",
        "current": "corrected",
    }
    assert security_admin_context.published_events == []


@pytest.mark.parametrize(
    ("operation", "request_data", "expected_allowed"),
    [
        pytest.param("create", {"subnet": "192.0.2.0/24"}, False, id="create"),
        pytest.param(
            "update",
            {"subnet": "192.0.2.0/24", "starts_at": 1_700_000_060.0},
            True,
            id="reschedule",
        ),
        pytest.param("delete", {"subnet": "192.0.2.0/24"}, True, id="delete"),
    ],
)
def test_banned_subnet_mutation_refreshes_guard_through_local_event(
    security_admin_context,
    operation,
    request_data,
    expected_allowed,
):
    context = security_admin_context
    handlers = context.handlers
    if operation != "create":
        _, initial = _call(
            handlers.RequestCreateBannedSubnetHandler, {"subnet": "192.0.2.0/24"}
        )
        assert initial["code"] == 200
        assert (
            context.login.LoginGuard.evaluate_subnet_access("192.0.2.10").allowed
            is False
        )
    context.published_events.clear()
    handler_class = {
        "create": handlers.RequestCreateBannedSubnetHandler,
        "update": handlers.RequestUpdateBannedSubnetHandler,
        "delete": handlers.RequestDeleteBannedSubnetHandler,
    }[operation]

    _, response = _call(handler_class, request_data)

    assert response["code"] == 200
    assert [orjson.loads(message) for message in context.published_events] == [
        {"type": "reload_subnets"}
    ]
    assert (
        context.login.LoginGuard.evaluate_subnet_access("192.0.2.10").allowed
        is expected_allowed
    )


def test_banned_subnet_reload_waits_for_event_consumer(
    security_admin_context,
    monkeypatch,
):
    context = security_admin_context
    handlers = context.handlers
    guard = context.login.LoginGuard
    published = []
    event_bus = SimpleNamespace(
        publish=lambda channel, message: published.append((channel, message))
    )
    monkeypatch.setattr(
        handlers, "ProviderManager", lambda: SimpleNamespace(event_bus=event_bus)
    )
    _, created = _call(
        handlers.RequestCreateBannedSubnetHandler, {"subnet": "192.0.2.0/24"}
    )
    assert created["code"] == 200
    assert guard.evaluate_subnet_access("192.0.2.10").allowed is True
    assert len(published) == 1
    channel, message = published[0]
    assert channel == handlers.LOGIN_GUARD_EVENT_CHANNEL
    assert orjson.loads(message) == {"type": "reload_subnets"}

    guard.handle_event(message)

    assert guard.evaluate_subnet_access("192.0.2.10").allowed is False


def test_banned_subnet_publish_failure_keeps_committed_change(
    security_admin_context,
    monkeypatch,
):
    handlers = security_admin_context.handlers

    def fail_publish(_channel, _message):
        raise RuntimeError("event bus unavailable")

    monkeypatch.setattr(
        handlers,
        "ProviderManager",
        lambda: SimpleNamespace(event_bus=SimpleNamespace(publish=fail_publish)),
    )
    log_messages = []
    sink_id = handlers.logger.add(log_messages.append, format="{message}")
    try:
        _, created = _call(
            handlers.RequestCreateBannedSubnetHandler, {"subnet": "192.0.2.0/24"}
        )
    finally:
        handlers.logger.remove(sink_id)

    assert created["code"] == 200
    assert (
        security_admin_context.login.LoginGuard.evaluate_subnet_access(
            "192.0.2.10"
        ).allowed
        is True
    )
    assert any("runtime state may be stale" in str(message) for message in log_messages)
    with security_admin_context.Session() as session:
        assert (
            session.get(security_admin_context.BannedSubnet, "192.0.2.0/24") is not None
        )


def test_banned_subnet_requires_explicit_self_block_confirmation(
    security_admin_context, monkeypatch
):
    handlers = security_admin_context.handlers
    monkeypatch.setattr(handlers, "get_client_ip", lambda _ws: "198.51.100.10")

    _, rejected = _call(
        handlers.RequestCreateBannedSubnetHandler,
        {"subnet": "198.51.100.0/24"},
    )
    assert rejected["code"] == 409

    _, accepted = _call(
        handlers.RequestCreateBannedSubnetHandler,
        {"subnet": "198.51.100.0/24", "confirm_self_block": True},
    )
    assert accepted["code"] == 200


@pytest.mark.parametrize(
    ("handler_name", "request_data"),
    [
        pytest.param("RequestListBannedSubnetsHandler", {}, id="list-subnets"),
        pytest.param(
            "RequestCreateBannedSubnetHandler",
            {"subnet": "192.0.2.0/24"},
            id="create-subnet",
        ),
        pytest.param("RequestListAuthLockoutsHandler", {}, id="list-lockouts"),
        pytest.param(
            "RequestUnlockAuthLockoutsHandler",
            {"locks": [{"scope": "ip", "ip_address": "192.0.2.1"}], "reason": "test"},
            id="unlock-lockouts",
        ),
    ],
)
def test_security_admin_action_requires_its_permission(
    security_admin_context,
    handler_name,
    request_data,
):
    handler_class = getattr(security_admin_context.handlers, handler_name)

    _, response = _call(handler_class, request_data, username="viewer")

    assert response["code"] == 403


@pytest.mark.parametrize(
    ("handler_name", "request_data"),
    [
        pytest.param(
            "RequestUpdateBannedSubnetHandler",
            {"subnet": "192.0.2.0/24", "reason": "x" * 1024, "expires_at": None},
            id="maximum-reason-and-null-expiry",
        ),
        pytest.param(
            "RequestUnlockAuthLockoutsHandler",
            {
                "locks": [{"scope": "ip", "ip_address": "192.0.2.1"}],
                "reason": "manual unlock",
            },
            id="single-lock-selector",
        ),
    ],
)
def test_security_admin_request_accepts_valid_data(
    security_admin_context,
    handler_name,
    request_data,
):
    model = getattr(security_admin_context.handlers, handler_name).request_model

    request = model.model_validate(request_data)

    assert request.model_dump(exclude_unset=True) == request_data


@pytest.mark.parametrize(
    ("request_data", "error_field"),
    [
        pytest.param(
            {"subnet": "192.0.2.0/24", "reason": ""}, "reason", id="empty-reason"
        ),
        pytest.param(
            {"subnet": "192.0.2.0/24", "reason": "x" * 1025},
            "reason",
            id="oversized-reason",
        ),
        pytest.param(
            {"subnet": "192.0.2.0/24", "starts_at": None},
            "starts_at",
            id="null-start",
        ),
    ],
)
def test_banned_subnet_update_rejects_invalid_field(
    security_admin_context,
    request_data,
    error_field,
):
    model = (
        security_admin_context.handlers.RequestUpdateBannedSubnetHandler.request_model
    )

    with pytest.raises(ValidationError) as excinfo:
        model.model_validate(request_data)

    assert {error["loc"][0] for error in excinfo.value.errors()} == {error_field}


def test_unlock_request_rejects_duplicate_lock_selectors(security_admin_context):
    model = (
        security_admin_context.handlers.RequestUnlockAuthLockoutsHandler.request_model
    )
    selector = {"scope": "ip", "ip_address": "192.0.2.1"}

    with pytest.raises(ValidationError, match="locks must contain unique selectors"):
        model.model_validate({"locks": [selector, selector], "reason": "manual unlock"})


@pytest.fixture
def active_lockouts(security_admin_context):
    context = security_admin_context
    now = context.handlers.time.time()
    with context.Session.begin() as session:
        session.add_all(
            [
                context.TrafficThrottle(
                    ip_address="192.0.2.1",
                    failed_attempts=10,
                    window_started_at=now - 60,
                    last_attempt=now,
                    locked_until=now + 600,
                ),
                context.AccountThrottle(
                    username="alice",
                    factor="password",
                    failed_attempts=5,
                    last_attempt=now,
                    locked_until=now + 500,
                ),
                context.LoginThrottle(
                    username="bob",
                    ip_address="192.0.2.2",
                    failed_attempts=5,
                    window_started_at=now - 60,
                    last_attempt=now,
                    locked_until=now + 400,
                ),
            ]
        )
    return context


def test_list_lockouts_cursor_returns_all_scopes(active_lockouts):
    handlers = active_lockouts.handlers

    _, first_page = _call(handlers.RequestListAuthLockoutsHandler, {"page_size": 2})
    _, second_page = _call(
        handlers.RequestListAuthLockoutsHandler,
        {"page_size": 2, "cursor": first_page["data"]["next_cursor"]},
    )

    assert first_page["code"] == second_page["code"] == 200
    assert len(first_page["data"]["items"]) == 2
    assert len(second_page["data"]["items"]) == 1
    assert first_page["data"]["has_more"] is True
    assert second_page["data"]["has_more"] is False
    assert {
        item["scope"]
        for item in first_page["data"]["items"] + second_page["data"]["items"]
    } == {"ip", "account", "account_ip"}


def test_unlock_all_scopes_clears_persisted_and_cached_denials(active_lockouts):
    context = active_lockouts
    guard = context.login.LoginGuard
    factor = context.login.AuthFactor.PASSWORD
    identities = [
        ("192.0.2.1", None, None),
        ("", "alice", factor),
        ("192.0.2.2", "bob", factor),
    ]
    selectors = [
        {"scope": "ip", "ip_address": "192.0.2.1"},
        {"scope": "account", "username": "alice", "factor": "password"},
        {"scope": "account_ip", "username": "bob", "ip_address": "192.0.2.2"},
    ]
    assert [guard.evaluate(*identity).allowed for identity in identities] == [False] * 3

    result, response = _call(
        context.handlers.RequestUnlockAuthLockoutsHandler,
        {"locks": selectors, "reason": "Emergency access"},
    )

    assert response["code"] == 200
    assert response["data"] == {"cleared": selectors, "not_found": []}
    assert result.data["reason"] == "Emergency access"
    assert [guard.evaluate(*identity).allowed for identity in identities] == [True] * 3
    with context.Session() as session:
        assert session.get(context.TrafficThrottle, "192.0.2.1") is None
        assert session.get(context.AccountThrottle, ("alice", "password")) is None
        assert session.get(context.LoginThrottle, ("bob", "192.0.2.2")) is None


def test_unlock_missing_lockouts_reports_each_selector(security_admin_context):
    selectors = [
        {"scope": "ip", "ip_address": "192.0.2.1"},
        {"scope": "account", "username": "alice", "factor": "password"},
        {"scope": "account_ip", "username": "bob", "ip_address": "192.0.2.2"},
    ]

    _, response = _call(
        security_admin_context.handlers.RequestUnlockAuthLockoutsHandler,
        {"locks": selectors, "reason": "Retry"},
    )

    assert response["code"] == 200
    assert response["data"] == {"cleared": [], "not_found": selectors}


@pytest.mark.asyncio
async def test_security_admin_websocket_actions(authenticated_client):
    from tests.support.utils import assert_success

    now = time.time()
    created = assert_success(
        await authenticated_client.create_banned_subnet(
            "192.0.2.19/24",
            reason="integration test",
            starts_at=now - 1,
            expires_at=now + 300,
        )
    )
    assert created["subnet"] == "192.0.2.0/24"
    assert created["status"] == "active"

    listed = assert_success(
        await authenticated_client.list_banned_subnets(status="active")
    )
    assert any(item["subnet"] == "192.0.2.0/24" for item in listed["items"])

    updated = assert_success(
        await authenticated_client.update_banned_subnet(
            "192.0.2.7/24", reason=None, expires_at=None
        )
    )
    assert updated["reason"] is None
    assert updated["expires_at"] is None
    assert_success(await authenticated_client.delete_banned_subnet("192.0.2.1/24"))


@pytest.mark.asyncio
async def test_unlock_auth_lockouts_over_websocket(
    authenticated_client, unauthenticated_client
):
    from tests.support.utils import assert_error, assert_success

    username = "security-lockout-target"
    for _index in range(5):
        response = await unauthenticated_client.send_request(
            "login",
            {"username": username, "password": "incorrect"},
            include_auth=False,
        )
        assert_error(response, 401)
    assert_error(
        await unauthenticated_client.send_request(
            "login",
            {"username": username, "password": "incorrect"},
            include_auth=False,
        ),
        429,
    )

    lockouts = assert_success(
        await authenticated_client.list_auth_lockouts(username=username)
    )["items"]
    selectors = []
    for item in lockouts:
        if item["scope"] == "account":
            selectors.append(
                {
                    "scope": "account",
                    "username": item["username"],
                    "factor": item["factor"],
                }
            )
        elif item["scope"] == "account_ip":
            selectors.append(
                {
                    "scope": "account_ip",
                    "username": item["username"],
                    "ip_address": item["ip_address"],
                }
            )
    assert {selector["scope"] for selector in selectors} == {"account", "account_ip"}

    unlocked = assert_success(
        await authenticated_client.unlock_auth_lockouts(
            selectors, "Approved integration-test access"
        )
    )
    assert unlocked == {"cleared": selectors, "not_found": []}
    assert_error(
        await unauthenticated_client.send_request(
            "login",
            {"username": username, "password": "incorrect"},
            include_auth=False,
        ),
        401,
    )

    audit_items = assert_success(
        await authenticated_client.view_audit_logs(filters=["unlock_auth_lockouts"])
    )["items"]
    assert audit_items[0]["data"]["reason"] == "Approved integration-test access"
