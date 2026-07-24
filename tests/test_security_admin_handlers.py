import time
from pathlib import Path
from shutil import copyfile
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[1]


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
    from include.providers.manager import ProviderManager

    engine = create_engine(f"sqlite:///{tmp_path / 'security-admin.db'}")
    Base.metadata.create_all(engine)
    test_session = sessionmaker(bind=engine)
    monkeypatch.setattr(access_control, "Session", test_session)
    monkeypatch.setattr(login, "Session", test_session)
    monkeypatch.setattr(access_control, "get_client_ip", lambda _ws: "203.0.113.10")
    monkeypatch.setattr(access_control, "_publish_guard_event", lambda _payload: None)
    ProviderManager().register(MemoryCachingProvider())
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
    _, created = _call(
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

    _, updated = _call(
        handlers.RequestUpdateBannedSubnetHandler,
        {"subnet": "192.0.2.7/24", "reason": None, "expires_at": None},
    )
    assert updated["code"] == 200
    assert updated["data"]["reason"] is None
    assert updated["data"]["expires_at"] is None

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


def test_security_admin_permissions_are_independent(security_admin_context):
    handlers = security_admin_context.handlers
    _, list_denied = _call(
        handlers.RequestListBannedSubnetsHandler, {}, username="viewer"
    )
    _, create_denied = _call(
        handlers.RequestCreateBannedSubnetHandler,
        {"subnet": "192.0.2.0/24"},
        username="viewer",
    )
    _, lockout_denied = _call(
        handlers.RequestListAuthLockoutsHandler, {}, username="viewer"
    )
    _, unlock_denied = _call(
        handlers.RequestUnlockAuthLockoutsHandler,
        {"locks": [{"scope": "ip", "ip_address": "192.0.2.1"}], "reason": "test"},
        username="viewer",
    )
    assert {
        response["code"]
        for response in (
            list_denied,
            create_denied,
            lockout_denied,
            unlock_denied,
        )
    } == {403}


def test_list_and_unlock_all_lockout_scopes(security_admin_context):
    context = security_admin_context
    handlers = context.handlers
    now = handlers.time.time()
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
                    username="alice",
                    ip_address="192.0.2.1",
                    failed_attempts=5,
                    window_started_at=now - 60,
                    last_attempt=now,
                    locked_until=now + 400,
                ),
            ]
        )

    _, first_page = _call(handlers.RequestListAuthLockoutsHandler, {"page_size": 2})
    assert len(first_page["data"]["items"]) == 2
    assert first_page["data"]["has_more"] is True
    _, second_page = _call(
        handlers.RequestListAuthLockoutsHandler,
        {"page_size": 2, "cursor": first_page["data"]["next_cursor"]},
    )
    scopes = {
        item["scope"]
        for item in first_page["data"]["items"] + second_page["data"]["items"]
    }
    assert scopes == {"ip", "account", "account_ip"}

    selectors = [
        {"scope": "ip", "ip_address": "192.0.2.1"},
        {"scope": "account", "username": "alice", "factor": "password"},
        {"scope": "account_ip", "username": "alice", "ip_address": "192.0.2.1"},
    ]
    cache_keys = [
        context.TrafficThrottle.make_cache_key("192.0.2.1"),
        context.AccountThrottle.make_cache_key("alice", "password"),
        context.LoginThrottle.make_cache_key("alice", "192.0.2.1"),
    ]
    cache = handlers.ProviderManager().caching
    for key in cache_keys:
        cache.set(context.login.LoginGuard._cache_key(key), now + 600, ttl=600)

    result, unlocked = _call(
        handlers.RequestUnlockAuthLockoutsHandler,
        {"locks": selectors, "reason": "Emergency access"},
    )
    assert unlocked["code"] == 200
    assert unlocked["data"] == {"cleared": selectors, "not_found": []}
    assert result.data["reason"] == "Emergency access"
    for key in cache_keys:
        assert cache.get(context.login.LoginGuard._cache_key(key)) is None

    _, repeated = _call(
        handlers.RequestUnlockAuthLockoutsHandler,
        {"locks": selectors, "reason": "Retry"},
    )
    assert repeated["data"] == {"cleared": [], "not_found": selectors}


@pytest.mark.asyncio
async def test_security_admin_websocket_actions(authenticated_client):
    from tests.utils import assert_success

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
    from tests.utils import assert_error, assert_success

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
