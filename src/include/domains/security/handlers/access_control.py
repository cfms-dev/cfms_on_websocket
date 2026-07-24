import ipaddress
import math
import time
from typing import Any

import orjson
from loguru import logger
from sqlalchemy import Double, and_, asc, desc, literal, null, or_, select, union_all
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import selectinload

from include.config.constants import LOGIN_GUARD_EVENT_CHANNEL
from include.database.models.identity import User
from include.database.models.security import (
    AccountThrottle,
    BannedSubnet,
    LoginThrottle,
    TrafficThrottle,
)
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.operations.comments import CommentStore
from include.domains.pagination import (
    CURSOR_PAGINATION_SCHEMA,
    CursorError,
    PaginationCursor,
    get_page_size,
    make_cursor_response,
)
from include.domains.security.guards.login import AuthFactor, LoginGuard, ThrottleScope
from include.messages import Messages as smsg
from include.providers.manager import ProviderManager
from include.transport.client_address import get_client_ip
from include.transport.connection import ConnectionHandler
from include.transport.request_handler import RequestHandler, Result

_SUBNET_STATUSES = ("scheduled", "active", "expired")
_LOCKOUT_SCOPES = (
    ThrottleScope.IP.value,
    ThrottleScope.ACCOUNT.value,
    ThrottleScope.ACCOUNT_IP.value,
)

_SUBNET_SCHEMA = {
    "type": "string",
    "minLength": 1,
    "maxLength": 128,
}
_REASON_SCHEMA = {
    "anyOf": [
        {"type": "string", "maxLength": 255},
        {"type": "null"},
    ]
}
_EXPIRY_SCHEMA = {
    "anyOf": [
        {"type": "number", "minimum": 0},
        {"type": "null"},
    ]
}


def _require_permission(
    handler: ConnectionHandler, permission: Permissions
) -> Result | None:
    with Session() as session:
        user = User.get_existing(session, handler.username)
        if permission not in user.all_permissions:
            handler.conclude_request(403, {}, smsg.ACCESS_DENIED)
            return Result(code=403, target=None, username=handler.username)
    return None


def _validate_interval(starts_at: float, expires_at: float | None) -> bool:
    return (
        math.isfinite(starts_at)
        and (expires_at is None or math.isfinite(expires_at))
        and (expires_at is None or expires_at > starts_at)
    )


def _subnet_status(starts_at: float, expires_at: float | None, now: float) -> str:
    if starts_at > now:
        return "scheduled"
    if expires_at is not None and expires_at <= now:
        return "expired"
    return "active"


def _serialize_subnet(row: BannedSubnet, now: float) -> dict[str, Any]:
    return {
        "subnet": row.subnet,
        "reason": row.reason,
        "created_at": row.created_at,
        "starts_at": row.starts_at,
        "expires_at": row.expires_at,
        "status": _subnet_status(row.starts_at, row.expires_at, now),
    }


def _contains_requester(
    handler: ConnectionHandler,
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    expires_at: float | None,
) -> bool:
    if expires_at is not None and expires_at <= time.time():
        return False
    try:
        requester = ipaddress.ip_address(get_client_ip(handler.stream.connection._ws))
    except ValueError:
        return False
    return requester in network


def _publish_guard_event(payload: dict[str, Any]) -> None:
    try:
        ProviderManager().event_bus.publish(
            LOGIN_GUARD_EVENT_CHANNEL, orjson.dumps(payload).decode()
        )
    except Exception:  # noqa: BLE001 - local state is already consistent.
        logger.exception("Failed to publish login guard invalidation event")


def _refresh_subnet_rules() -> None:
    LoginGuard.reload_networks()
    _publish_guard_event({"type": "reload_subnets"})


class RequestListBannedSubnetsHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            **CURSOR_PAGINATION_SCHEMA,
            "status": {"type": "string", "enum": list(_SUBNET_STATUSES)},
        },
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        denial = _require_permission(handler, Permissions.LIST_BANNED_SUBNETS)
        if denial:
            return denial

        page_size = get_page_size(handler.data)
        status = handler.data.get("status")
        cursor = handler.data.get("cursor")
        filters = {"status": status}
        sort = "created_at:desc,subnet:asc"
        try:
            decoded_cursor = PaginationCursor.decode(
                cursor,
                action="list_banned_subnets",
                sort=sort,
                filters=filters,
                ttl=3600,
                value_types=[(int, float), str],
            )
        except CursorError as exc:
            handler.conclude_request(400, {}, str(exc))
            return Result(code=400, target=None, username=handler.username)

        now = time.time()
        statement = select(BannedSubnet).options(
            selectinload(BannedSubnet.reason_comment)
        )
        if status == "scheduled":
            statement = statement.where(BannedSubnet.starts_at > now)
        elif status == "active":
            statement = statement.where(
                BannedSubnet.starts_at <= now,
                or_(BannedSubnet.expires_at.is_(None), BannedSubnet.expires_at > now),
            )
        elif status == "expired":
            statement = statement.where(
                BannedSubnet.expires_at.is_not(None), BannedSubnet.expires_at <= now
            )

        if decoded_cursor is not None:
            last_created_at, last_subnet = decoded_cursor.last
            statement = statement.where(
                or_(
                    BannedSubnet.created_at < last_created_at,
                    and_(
                        BannedSubnet.created_at == last_created_at,
                        BannedSubnet.subnet > last_subnet,
                    ),
                )
            )

        with Session() as session:
            rows = session.execute(
                statement.order_by(
                    desc(BannedSubnet.created_at), asc(BannedSubnet.subnet)
                ).limit(page_size + 1)
            ).scalars()
            items = [_serialize_subnet(row, now) for row in rows]

        response = make_cursor_response(
            items,
            page_size=page_size,
            action="list_banned_subnets",
            sort=sort,
            filters=filters,
            cursor_key=lambda item: [item["created_at"], item["subnet"]],
        )
        handler.conclude_request(200, response, smsg.SUCCESS)
        return Result(
            code=200,
            target=None,
            data={"page_size": page_size, "status": status},
            username=handler.username,
        )


class RequestCreateBannedSubnetHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "subnet": _SUBNET_SCHEMA,
            "reason": _REASON_SCHEMA,
            "starts_at": {"type": "number", "minimum": 0},
            "expires_at": _EXPIRY_SCHEMA,
            "confirm_self_block": {"type": "boolean"},
        },
        "required": ["subnet"],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        denial = _require_permission(handler, Permissions.MANAGE_BANNED_SUBNETS)
        if denial:
            return denial

        try:
            network = ipaddress.ip_network(handler.data["subnet"], strict=False)
        except ValueError:
            handler.conclude_request(400, {}, "Invalid CIDR subnet")
            return Result(
                code=400, target=handler.data["subnet"], username=handler.username
            )

        now = time.time()
        starts_at = float(handler.data.get("starts_at", now))
        expires_at = handler.data.get("expires_at")
        if expires_at is not None:
            expires_at = float(expires_at)
        if not _validate_interval(starts_at, expires_at):
            handler.conclude_request(
                400, {}, "`expires_at` must be later than `starts_at`"
            )
            return Result(code=400, target=str(network), username=handler.username)
        if _contains_requester(handler, network, expires_at) and not handler.data.get(
            "confirm_self_block", False
        ):
            handler.conclude_request(
                409,
                {},
                "The subnet contains your current IP; set `confirm_self_block` to proceed",
            )
            return Result(code=409, target=str(network), username=handler.username)

        try:
            with Session.begin() as session:
                reason = handler.data.get("reason")
                row = BannedSubnet(
                    subnet=str(network),
                    reason_comment_id=(
                        CommentStore.get_or_create_id(session, reason)
                        if reason is not None
                        else None
                    ),
                    created_at=now,
                    starts_at=starts_at,
                    expires_at=expires_at,
                )
                session.add(row)
                session.flush()
                response = _serialize_subnet(row, time.time())
        except IntegrityError:
            handler.conclude_request(409, {}, "Subnet rule already exists")
            return Result(code=409, target=str(network), username=handler.username)

        _refresh_subnet_rules()
        handler.conclude_request(200, response, "Banned subnet created")
        return Result(
            code=200,
            target=str(network),
            data={"starts_at": starts_at, "expires_at": expires_at},
            username=handler.username,
        )


class RequestUpdateBannedSubnetHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "subnet": _SUBNET_SCHEMA,
            "reason": _REASON_SCHEMA,
            "starts_at": {"type": "number", "minimum": 0},
            "expires_at": _EXPIRY_SCHEMA,
            "confirm_self_block": {"type": "boolean"},
        },
        "required": ["subnet"],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        denial = _require_permission(handler, Permissions.MANAGE_BANNED_SUBNETS)
        if denial:
            return denial
        if not {"reason", "starts_at", "expires_at"} & handler.data.keys():
            handler.conclude_request(400, {}, "No subnet rule changes specified")
            return Result(
                code=400, target=handler.data["subnet"], username=handler.username
            )

        try:
            network = ipaddress.ip_network(handler.data["subnet"], strict=False)
        except ValueError:
            handler.conclude_request(400, {}, "Invalid CIDR subnet")
            return Result(
                code=400, target=handler.data["subnet"], username=handler.username
            )

        with Session.begin() as session:
            row = session.get(BannedSubnet, str(network))
            if row is None:
                handler.conclude_request(404, {}, "Subnet rule not found")
                return Result(code=404, target=str(network), username=handler.username)

            starts_at = float(handler.data.get("starts_at", row.starts_at))
            expires_at = handler.data.get("expires_at", row.expires_at)
            if expires_at is not None:
                expires_at = float(expires_at)
            if not _validate_interval(starts_at, expires_at):
                handler.conclude_request(
                    400, {}, "`expires_at` must be later than `starts_at`"
                )
                return Result(code=400, target=str(network), username=handler.username)
            if _contains_requester(
                handler, network, expires_at
            ) and not handler.data.get("confirm_self_block", False):
                handler.conclude_request(
                    409,
                    {},
                    "The subnet contains your current IP; set `confirm_self_block` to proceed",
                )
                return Result(code=409, target=str(network), username=handler.username)

            if "reason" in handler.data:
                reason = handler.data["reason"]
                row.reason_comment_id = (
                    CommentStore.get_or_create_id(session, reason)
                    if reason is not None
                    else None
                )
            row.starts_at = starts_at
            row.expires_at = expires_at
            session.flush()
            response = _serialize_subnet(row, time.time())

        _refresh_subnet_rules()
        handler.conclude_request(200, response, "Banned subnet updated")
        return Result(
            code=200,
            target=str(network),
            data={"starts_at": starts_at, "expires_at": expires_at},
            username=handler.username,
        )


class RequestDeleteBannedSubnetHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {"subnet": _SUBNET_SCHEMA},
        "required": ["subnet"],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        denial = _require_permission(handler, Permissions.MANAGE_BANNED_SUBNETS)
        if denial:
            return denial
        try:
            subnet = str(ipaddress.ip_network(handler.data["subnet"], strict=False))
        except ValueError:
            handler.conclude_request(400, {}, "Invalid CIDR subnet")
            return Result(
                code=400, target=handler.data["subnet"], username=handler.username
            )

        with Session.begin() as session:
            row = session.get(BannedSubnet, subnet)
            if row is None:
                handler.conclude_request(404, {}, "Subnet rule not found")
                return Result(code=404, target=subnet, username=handler.username)
            session.delete(row)

        _refresh_subnet_rules()
        handler.conclude_request(200, {}, "Banned subnet deleted")
        return Result(code=200, target=subnet, username=handler.username)


def _lockout_union():
    return union_all(
        select(
            literal(ThrottleScope.IP.value).label("scope"),
            literal("").label("username"),
            literal("").label("factor"),
            TrafficThrottle.ip_address.label("ip_address"),
            TrafficThrottle.failed_attempts.label("failed_attempts"),
            TrafficThrottle.window_started_at.label("window_started_at"),
            TrafficThrottle.last_attempt.label("last_attempt"),
            TrafficThrottle.locked_until.label("locked_until"),
        ),
        select(
            literal(ThrottleScope.ACCOUNT.value).label("scope"),
            AccountThrottle.username.label("username"),
            AccountThrottle.factor.label("factor"),
            literal("").label("ip_address"),
            AccountThrottle.failed_attempts.label("failed_attempts"),
            null().cast(Double).label("window_started_at"),
            AccountThrottle.last_attempt.label("last_attempt"),
            AccountThrottle.locked_until.label("locked_until"),
        ),
        select(
            literal(ThrottleScope.ACCOUNT_IP.value).label("scope"),
            LoginThrottle.username.label("username"),
            literal("").label("factor"),
            LoginThrottle.ip_address.label("ip_address"),
            LoginThrottle.failed_attempts.label("failed_attempts"),
            LoginThrottle.window_started_at.label("window_started_at"),
            LoginThrottle.last_attempt.label("last_attempt"),
            LoginThrottle.locked_until.label("locked_until"),
        ),
    ).subquery("auth_lockouts")


def _after_lockout_cursor(columns, last: list[Any]):
    locked_until, scope, username, factor, ip_address = last
    tie_columns = [columns.scope, columns.username, columns.factor, columns.ip_address]
    tie_values = [scope, username, factor, ip_address]
    tie_conditions = []
    for index, (column, value) in enumerate(zip(tie_columns, tie_values)):
        tie_conditions.append(
            and_(
                *(tie_columns[prefix] == tie_values[prefix] for prefix in range(index)),
                column > value,
            )
        )
    return or_(
        columns.locked_until < locked_until,
        and_(columns.locked_until == locked_until, or_(*tie_conditions)),
    )


class RequestListAuthLockoutsHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            **CURSOR_PAGINATION_SCHEMA,
            "scope": {"type": "string", "enum": list(_LOCKOUT_SCOPES)},
            "username": {"type": "string", "minLength": 1, "maxLength": 255},
            "ip_address": {"type": "string", "minLength": 1, "maxLength": 45},
            "factor": {
                "type": "string",
                "enum": [factor.value for factor in AuthFactor],
            },
        },
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        denial = _require_permission(handler, Permissions.LIST_AUTH_LOCKOUTS)
        if denial:
            return denial

        page_size = get_page_size(handler.data)
        filters = {
            key: handler.data.get(key)
            for key in ("scope", "username", "ip_address", "factor")
        }
        sort = "locked_until:desc,scope:asc,username:asc,factor:asc,ip_address:asc"
        try:
            decoded_cursor = PaginationCursor.decode(
                handler.data.get("cursor"),
                action="list_auth_lockouts",
                sort=sort,
                filters=filters,
                ttl=3600,
                value_types=[(int, float), str, str, str, str],
            )
        except CursorError as exc:
            handler.conclude_request(400, {}, str(exc))
            return Result(code=400, target=None, username=handler.username)

        lockouts = _lockout_union()
        columns = lockouts.c
        now = time.time()
        statement = select(lockouts).where(columns.locked_until > now)
        for field in ("scope", "username", "ip_address", "factor"):
            value = filters[field]
            if value is not None:
                statement = statement.where(getattr(columns, field) == value)
        if decoded_cursor is not None:
            statement = statement.where(
                _after_lockout_cursor(columns, decoded_cursor.last)
            )
        statement = statement.order_by(
            desc(columns.locked_until),
            asc(columns.scope),
            asc(columns.username),
            asc(columns.factor),
            asc(columns.ip_address),
        ).limit(page_size + 1)

        with Session() as session:
            rows = session.execute(statement).mappings()
            items = []
            for row in rows:
                item = {
                    "scope": row["scope"],
                    "username": row["username"] or None,
                    "factor": row["factor"] or None,
                    "ip_address": row["ip_address"] or None,
                    "failed_attempts": row["failed_attempts"],
                    "window_started_at": row["window_started_at"],
                    "last_attempt": row["last_attempt"],
                    "locked_until": row["locked_until"],
                    "retry_after_seconds": max(1, math.ceil(row["locked_until"] - now)),
                    "_cursor_username": row["username"],
                    "_cursor_factor": row["factor"],
                    "_cursor_ip_address": row["ip_address"],
                }
                items.append(item)

        response = make_cursor_response(
            items,
            page_size=page_size,
            action="list_auth_lockouts",
            sort=sort,
            filters=filters,
            cursor_key=lambda item: [
                item["locked_until"],
                item["scope"],
                item["_cursor_username"],
                item["_cursor_factor"],
                item["_cursor_ip_address"],
            ],
        )
        handler.conclude_request(200, response, smsg.SUCCESS)
        return Result(
            code=200,
            target=None,
            data={"page_size": page_size, **filters},
            username=handler.username,
        )


_LOCKOUT_SELECTOR_SCHEMA = {
    "oneOf": [
        {
            "type": "object",
            "properties": {
                "scope": {"const": ThrottleScope.IP.value},
                "ip_address": {"type": "string", "minLength": 1, "maxLength": 45},
            },
            "required": ["scope", "ip_address"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {
                "scope": {"const": ThrottleScope.ACCOUNT.value},
                "username": {"type": "string", "minLength": 1, "maxLength": 255},
                "factor": {
                    "type": "string",
                    "enum": [factor.value for factor in AuthFactor],
                },
            },
            "required": ["scope", "username", "factor"],
            "additionalProperties": False,
        },
        {
            "type": "object",
            "properties": {
                "scope": {"const": ThrottleScope.ACCOUNT_IP.value},
                "username": {"type": "string", "minLength": 1, "maxLength": 255},
                "ip_address": {"type": "string", "minLength": 1, "maxLength": 45},
            },
            "required": ["scope", "username", "ip_address"],
            "additionalProperties": False,
        },
    ]
}


def _selector_record_and_key(selector: dict[str, str]):
    scope = selector["scope"]
    if scope == ThrottleScope.IP.value:
        identity = selector["ip_address"]
        return TrafficThrottle, identity, TrafficThrottle.make_cache_key(identity)
    if scope == ThrottleScope.ACCOUNT.value:
        identity = (selector["username"], selector["factor"])
        return AccountThrottle, identity, AccountThrottle.make_cache_key(*identity)
    identity = (selector["username"], selector["ip_address"])
    return LoginThrottle, identity, LoginThrottle.make_cache_key(*identity)


class RequestUnlockAuthLockoutsHandler(RequestHandler):
    schema = {
        "type": "object",
        "properties": {
            "locks": {
                "type": "array",
                "minItems": 1,
                "maxItems": 100,
                "uniqueItems": True,
                "items": _LOCKOUT_SELECTOR_SCHEMA,
            },
            "reason": {"type": "string", "minLength": 1, "maxLength": 1024},
        },
        "required": ["locks", "reason"],
        "additionalProperties": False,
    }
    require_auth = True

    def handle(self, handler: ConnectionHandler):
        denial = _require_permission(handler, Permissions.UNLOCK_AUTH_LOCKOUTS)
        if denial:
            return denial

        selectors = handler.data["locks"]
        cleared = []
        not_found = []
        cache_keys: list[tuple[str, ...]] = []
        with LoginGuard._write_lock, Session.begin() as session:
            for selector in selectors:
                model, identity, cache_key = _selector_record_and_key(selector)
                cache_keys.append(cache_key)
                record = session.get(model, identity)
                if record is None:
                    not_found.append(selector)
                else:
                    session.delete(record)
                    cleared.append(selector)

        LoginGuard.invalidate_cache_keys(cache_keys)
        _publish_guard_event(
            {"type": "invalidate_lockouts", "keys": [list(key) for key in cache_keys]}
        )
        response = {"cleared": cleared, "not_found": not_found}
        handler.conclude_request(200, response, "Authentication lockouts cleared")
        return Result(
            code=200,
            target="auth_lockouts",
            data={
                "reason": handler.data["reason"],
                "requested": selectors,
                "cleared_count": len(cleared),
            },
            username=handler.username,
        )
