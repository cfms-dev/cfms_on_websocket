__all__ = [
    "audit_http_request",
    "get_http_client_address",
    "get_optional_http_principal",
    "http_rate_limit",
    "require_http_permissions",
    "require_http_principal",
]

from collections.abc import Callable
from typing import Annotated, Any

import jwt
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from loguru import logger as log
from pydantic import TypeAdapter, ValidationError

from include.config.settings import global_config
from include.config.validation import get_trusted_proxy_networks
from include.database.models.identity import User
from include.database.session import Session
from include.domains.access.permissions import Permissions
from include.domains.identity.types import RequestUsername
from include.domains.operations.commands.audit import log_audit
from include.domains.security.guards.request_rate_control import check_request_rate
from include.transport.client_address import resolve_client_ip

from .contracts import HttpPrincipal

logger = log.bind(name="http_api")
_bearer = HTTPBearer(auto_error=False)
_username_adapter = TypeAdapter(RequestUsername)


def get_http_client_address(request: Request) -> str:
    if request.client is None:
        return ""
    try:
        return resolve_client_ip(
            request.client.host,
            request.headers.get("X-Forwarded-For"),
            request.headers.get("X-Real-IP"),
            get_trusted_proxy_networks(global_config),
        )
    except ValueError:
        logger.warning("HTTP request has an invalid peer address")
        return ""


def _authentication_error() -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid or missing bearer token",
        headers={"WWW-Authenticate": "Bearer"},
    )


def _principal_from_token(token: str) -> HttpPrincipal:
    try:
        payload = jwt.decode(
            token,
            options={
                "verify_signature": False,
                "verify_exp": False,
                "verify_nbf": False,
                "verify_iat": False,
                "verify_aud": False,
                "verify_iss": False,
            },
        )
        if not isinstance(payload, dict):
            raise _authentication_error()
        username = _username_adapter.validate_python(
            payload.get("username"), strict=True
        )
    except HTTPException:
        raise
    except jwt.InvalidTokenError, ValidationError:
        raise _authentication_error() from None

    with Session() as session:
        user = session.get(User, username)
        if user is None or not user.is_token_valid(token):
            raise _authentication_error()
        return HttpPrincipal(
            username=user.username,
            permissions=frozenset(user.all_permissions),
            groups=frozenset(user.all_groups),
        )


def get_optional_http_principal(
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(_bearer),
    ],
) -> HttpPrincipal | None:
    if credentials is None:
        return None
    if credentials.scheme.lower() != "bearer":
        raise _authentication_error()
    return _principal_from_token(credentials.credentials)


def require_http_principal(
    principal: Annotated[HttpPrincipal | None, Depends(get_optional_http_principal)],
) -> HttpPrincipal:
    if principal is None:
        raise _authentication_error()
    return principal


def require_http_permissions(
    *required: Permissions,
) -> Callable[[HttpPrincipal], HttpPrincipal]:
    required_permissions = frozenset(required)

    def dependency(
        principal: Annotated[HttpPrincipal, Depends(require_http_principal)],
    ) -> HttpPrincipal:
        if not required_permissions.issubset(principal.permissions):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Permission denied",
            )
        return principal

    return dependency


def http_rate_limit(
    owner: str,
    operation: str,
    *,
    cost: int = 1,
) -> Callable[..., None]:
    if not owner or not operation:
        raise ValueError("HTTP rate-limit owner and operation must not be empty")
    if isinstance(cost, bool) or not isinstance(cost, int) or cost <= 0:
        raise ValueError("HTTP rate-limit cost must be a positive integer")
    action = f"http:{owner}:{operation}"

    def dependency(
        request: Request,
        principal: Annotated[
            HttpPrincipal | None,
            Depends(get_optional_http_principal),
        ],
    ) -> None:
        decision = check_request_rate(
            action,
            cost,
            get_http_client_address(request),
            username=principal.username if principal else None,
            bypass=(
                principal is not None
                and Permissions.BYPASS_REQUEST_RATE_LIMIT in principal.permissions
            ),
        )
        if not decision.allowed:
            retry_after = max(1, decision.retry_after_seconds)
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Too many requests",
                headers={"Retry-After": str(retry_after)},
            )

    return dependency


def audit_http_request(
    owner: str,
    operation: str,
    result: int,
    request: Request,
    *,
    principal: HttpPrincipal | None = None,
    target: str | None = None,
    data: dict[str, Any] | None = None,
) -> None:
    if not owner or not operation:
        raise ValueError("HTTP audit owner and operation must not be empty")
    log_audit(
        f"http:{owner}:{operation}",
        result,
        username=principal.username if principal else None,
        target=target,
        data=data,
        remote_address=get_http_client_address(request),
    )
