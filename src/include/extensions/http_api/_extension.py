__all__ = [
    "HttpPrincipal",
    "HttpRouterRegistration",
    "audit_http_request",
    "get_http_client_address",
    "get_optional_http_principal",
    "http_hookimpl",
    "http_rate_limit",
    "require_http_permissions",
    "require_http_principal",
]

from collections.abc import Mapping
from typing import Any

from include.config.settings import global_config
from include.extensions.manager import hookimpl, pm

from ._application import build_http_application
from ._config import HttpApiPolicy
from ._contracts import (
    HttpApiHookSpecs,
    HttpPrincipal,
    HttpRouterRegistration,
    http_hookimpl,
)
from ._runtime import HttpApiRuntime
from ._security import (
    audit_http_request,
    get_http_client_address,
    get_optional_http_principal,
    http_rate_limit,
    require_http_permissions,
    require_http_principal,
)

_runtime = HttpApiRuntime()
if not hasattr(pm.hook, "ext_register_http_routers"):
    pm.add_hookspecs(HttpApiHookSpecs)


@hookimpl
def ext_validate_config(config: Mapping[str, Any]) -> None:
    HttpApiPolicy.from_config(config)


@hookimpl
def ext_on_startup() -> None:
    policy = HttpApiPolicy.from_config(global_config)
    _runtime.start(build_http_application(policy), policy)


@hookimpl
def ext_on_shutdown() -> None:
    policy = HttpApiPolicy.from_config(global_config)
    _runtime.shutdown(policy.shutdown_timeout_seconds)
