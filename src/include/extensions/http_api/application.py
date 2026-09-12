__all__ = ["build_http_application", "collect_http_router_registrations"]

import asyncio
from collections.abc import Iterable
from string import Formatter

from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from loguru import logger as log
from starlette.convertors import (
    FloatConvertor,
    IntegerConvertor,
    PathConvertor,
    StringConvertor,
    UUIDConvertor,
)
from starlette.datastructures import Headers, MutableHeaders
from starlette.middleware import Middleware
from starlette.routing import BaseRoute, Route

from include.domains.security.guards.login import LoginGuard
from include.extensions.manager import get_loaded_extension_metadata, pm
from include.observability.exception_logging import log_exception_with_id

from .config import HttpApiPolicy
from .contracts import HttpRouterRegistration
from .security import get_http_client_address

logger = log.bind(name="http_api")
_API_PREFIX = "/api/v1"
_KNOWN_CONVERTOR_SUPERSETS = {
    PathConvertor: frozenset(
        {StringConvertor, IntegerConvertor, FloatConvertor, UUIDConvertor}
    ),
    StringConvertor: frozenset({IntegerConvertor, FloatConvertor, UUIDConvertor}),
    FloatConvertor: frozenset({IntegerConvertor}),
}


class _CorsResponseHeadersMiddleware:
    def __init__(self, app, allowed_origins: tuple[str, ...]):
        self.app = app
        self.allowed_origins = frozenset(allowed_origins)

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        origin = Headers(scope=scope).get("origin")
        if origin not in self.allowed_origins:
            await self.app(scope, receive, send)
            return

        async def send_with_cors_headers(message) -> None:
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                if "access-control-allow-origin" not in headers:
                    headers["Access-Control-Allow-Origin"] = origin
                    headers.add_vary_header("Origin")
            await send(message)

        await self.app(scope, receive, send_with_cors_headers)


class _RequestBodyLimitMiddleware:
    def __init__(self, app, max_bytes: int, timeout_seconds: float):
        self.app = app
        self.max_bytes = max_bytes
        self.timeout_seconds = timeout_seconds

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope["headers"])
        content_length = headers.get(b"content-length")
        if content_length is not None and not content_length.isdigit():
            response = JSONResponse(
                {"detail": "Invalid Content-Length"}, status_code=400
            )
            await response(scope, receive, send)
            return
        if content_length is not None and int(content_length) > self.max_bytes:
            response = JSONResponse(
                {"detail": "Request body too large"},
                status_code=413,
                headers={"Connection": "close"},
            )
            await response(scope, receive, send)
            return

        body = bytearray()
        disconnected = False
        too_large = False
        try:
            async with asyncio.timeout(self.timeout_seconds):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        disconnected = True
                        break

                    chunk = message.get("body", b"")
                    remaining = self.max_bytes - len(body)
                    if len(chunk) > remaining:
                        too_large = True
                        break
                    body.extend(chunk)
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            response = JSONResponse(
                {"detail": "Request body timeout"},
                status_code=408,
                headers={"Connection": "close"},
            )
            await response(scope, receive, send)
            return

        if too_large:
            response = JSONResponse(
                {"detail": "Request body too large"},
                status_code=413,
                headers={"Connection": "close"},
            )
            await response(scope, receive, send)
            return

        replayed = False

        async def replay_receive():
            nonlocal replayed
            if not replayed:
                replayed = True
                if disconnected:
                    return {
                        "type": "http.request",
                        "body": bytes(body),
                        "more_body": True,
                    }
                return {
                    "type": "http.request",
                    "body": bytes(body),
                    "more_body": False,
                }
            if disconnected:
                return {"type": "http.disconnect"}
            return await receive()

        await self.app(scope, replay_receive, send)


class _SecurityBoundaryMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope)
        client_address = get_http_client_address(request)
        if (
            not client_address
            or not LoginGuard.evaluate_subnet_access(client_address).allowed
        ):
            response = JSONResponse(
                {"detail": "Forbidden"},
                status_code=403,
                headers={"Connection": "close"},
            )
            await response(scope, receive, send)
            return

        response_started = False

        async def tracked_send(message) -> None:
            nonlocal response_started
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, receive, tracked_send)
        except Exception as exc:
            log_id = log_exception_with_id(
                exc,
                logger,
                context=f"Unhandled HTTP request failure ({scope.get('path', '')})",
            )
            if response_started:
                raise
            response = JSONResponse(
                {"detail": "Internal server error", "log_id": log_id},
                status_code=500,
            )
            await response(scope, receive, send)


def collect_http_router_registrations() -> tuple[HttpRouterRegistration, ...]:
    loaded_metadata = get_loaded_extension_metadata()
    loaded_identifiers = {metadata.identifier for metadata in loaded_metadata}
    order = {
        metadata.identifier: index for index, metadata in enumerate(loaded_metadata)
    }

    registrations = []
    for result in pm.hook.ext_register_http_routers():
        if not isinstance(result, tuple):
            raise TypeError("ext_register_http_routers must return a tuple")
        registrations.extend(result)

    for registration in registrations:
        if not isinstance(registration, HttpRouterRegistration):
            raise TypeError(
                "ext_register_http_routers returned a non-HttpRouterRegistration value"
            )
        if registration.owner not in loaded_identifiers:
            raise ValueError(
                f"HTTP router owner {registration.owner!r} is not a loaded extension"
            )
        if not isinstance(registration.router, APIRouter):
            raise TypeError("HTTP router registration must contain an APIRouter")

    return tuple(sorted(registrations, key=lambda item: order[item.owner]))


def _normalized_route_pattern(
    route: Route,
    *,
    prefix: str = "",
) -> tuple[tuple[str, str | None], ...]:
    return tuple(
        (
            literal,
            route.param_convertors[field_name].regex
            if field_name is not None
            else None,
        )
        for literal, field_name, _format_spec, _conversion in Formatter().parse(
            f"{prefix}{route.path_format}"
        )
    )


def _convertor_route_pattern(
    route: APIRoute,
) -> tuple[tuple[str, type[object] | None], ...]:
    return tuple(
        (
            literal,
            type(route.param_convertors[field_name])
            if field_name is not None
            else None,
        )
        for literal, field_name, _format_spec, _conversion in Formatter().parse(
            f"{_API_PREFIX}{route.path_format}"
        )
    )


def _known_route_pattern_contains(previous: APIRoute, route: APIRoute) -> bool:
    previous_pattern = _convertor_route_pattern(previous)
    route_pattern = _convertor_route_pattern(route)
    if len(previous_pattern) != len(route_pattern):
        return False

    for (previous_literal, previous_convertor), (literal, convertor) in zip(
        previous_pattern, route_pattern, strict=True
    ):
        if previous_literal != literal or (previous_convertor is None) != (
            convertor is None
        ):
            return False
        if previous_convertor == convertor:
            continue
        if convertor not in _KNOWN_CONVERTOR_SUPERSETS.get(
            previous_convertor, frozenset()
        ):
            return False
    return True


def _validate_routes(
    registrations: tuple[HttpRouterRegistration, ...],
    *,
    reserved_routes: Iterable[BaseRoute],
) -> None:
    route_keys: dict[
        tuple[str, tuple[tuple[str, str | None], ...]], tuple[str, str]
    ] = {}
    dynamic_routes: dict[str, list[tuple[APIRoute, str, str]]] = {}
    for route in reserved_routes:
        if not isinstance(route, Route):
            continue
        normalized_pattern = _normalized_route_pattern(route)
        for method in route.methods or set():
            route_keys[(method.upper(), normalized_pattern)] = (
                "http_api",
                route.path,
            )
    for registration in registrations:
        router = registration.router
        if not router.prefix or router.prefix == "/":
            raise ValueError(
                f"HTTP router owned by {registration.owner!r} must declare a "
                "non-empty sub-prefix"
            )
        for route in router.routes:
            if not isinstance(route, APIRoute):
                raise TypeError(
                    f"HTTP router owned by {registration.owner!r} contains an "
                    "unsupported non-HTTP route"
                )
            final_path = f"{_API_PREFIX}{route.path}"
            normalized_pattern = _normalized_route_pattern(route, prefix=_API_PREFIX)
            for method in sorted(route.methods or set()):
                method = method.upper()
                key = (method, normalized_pattern)
                previous_route = route_keys.get(key)
                if previous_route is not None:
                    previous_owner, previous_path = previous_route
                    raise ValueError(
                        f"Duplicate HTTP route {method} {final_path} registered by "
                        f"{registration.owner!r} has the same match pattern as "
                        f"{previous_path} registered by {previous_owner!r}"
                    )
                for previous, previous_owner, previous_path in dynamic_routes.get(
                    method, ()
                ):
                    is_shadowed = (
                        previous.path_regex.fullmatch(route.path)
                        if not route.param_convertors
                        else _known_route_pattern_contains(previous, route)
                    )
                    if is_shadowed:
                        raise ValueError(
                            f"Shadowed HTTP route {method} {final_path} registered "
                            f"by {registration.owner!r} is unreachable because "
                            f"{previous_path} registered by {previous_owner!r} "
                            "matches it first"
                        )
                route_keys[key] = (registration.owner, final_path)
                if route.param_convertors:
                    dynamic_routes.setdefault(method, []).append(
                        (route, registration.owner, final_path)
                    )


def build_http_application(policy: HttpApiPolicy) -> FastAPI:
    registrations = collect_http_router_registrations()
    middleware = []
    if policy.cors_allowed_origins:
        middleware.append(
            Middleware(
                _CorsResponseHeadersMiddleware,
                allowed_origins=policy.cors_allowed_origins,
            )
        )
    middleware.extend(
        (
            Middleware(_SecurityBoundaryMiddleware),
            Middleware(
                _RequestBodyLimitMiddleware,
                max_bytes=policy.max_request_body_bytes,
                timeout_seconds=policy.request_body_timeout_seconds,
            ),
        )
    )
    if policy.cors_allowed_origins:
        middleware.append(
            Middleware(
                CORSMiddleware,
                allow_origins=list(policy.cors_allowed_origins),
                allow_credentials=False,
                allow_methods=["*"],
                allow_headers=["Authorization", "Content-Type"],
            )
        )
    app = FastAPI(
        docs_url=f"{_API_PREFIX}/docs" if policy.docs_enabled else None,
        redoc_url=None,
        openapi_url=(f"{_API_PREFIX}/openapi.json" if policy.docs_enabled else None),
        swagger_ui_oauth2_redirect_url=(
            f"{_API_PREFIX}/docs/oauth2-redirect" if policy.docs_enabled else None
        ),
        middleware=middleware,
    )
    _validate_routes(registrations, reserved_routes=app.routes)

    @app.get("/healthz", include_in_schema=False)
    def healthcheck() -> dict[str, str]:
        return {"status": "ok"}

    for registration in registrations:
        app.include_router(registration.router, prefix=_API_PREFIX)

    return app
