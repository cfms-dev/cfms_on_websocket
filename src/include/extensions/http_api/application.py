__all__ = ["build_http_application", "collect_http_router_registrations"]

from fastapi import APIRouter, FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.routing import APIRoute
from loguru import logger as log

from include.domains.security.guards.login import LoginGuard
from include.extensions.manager import get_loaded_extension_metadata, pm
from include.observability.exception_logging import log_exception_with_id

from .config import HttpApiPolicy
from .contracts import HttpRouterRegistration
from .security import get_http_client_address

logger = log.bind(name="http_api")
_API_PREFIX = "/api/v1"


class _RequestBodyLimitMiddleware:
    def __init__(self, app, max_bytes: int):
        self.app = app
        self.max_bytes = max_bytes

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
                {"detail": "Request body too large"}, status_code=413
            )
            await response(scope, receive, send)
            return

        body = bytearray()
        disconnected = False
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                disconnected = True
                break

            chunk = message.get("body", b"")
            remaining = self.max_bytes - len(body)
            if len(chunk) > remaining:
                body.extend(chunk[: remaining + 1])
                response = JSONResponse(
                    {"detail": "Request body too large"}, status_code=413
                )
                await response(scope, receive, send)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break

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
            response = JSONResponse({"detail": "Forbidden"}, status_code=403)
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


def _validate_routes(
    registrations: tuple[HttpRouterRegistration, ...],
    *,
    docs_enabled: bool,
) -> None:
    route_keys: dict[tuple[str, str], str] = {}
    if docs_enabled:
        for path in (
            f"{_API_PREFIX}/docs",
            f"{_API_PREFIX}/docs/oauth2-redirect",
            f"{_API_PREFIX}/openapi.json",
        ):
            route_keys[("GET", path)] = "http_api"
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
            for method in route.methods or set():
                key = (method.upper(), final_path)
                previous_owner = route_keys.get(key)
                if previous_owner is not None:
                    raise ValueError(
                        f"Duplicate HTTP route {key[0]} {key[1]} registered by "
                        f"{previous_owner!r} and {registration.owner!r}"
                    )
                route_keys[key] = registration.owner


def build_http_application(policy: HttpApiPolicy) -> FastAPI:
    registrations = collect_http_router_registrations()
    _validate_routes(registrations, docs_enabled=policy.docs_enabled)
    app = FastAPI(
        docs_url=f"{_API_PREFIX}/docs" if policy.docs_enabled else None,
        redoc_url=None,
        openapi_url=(f"{_API_PREFIX}/openapi.json" if policy.docs_enabled else None),
        swagger_ui_oauth2_redirect_url=(
            f"{_API_PREFIX}/docs/oauth2-redirect" if policy.docs_enabled else None
        ),
    )

    @app.get("/healthz", include_in_schema=False)
    def healthcheck() -> dict[str, str]:
        return {"status": "ok"}

    for registration in registrations:
        app.include_router(registration.router, prefix=_API_PREFIX)

    app.add_middleware(
        _RequestBodyLimitMiddleware,
        max_bytes=policy.max_request_body_bytes,
    )
    app.add_middleware(_SecurityBoundaryMiddleware)
    if policy.cors_allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=list(policy.cors_allowed_origins),
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["Authorization", "Content-Type"],
        )
    return app
