__all__ = [
    "HttpApiHookSpecs",
    "HttpPrincipal",
    "HttpRouterRegistration",
    "http_hookimpl",
]

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING

from include.domains.access.permissions import Permissions
from include.extensions.manager import hookimpl, hookspec

if TYPE_CHECKING:
    from fastapi import APIRouter

http_hookimpl = hookimpl


@dataclass(frozen=True, slots=True)
class HttpRouterRegistration:
    owner: str
    router: "APIRouter"


@dataclass(frozen=True, slots=True)
class HttpPrincipal:
    username: str
    permissions: frozenset[Permissions]
    groups: frozenset[str]


class HttpApiHookSpecs(ABC):
    @hookspec
    @abstractmethod
    def ext_register_http_routers(self) -> tuple[HttpRouterRegistration, ...]:
        """Register extension-owned HTTP-only routers."""
