from typing import Any

from sqlalchemy.orm import Session

from include.domains.identity.auth.base import (
    AuthFactorCategory,
    BaseAuthMethodProvider,
)
lazy from include.database.models.identity import User


class AuthRegistry:
    """Central registry managing all supported authentication method providers."""

    def __init__(self) -> None:
        self._providers: dict[str, BaseAuthMethodProvider] = {}

    def register(self, provider: BaseAuthMethodProvider) -> None:
        if provider.method_id in self._providers:
            raise ValueError(f"Duplicate authentication method {provider.method_id!r}")
        self._providers[provider.method_id] = provider

    def get(self, method_id: str) -> BaseAuthMethodProvider | None:
        return self._providers.get(method_id)

    def list_supported_methods(self) -> list[str]:
        return list(self._providers.keys())

    def get_supported_methods_metadata(self) -> dict[str, dict[str, Any]]:
        return {
            mid: {
                "category": p.category.value,
                "throttle_factor": p.throttle_factor,
                "schema": p.credential_schema.model_json_schema(),
            }
            for mid, p in self._providers.items()
        }

    def get_user_configured_methods(
        self, session: Session, user: User
    ) -> dict[str, list[str]]:
        primary = []
        secondary = []
        for mid, p in self._providers.items():
            if p.is_configured(session, user):
                if p.category == AuthFactorCategory.PRIMARY:
                    primary.append(mid)
                elif p.category == AuthFactorCategory.SECONDARY:
                    secondary.append(mid)
        return {"primary": primary, "secondary": secondary}

    def user_requires_mfa(self, session: Session, user: User) -> bool:
        return any(
            p.category == AuthFactorCategory.SECONDARY
            and p.is_configured(session, user)
            for p in self._providers.values()
        )

    def get_user_mfa_methods(self, session: Session, user: User) -> list[str]:
        return [
            mid
            for mid, p in self._providers.items()
            if p.category == AuthFactorCategory.SECONDARY
            and p.is_configured(session, user)
        ]


auth_registry = AuthRegistry()
