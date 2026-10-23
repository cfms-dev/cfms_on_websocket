from typing import Any

from sqlalchemy.orm import Session

from include.database.models.auth import UserAuthPolicy
from include.domains.identity.auth.base import (
    AuthFactorCategory,
    BaseAuthMethodProvider,
)
from include.domains.identity.auth.policies import evaluate_auth_policy
from include.domains.identity.auth.providers.password import PasswordAuthProvider
from include.domains.identity.auth.providers.publickey import PublicKeyAuthProvider
from include.domains.identity.auth.providers.totp import TOTPAuthProvider
from include.domains.identity.auth.types import (
    AuthEvidence,
    AuthPolicyDecision,
    AuthPurpose,
    RegisteredCredential,
    auth_chains_adapter,
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
                "purposes": sorted(p.supported_purposes),
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
            if any(c.active for c in p.list_credentials(session, user)):
                if p.category == AuthFactorCategory.PRIMARY:
                    primary.append(mid)
                elif p.category == AuthFactorCategory.SECONDARY:
                    secondary.append(mid)
        return {"primary": primary, "secondary": secondary}

    def user_requires_mfa(self, session: Session, user: User) -> bool:
        policy = session.get(UserAuthPolicy, (user.id, AuthPurpose.MFA.value))
        return policy is not None and bool(policy.chains)

    def get_user_mfa_methods(self, session: Session, user: User) -> list[str]:
        policy = session.get(UserAuthPolicy, (user.id, AuthPurpose.MFA.value))
        if policy is None:
            return []
        return sorted(
            {
                step.method
                for chain in auth_chains_adapter.validate_python(policy.chains)
                for step in chain
            }
        )

    def list_user_credentials(
        self, session: Session, user: User
    ) -> list[RegisteredCredential]:
        return [
            credential
            for provider in self._providers.values()
            for credential in provider.list_credentials(session, user)
        ]

    def evaluate_user_policy(
        self,
        session: Session,
        user: User,
        purpose: AuthPurpose,
        evidence: list[AuthEvidence],
        *,
        attempt_id: str,
        method: str | None = None,
        excluded_method: str | None = None,
    ) -> AuthPolicyDecision:
        policy = session.get(UserAuthPolicy, (user.id, purpose.value))
        chains = (
            [] if policy is None else auth_chains_adapter.validate_python(policy.chains)
        )
        eligible = [
            chain
            for chain in chains
            if len({step.method for step in chain}) == 1
            and (method is None or chain[0].method == method)
            and chain[0].method != excluded_method
            and (provider := self.get(chain[0].method)) is not None
            and purpose in provider.supported_purposes
        ]
        if chains and not eligible:
            return AuthPolicyDecision(satisfied=False)
        methods = {chain[0].method for chain in eligible} | {e.method for e in evidence}
        credentials = [
            credential
            for mid in methods
            if (provider := self.get(mid)) is not None
            for credential in provider.list_credentials(session, user)
        ]
        return evaluate_auth_policy(
            purpose,
            eligible,
            credentials,
            evidence,
            user_id=user.id,
            attempt_id=attempt_id,
        )


auth_registry = AuthRegistry()

auth_registry.register(PasswordAuthProvider())
auth_registry.register(PublicKeyAuthProvider())
auth_registry.register(TOTPAuthProvider())
