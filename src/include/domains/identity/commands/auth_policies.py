from typing import Any, cast

from sqlalchemy import update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from include.database.models.auth import UserAuthPolicy
from include.database.models.identity import User
from include.domains.identity.auth.policies import can_complete_auth_chain
from include.domains.identity.auth.registry import auth_registry
from include.domains.identity.auth.types import (
    LOGIN_DISALLOWED_METHODS,
    AuthPurpose,
    auth_chains_adapter,
)


class AuthPolicyConflict(ValueError):
    pass


class AuthPolicyUnavailable(ValueError):
    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def ensure_authentication_available(session: Session, user: User) -> None:
    """Require a complete login path and preserve any configured escalation path."""
    credentials = auth_registry.list_user_credentials(session, user)
    available: dict[AuthPurpose, set[str]] = {}
    policies = {
        purpose: session.get(UserAuthPolicy, (user.id, purpose.value))
        for purpose in AuthPurpose
    }
    for purpose, policy in policies.items():
        methods = set()
        for chain in auth_chains_adapter.validate_python(
            policy.chains if policy else []
        ):
            method = chain[0].method
            provider = auth_registry.get(method)
            if (
                len({step.method for step in chain}) == 1
                and provider is not None
                and purpose in provider.supported_purposes
                and not (
                    purpose == AuthPurpose.LOGIN and method in LOGIN_DISALLOWED_METHODS
                )
                and can_complete_auth_chain(chain, credentials)
            ):
                methods.add(method)
        available[purpose] = methods
    mfa = policies[AuthPurpose.MFA]
    if not any(
        not (mfa and mfa.chains) or bool(available[AuthPurpose.MFA] - {login_method})
        for login_method in available[AuthPurpose.LOGIN]
    ):
        raise AuthPolicyUnavailable("login_unavailable")
    escalation = policies[AuthPurpose.ESCALATION]
    if escalation and escalation.chains and not available[AuthPurpose.ESCALATION]:
        raise AuthPolicyUnavailable("escalation_unavailable")


def replace_auth_policy(
    session: Session,
    user: User,
    purpose: AuthPurpose,
    chains: list[list[dict[str, str | list[str]]]],
    *,
    expected_revision: int,
) -> None:
    """Validate and replace a purpose policy in the caller's transaction."""
    purpose = AuthPurpose(purpose)
    if expected_revision < 0:
        raise ValueError("Policy revision must not be negative")
    parsed = auth_chains_adapter.validate_python(chains)
    credentials = {
        (c.method, c.credential_id)
        for c in auth_registry.list_user_credentials(session, user)
    }
    for chain in parsed:
        if len({step.method for step in chain}) != 1:
            raise ValueError("An authentication chain must use exactly one method")
        for step in chain:
            if purpose == AuthPurpose.LOGIN and step.method in LOGIN_DISALLOWED_METHODS:
                raise ValueError(
                    f"Authentication method {step.method!r} is not permitted for login"
                )
            provider = auth_registry.get(step.method)
            if provider is None:
                raise ValueError(f"Unknown authentication method {step.method!r}")
            if purpose not in provider.supported_purposes:
                raise ValueError(
                    f"Authentication method {step.method!r} does not support {purpose}"
                )
            if len(set(step.credential_ids)) != len(step.credential_ids):
                raise ValueError("Duplicate credential selector")
            if any(
                (step.method, cid) not in credentials for cid in step.credential_ids
            ):
                raise ValueError("Policy references an unregistered credential")
    data = auth_chains_adapter.dump_python(parsed, mode="json")
    if expected_revision == 0:
        try:
            with session.begin_nested():
                session.add(
                    UserAuthPolicy(
                        user_id=user.id, purpose=purpose.value, revision=1, chains=data
                    )
                )
                session.flush()
        except IntegrityError as exc:
            raise AuthPolicyConflict("Authentication policy changed") from exc
    else:
        result = cast(
            CursorResult[Any],
            session.execute(
                update(UserAuthPolicy)
                .where(
                    UserAuthPolicy.user_id == user.id,
                    UserAuthPolicy.purpose == purpose.value,
                    UserAuthPolicy.revision == expected_revision,
                )
                .values(chains=data, revision=expected_revision + 1)
            ),
        )
        if result.rowcount != 1:
            raise AuthPolicyConflict("Authentication policy changed")
