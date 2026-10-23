from typing import Any, cast

from sqlalchemy import update
from sqlalchemy.engine import CursorResult
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from include.database.models.auth import UserAuthPolicy
from include.database.models.identity import User
from include.domains.identity.auth.registry import auth_registry
from include.domains.identity.auth.types import AuthPurpose, auth_chains_adapter


class AuthPolicyConflict(ValueError):
    pass


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
        for step in chain:
            if auth_registry.get(step.method) is None:
                raise ValueError(f"Unknown authentication method {step.method!r}")
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
