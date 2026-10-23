from sqlalchemy.orm import Session

from include.database.models.auth import UserAuthPolicy
from include.database.models.identity import User
from include.domains.identity.auth.registry import auth_registry
from include.domains.identity.auth.types import (
    AuthenticationContext,
    AuthEvidence,
    AuthPolicyDecision,
    AuthPurpose,
)


class InvalidAuthenticationAttempt(ValueError):
    pass


def start_login_attempt(
    session: Session,
    user: User,
    method: str,
    credential_id: str,
) -> AuthenticationContext | None:
    policies = [
        session.get(UserAuthPolicy, (user.id, purpose.value))
        for purpose in (AuthPurpose.LOGIN, AuthPurpose.MFA)
    ]
    context = AuthenticationContext(
        login_revision=policies[0].revision if policies[0] else 0,
        mfa_revision=policies[1].revision if policies[1] else 0,
    )
    initial = auth_registry.evaluate_user_policy(
        session,
        user,
        AuthPurpose.LOGIN,
        [],
        attempt_id=context.attempt_id,
    )
    if not any(
        s.method == method and credential_id in s.credential_ids
        for s in initial.next_steps
    ):
        return None
    return context.model_copy(
        update={
            "evidence": [
                AuthEvidence(
                    user_id=user.id,
                    attempt_id=context.attempt_id,
                    method=method,
                    credential_id=credential_id,
                )
            ]
        }
    )


def get_login_progress(
    session: Session,
    user: User,
    context: AuthenticationContext,
) -> AuthPolicyDecision:
    for purpose, revision in (
        (AuthPurpose.LOGIN, context.login_revision),
        (AuthPurpose.MFA, context.mfa_revision),
    ):
        policy = session.get(UserAuthPolicy, (user.id, purpose.value))
        if (policy.revision if policy else 0) != revision:
            raise InvalidAuthenticationAttempt(
                "Authentication policy changed; restart login"
            )
    active = {
        (c.method, c.credential_id)
        for c in auth_registry.list_user_credentials(session, user)
        if c.active
    }
    if (
        not context.evidence
        or len({e.event_id for e in context.evidence}) != len(context.evidence)
        or any(
            e.user_id != user.id
            or e.attempt_id != context.attempt_id
            or (e.method, e.credential_id) not in active
            for e in context.evidence
        )
    ):
        raise InvalidAuthenticationAttempt(
            "Authentication credentials changed; restart login"
        )
    login = auth_registry.evaluate_user_policy(
        session,
        user,
        AuthPurpose.LOGIN,
        context.evidence,
        attempt_id=context.attempt_id,
    )
    if not login.satisfied:
        return login
    return auth_registry.evaluate_user_policy(
        session,
        user,
        AuthPurpose.MFA,
        context.evidence,
        attempt_id=context.attempt_id,
    )
