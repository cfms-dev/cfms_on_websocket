import time
from typing import Any

lazy from sqlalchemy.orm import Session as ORMSession

from include.config.constants import DEFAULT_TOKEN_EXPIRY_SECONDS
from include.config.settings import global_config
from include.database.models.identity import User, UserStatus
from include.database.models.keyrings import UserKey
from include.domains.identity.auth.flows import get_login_progress
from include.domains.identity.auth.password_state import password_change_requirement
from include.domains.identity.auth.types import (
    AuthenticationContext,
    AuthPurpose,
    InvalidAuthenticationAttempt,
    PasswordAssessment,
)
from include.domains.identity.tokens import Token, TokenPurpose
from include.exceptions.misc import UserNotActiveError
from include.providers.manager import ProviderManager


def issue_login_token(user: User) -> Token:
    if user.status != UserStatus.ACTIVE:
        raise UserNotActiveError(user.status_reason)

    return user.renew_token()


def build_login_success_data(
    session: ORMSession,
    user: User,
    token: Token,
) -> dict[str, Any]:
    data: dict[str, Any] = {
        "user_id": str(user.id),
        "token": token.raw,
        "exp": token.exp,
        "purpose": int(token.purpose),
        "nickname": user.nickname,
        "avatar_id": user.avatar_id,
        "permissions": list(user.all_permissions),
        "groups": list(user.all_groups),
    }

    if user.preference_dek_id:
        preference_dek = session.get(UserKey, user.preference_dek_id)
        if preference_dek:
            data["preference_dek"] = {
                "key_id": preference_dek.id,
                "key_content": preference_dek.content,
                "label": preference_dek.label,
            }

    return data


def finish_login_attempt(
    session: ORMSession,
    user: User,
    context: AuthenticationContext,
    *,
    expires_at: float | None = None,
    password_assessment: PasswordAssessment | None = None,
) -> tuple[int, str, dict[str, Any]]:
    """Issue a session only after both policies pass, or offer supported continuation."""
    progress = get_login_progress(session, user, context)
    if user.status != UserStatus.ACTIVE:
        return 4003, "User account is not active", {"reason": user.status_reason}
    if progress.purpose == AuthPurpose.LOGIN:
        return 403, "Login policy is not complete", {}
    duration = DEFAULT_TOKEN_EXPIRY_SECONDS / 2
    if expires_at is not None:
        duration = min(duration, expires_at - time.time())
    if duration <= 0:
        raise InvalidAuthenticationAttempt("Authentication expired; restart login")
    cache_key = f"auth:password:{context.attempt_id}"
    if password_assessment is not None and not ProviderManager().caching.set(
        cache_key, password_assessment.model_dump_json(), ttl=duration
    ):
        return 503, "Authentication state could not be saved; restart login", {}
    if progress.satisfied:
        requirement = password_change_requirement(
            session, user, context, password_assessment
        )
        if requirement is not None:
            token = Token.new(
                user.id,
                min(300, duration),
                user.secret_key or global_config["server"]["secret_key"],
                purpose=TokenPurpose.POST_AUTH,
                auth_context=context,
            )
            session.commit()
            return (
                requirement,
                "Password must be changed before you can log in",
                {
                    "token": token.raw,
                    "exp": token.exp,
                    "purpose": int(token.purpose),
                    "required_actions": ["change_password"],
                },
            )
        token = user.create_token_after_authentication()
        if any(e.method == "password" for e in context.evidence):
            ProviderManager().caching.delete(cache_key)
        return 200, "Login successful", build_login_success_data(session, user, token)
    methods = sorted({step.method for step in progress.next_steps})
    if not methods:
        return 403, "Authentication policy cannot be completed by this endpoint", {}
    token = Token.new(
        user.id,
        duration,
        user.secret_key or global_config["server"]["secret_key"],
        purpose=TokenPurpose.AUTH,
        auth_context=context,
    )
    session.commit()
    return (
        202,
        "Two-factor authentication required",
        {
            "token": token.raw,
            "exp": token.exp,
            "purpose": int(token.purpose),
            "methods": methods,
        },
    )
