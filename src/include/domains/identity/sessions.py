import time
from typing import Any

lazy from sqlalchemy.orm import Session as ORMSession

from include.config.constants import DEFAULT_TOKEN_EXPIRY_SECONDS
from include.config.settings import global_config
from include.database.models.identity import User, UserStatus
from include.database.models.keyrings import UserKey
from include.domains.identity.auth.flows import get_login_progress
from include.domains.identity.auth.types import AuthenticationContext
from include.domains.identity.tokens import Token, TokenPurpose
from include.exceptions.misc import UserNotActiveError


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
) -> tuple[int, str, dict[str, Any]]:
    """Issue a session only after both policies pass, or offer supported continuation."""
    progress = get_login_progress(session, user, context)
    if progress.satisfied:
        token = user.create_token_after_authentication()
        return 200, "Login successful", build_login_success_data(session, user, token)
    if not any(step.method == "totp" for step in progress.next_steps):
        return 403, "Authentication policy cannot be completed by this endpoint", {}
    duration = DEFAULT_TOKEN_EXPIRY_SECONDS / 2
    if expires_at is not None:
        duration = min(duration, expires_at - time.time())
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
            "methods": ["totp"],
        },
    )
