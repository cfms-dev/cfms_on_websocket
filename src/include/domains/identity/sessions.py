from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session as ORMSession

from include.database.models.identity import User, UserStatus
from include.database.models.keyrings import UserKey
from include.domains.identity.tokens import Token
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
