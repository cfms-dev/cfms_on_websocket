import secrets
import time
from typing import cast

import orjson
import pyotp
from argon2 import PasswordHasher
from sqlalchemy import CursorResult, update
from sqlalchemy.orm import Session

from include.config.settings import global_config
from include.database.models.auth import (
    UserAuthPolicy,
    UserPasswordCredential,
    UserTotpCredential,
)
from include.database.models.identity import User, UserStatus
from include.domains.identity.auth.types import (
    AuthPurpose,
    InvalidAuthenticationAttempt,
)
from include.domains.identity.commands.auth_policies import (
    ensure_authentication_available,
    remove_credential_from_auth_policies,
    replace_auth_policy,
)

_password_hasher = PasswordHasher()


def set_password(
    session: Session,
    user: User,
    plain_password: str,
    force_update_after_login: bool = False,
    *,
    expected_signing_key: str | None = None,
) -> None:
    new_secret = secrets.token_hex(32)
    if expected_signing_key is not None:
        claimed = cast(
            CursorResult,
            session.execute(
                update(User)
                .where(
                    User.id == user.id,
                    User.secret_key == expected_signing_key,
                    User.status == UserStatus.ACTIVE,
                )
                .values(secret_key=new_secret)
            ),
        )
        if claimed.rowcount != 1:
            raise InvalidAuthenticationAttempt(
                "Authentication credentials changed; restart login"
            )
    credential = session.get(UserPasswordCredential, user.id)
    if credential is None:
        credential = UserPasswordCredential(user=user)
        session.add(credential)
    credential.set_password(plain_password, force_update_after_login)
    user.secret_key = new_secret


def setup_totp(session: Session, user: User) -> tuple[UserTotpCredential, list[str]]:
    secret = pyotp.random_base32()
    backup_codes = [secrets.token_hex(4) for _ in range(10)]
    pepper = global_config["security"]["pepper"]
    hashed_codes = [_password_hasher.hash(code + pepper) for code in backup_codes]
    credential = session.get(UserTotpCredential, user.id)
    if credential is None:
        credential = UserTotpCredential(user=user)
        session.add(credential)
    credential.secret = secret
    credential.enabled = False
    credential.backup_codes = orjson.dumps(hashed_codes).decode("utf-8")
    credential.created_time = time.time()
    return credential, backup_codes


def enable_login_totp(
    session: Session, user: User, credential: UserTotpCredential
) -> None:
    """Activate TOTP and explicitly establish the standard login MFA policy."""
    credential.enable()
    session.flush()
    policy = session.get(UserAuthPolicy, (user.id, AuthPurpose.MFA.value))
    if policy is None or not policy.chains:
        replace_auth_policy(
            session,
            user,
            AuthPurpose.MFA,
            [
                [
                    {
                        "method": "totp",
                        "credential_ids": [credential.credential_id],
                    }
                ]
            ],
            expected_revision=policy.revision if policy else 0,
        )


def remove_totp(session: Session, user: User, credential: UserTotpCredential) -> None:
    """Remove TOTP and its policy dependencies in the caller's transaction."""
    remove_credential_from_auth_policies(
        session, user, "totp", credential.credential_id
    )
    session.delete(credential)
    session.flush()
    ensure_authentication_available(session, user)
