import secrets
import time

import orjson
import pyotp
from argon2 import PasswordHasher
from sqlalchemy.orm import Session

from include.config.settings import global_config
from include.database.models.auth import (
    UserAuthPolicy,
    UserPasswordCredential,
    UserTotpCredential,
)
from include.database.models.identity import User
from include.domains.identity.auth.types import AuthPurpose
from include.domains.identity.commands.auth_policies import replace_auth_policy

_password_hasher = PasswordHasher()


def set_password(
    session: Session,
    user: User,
    plain_password: str,
    force_update_after_login: bool = False,
) -> None:
    credential = session.get(UserPasswordCredential, user.id)
    if credential is None:
        credential = UserPasswordCredential(user=user)
        session.add(credential)
    credential.set_password(plain_password, force_update_after_login)
    user.secret_key = secrets.token_hex(32)


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
    """Remove TOTP, clearing only its exact standard single-step MFA policy."""
    policy = session.get(UserAuthPolicy, (user.id, AuthPurpose.MFA.value))
    if policy is not None and policy.chains == [
        [
            {
                "method": "totp",
                "credential_ids": [credential.credential_id],
            }
        ]
    ]:
        replace_auth_policy(
            session, user, AuthPurpose.MFA, [], expected_revision=policy.revision
        )
    session.delete(credential)
