import hashlib
import time

import orjson
from sqlalchemy.orm import Session

from include.config.settings import global_config
from include.database.models.auth import UserPasswordCredential
from include.database.models.identity import User
from include.domains.identity.auth.types import (
    AuthenticationContext,
    InvalidAuthenticationAttempt,
    PasswordAssessment,
)
from include.domains.identity.validators.passwords import check_passwd_requirements
from include.providers.manager import ProviderManager


def password_policy_digest() -> str:
    cfg = global_config["security"]
    return hashlib.sha256(
        orjson.dumps(
            {
                key: cfg[key]
                for key in (
                    "passwd_min_length",
                    "passwd_max_length",
                    "passwd_rules",
                    "passwd_min_passed_count",
                    "enable_passwd_force_expiration",
                    "passwd_expire_after_days",
                )
            },
            option=orjson.OPT_SORT_KEYS,
        )
    ).hexdigest()


def assess_password(
    credential: UserPasswordCredential, password: str
) -> PasswordAssessment:
    cfg = global_config["security"]
    satisfied = True
    try:
        check_passwd_requirements(
            password,
            cfg["passwd_min_length"],
            cfg["passwd_max_length"],
            cfg["passwd_rules"],
            cfg["passwd_min_passed_count"],
        )
    except ValueError:
        satisfied = False
    return PasswordAssessment(
        credential_id=credential.credential_id,
        modified_at=credential.passwd_last_modified,
        policy_digest=password_policy_digest(),
        rules_satisfied=satisfied,
    )


def password_change_requirement(
    session: Session,
    user: User,
    context: AuthenticationContext,
    assessment: PasswordAssessment | None = None,
) -> int | None:
    password_ids = {e.credential_id for e in context.evidence if e.method == "password"}
    if not password_ids:
        return None
    if assessment is None:
        stored = ProviderManager().caching.get(f"auth:password:{context.attempt_id}")
        if stored is None:
            raise InvalidAuthenticationAttempt(
                "Authentication state expired; restart login"
            )
        assessment = PasswordAssessment.model_validate_json(stored)
    credential = session.get(UserPasswordCredential, user.id)
    if (
        credential is None
        or assessment.credential_id not in password_ids
        or credential.credential_id != assessment.credential_id
        or credential.passwd_last_modified != assessment.modified_at
        or assessment.policy_digest != password_policy_digest()
    ):
        raise InvalidAuthenticationAttempt(
            "Password or password policy changed; restart login"
        )
    if not assessment.rules_satisfied:
        return 4001
    cfg = global_config["security"]
    if credential.passwd_last_modified == 0 or (
        cfg["enable_passwd_force_expiration"]
        and time.time() - credential.passwd_last_modified
        > 86400 * cfg["passwd_expire_after_days"]
    ):
        return 4002
    return None
