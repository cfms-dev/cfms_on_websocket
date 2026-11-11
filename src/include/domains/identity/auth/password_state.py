import hashlib
import time
from dataclasses import asdict

import orjson
from sqlalchemy.orm import Session

from include.config.validation import PasswordPolicy
from include.database.models.auth import UserPasswordCredential
from include.database.models.identity import User
from include.domains.identity.auth.types import (
    AuthenticationContext,
    InvalidAuthenticationAttempt,
    PasswordAssessment,
)
from include.domains.identity.validators.passwords import check_passwd_requirements
from include.providers.manager import ProviderManager


def password_policy_digest(policy: PasswordPolicy) -> str:
    return hashlib.sha256(
        orjson.dumps(asdict(policy), option=orjson.OPT_SORT_KEYS)
    ).hexdigest()


def assess_password(
    credential: UserPasswordCredential, password: str, policy: PasswordPolicy
) -> PasswordAssessment:
    satisfied = True
    try:
        check_passwd_requirements(
            password,
            policy.passwd_min_length,
            policy.passwd_max_length,
            policy.passwd_rules,
            policy.passwd_min_passed_count,
        )
    except ValueError:
        satisfied = False
    return PasswordAssessment(
        credential_id=credential.credential_id,
        modified_at=credential.passwd_last_modified,
        policy_digest=password_policy_digest(policy),
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
    policy = PasswordPolicy.from_options(session)
    credential = session.get(UserPasswordCredential, user.id)
    if (
        credential is None
        or assessment.credential_id not in password_ids
        or credential.credential_id != assessment.credential_id
        or credential.passwd_last_modified != assessment.modified_at
        or assessment.policy_digest != password_policy_digest(policy)
    ):
        raise InvalidAuthenticationAttempt(
            "Password or password policy changed; restart login"
        )
    if not assessment.rules_satisfied:
        return 4001
    if credential.passwd_last_modified == 0 or (
        policy.enable_passwd_force_expiration
        and time.time() - credential.passwd_last_modified
        > 86400 * policy.passwd_expire_after_days
    ):
        return 4002
    return None
