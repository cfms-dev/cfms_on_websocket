import time
from typing import Any

from pydantic import BaseModel
from sqlalchemy.orm import Session

from include.config.settings import global_config
from include.database.models.identity import User
from include.domains.identity.auth.base import (
    AuthFactorCategory,
    AuthVerificationResult,
    BaseAuthMethodProvider,
)
from include.domains.identity.password_auth import verify_password_or_dummy
from include.domains.identity.validators.passwords import check_passwd_requirements
lazy from include.types import NonEmptyString


class PasswordCredentialSchema(BaseModel):
    username: NonEmptyString
    password: NonEmptyString


class PasswordAuthProvider(BaseAuthMethodProvider):
    method_id = "password"
    category = AuthFactorCategory.PRIMARY
    throttle_factor = "password"
    credential_schema = PasswordCredentialSchema

    def is_configured(self, session: Session, user: User) -> bool:
        return user.password_credential is not None

    def verify(
        self,
        session: Session,
        user: User,
        payload: dict[str, Any],
        context: dict[str, Any],
    ) -> AuthVerificationResult:
        password: str = payload.get("password", "")
        if not verify_password_or_dummy(user, password):
            return AuthVerificationResult(
                success=False, error_code=401, error_message="Invalid credentials"
            )

        if not user.password_credential:
            return AuthVerificationResult(
                success=False, error_code=401, error_message="Invalid credentials"
            )

        cfg = global_config["security"]
        try:
            check_passwd_requirements(
                password,
                cfg["passwd_min_length"],
                cfg["passwd_max_length"],
                cfg["passwd_rules"],
                cfg["passwd_min_passed_count"],
            )
        except ValueError:
            return AuthVerificationResult(
                success=False,
                error_code=4001,
                error_message="Password must be changed before you can log in",
            )

        if cfg["enable_passwd_force_expiration"]:
            expiration_seconds = 3600 * 24 * cfg["passwd_expire_after_days"]
            if (
                time.time() - user.password_credential.passwd_last_modified
                > expiration_seconds
            ):
                return AuthVerificationResult(
                    success=False,
                    error_code=4002,
                    error_message="Password should be changed because it's expired",
                )

        if user.password_credential.check_needs_rehash():
            user.password_credential.set_password(password)
            session.add(user.password_credential)

        return AuthVerificationResult(success=True)
