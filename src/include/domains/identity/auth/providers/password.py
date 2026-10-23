import time
from typing import Any

from pydantic import BaseModel
from sqlalchemy.orm import Session

from include.config.settings import global_config
from include.database.models.auth import UserPasswordCredential
from include.database.models.identity import User
from include.domains.identity.auth.base import (
    AuthFactorCategory,
    AuthVerificationResult,
    BaseAuthMethodProvider,
)
from include.domains.identity.auth.types import RegisteredCredential
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

    def list_credentials(
        self, session: Session, user: User
    ) -> list[RegisteredCredential]:
        credential = session.get(UserPasswordCredential, user.id)
        return (
            []
            if credential is None
            else [
                RegisteredCredential(
                    method=self.method_id,
                    credential_id=credential.credential_id,
                    active=True,
                )
            ]
        )

    def verify(
        self,
        session: Session,
        user: User,
        payload: dict[str, Any],
        context: dict[str, Any],
    ) -> AuthVerificationResult:
        password: str = payload.get("password", "")
        credential = session.get(UserPasswordCredential, user.id)
        if not verify_password_or_dummy(credential, password):
            return AuthVerificationResult(
                success=False, error_code=401, error_message="Invalid credentials"
            )

        assert credential is not None

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
            if time.time() - credential.passwd_last_modified > expiration_seconds:
                return AuthVerificationResult(
                    success=False,
                    error_code=4002,
                    error_message="Password should be changed because it's expired",
                )

        credential.rehash_if_needed(password)

        return AuthVerificationResult(
            success=True, credential_id=credential.credential_id
        )
