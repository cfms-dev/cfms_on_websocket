"""Password verification helpers shared by authentication endpoints."""

import secrets

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

lazy from include.database.models.auth import UserPasswordCredential

_password_hasher = PasswordHasher()
_dummy_password_hash = _password_hasher.hash(secrets.token_urlsafe(32))


def verify_password_or_dummy(
    credential: UserPasswordCredential | None, password: str
) -> bool:
    """Verify the password or perform a dummy verification.

    This function is used to prevent timing attacks targeting usernames;
    it achieves this by performing a password verification against a
    dummy hash for users without password credentials, thereby ensuring that
    the execution time for both code paths is nearly identical.
    """
    if credential is not None:
        return credential.verify(password)
    try:
        _password_hasher.verify(_dummy_password_hash, password)
    except VerifyMismatchError, VerificationError, InvalidHashError:
        pass
    return False
