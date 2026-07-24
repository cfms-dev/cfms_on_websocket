"""Password verification helpers shared by authentication endpoints."""

import secrets
from typing import TYPE_CHECKING

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

if TYPE_CHECKING:
    from include.database.models.identity import User

_password_hasher = PasswordHasher()
_dummy_password_hash = _password_hasher.hash(secrets.token_urlsafe(32))


def verify_password_or_dummy(user: User | None, password: str) -> bool:
    """Verify the password or perform a dummy verification.

    This function is used to prevent timing attacks targeting usernames;
    it achieves this by performing a password verification against a
    dummy hash for non-existent users, thereby ensuring that the execution
    time for both code paths is nearly identical.
    """
    if user is not None:
        return user.verify_password(password)
    try:
        _password_hasher.verify(_dummy_password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        pass
    return False
