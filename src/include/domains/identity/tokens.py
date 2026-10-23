__all__ = ["Token"]

import time
import uuid
from enum import IntFlag

import jwt
from pydantic import Field, TypeAdapter, ValidationError
from pydantic.dataclasses import dataclass

from include.domains.identity.auth.types import AuthenticationContext


class TokenPurpose(IntFlag):
    """Enumeration of token purposes.

    Since a single token may serve multiple purposes, this class is defined as a
    subclass of `IntFlag`.

    The `auto()` function is not used to determine the flag values because we
    prefer to explicitly define the flags corresponding to each purpose within
    the communication protocol, rather than relying on an automated mechanism
    that might appear to be a "black box" (though it is not, in fact, a black
    box—see the
    [documentation](https://docs.python.org/3.15/library/enum.html#enum.IntFlag)).

    However, we still employed the `auto()` determination method, ensuring that
    each flag is a power of 2, starting from 1.
    """

    AUTH = 1  # Used for further authentication (e.g., 2FA, etc.)
    GENERAL = 2  # Used for general purposes (e.g., API access, etc.)
    ESCALATION = 4  # Token with superuser privileges


@dataclass
class Token:
    """Data class representing a token.

    Many of the properties in this class are non-null, as any valid token issued
    by CFMS is required by the specification to adhere to this constraint.
    """

    sub: uuid.UUID  # is user.id
    purpose: TokenPurpose
    exp: float
    nbf: float
    iat: float
    _secret: str = Field(exclude=True, repr=False)
    auth_context: AuthenticationContext | None = None

    @classmethod
    def from_raw(cls, raw_token: str, secret: str) -> Token:
        """Create a Token instance from a raw JWT token string.

        The provided token will be verified during decoding; therefore, the SECRET
        used must also be provided.
        """
        decoded = jwt.decode(raw_token, secret, algorithms="HS256")

        try:
            return TypeAdapter(cls).validate_python({**decoded, "_secret": secret})
        except ValidationError as exc:
            raise jwt.InvalidTokenError("Invalid token claims") from exc

    @classmethod
    def new(
        cls,
        user_id: uuid.UUID,
        duration: float,
        secret: str,
        purpose=TokenPurpose.GENERAL,
        *,
        auth_context: AuthenticationContext | None = None,
    ) -> Token:
        nbf = iat = time.time()
        exp = nbf + duration
        return cls(
            sub=user_id,
            purpose=purpose,
            exp=exp,
            nbf=nbf,
            iat=iat,
            _secret=secret,
            auth_context=auth_context,
        )

    @property
    def raw(self) -> str:
        return jwt.encode(
            TypeAdapter(Token).dump_python(self, mode="json", exclude_none=True),
            self._secret,
            algorithm="HS256",
        )

    def has_purpose(self, purpose: TokenPurpose, /) -> bool:
        """Check if the token has the specified purpose."""
        return self.purpose & purpose == purpose
