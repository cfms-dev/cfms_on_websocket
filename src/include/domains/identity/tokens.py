__all__ = ["Token"]

import time
from enum import IntFlag

import jwt
from pydantic import Field, TypeAdapter
from pydantic.dataclasses import dataclass


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

    username: str
    purpose: TokenPurpose
    exp: float
    nbf: float
    iat: float
    _secret: str = Field(exclude=True)

    @classmethod
    def from_raw(cls, raw_token: str, secret: str) -> Token:
        """Create a Token instance from a raw JWT token string.

        The provided token will be verified during decoding; therefore, the SECRET
        used must also be provided.
        """
        decoded = jwt.decode(raw_token, secret, algorithms="HS256")

        token = TypeAdapter(cls).validate_python(decoded)
        token._secret = secret
        return token

    @classmethod
    def new(
        cls, username: str, duration: float, secret: str, purpose=TokenPurpose.GENERAL
    ) -> Token:
        nbf = iat = time.time()
        exp = nbf + duration
        return cls(
            username=username,
            purpose=purpose,
            exp=exp,
            nbf=nbf,
            iat=iat,
            _secret=secret,
        )

    @property
    def raw(self) -> str:
        return jwt.encode(
            TypeAdapter(Token).dump_python(self), self._secret, algorithm="HS256"
        )
