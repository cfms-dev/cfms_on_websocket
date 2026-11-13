import secrets
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cache

import orjson
import pyotp
import pytest
from argon2 import PasswordHasher


@dataclass(frozen=True)
class AuthMaterial:
    password_hash: str = field(repr=False)
    totp_secret: str = field(repr=False)
    backup_codes: tuple[str, ...] = field(repr=False)
    backup_hashes: str = field(repr=False)


@pytest.fixture(scope="session")
def auth_material_factory() -> Callable[[str, str], AuthMaterial]:
    @cache
    def prepare(password: str, pepper: str) -> AuthMaterial:
        hasher = PasswordHasher()
        codes = tuple(secrets.token_hex(4) for _ in range(10))
        return AuthMaterial(
            password_hash=hasher.hash(password),
            totp_secret=pyotp.random_base32(),
            backup_codes=codes,
            backup_hashes=orjson.dumps(
                [hasher.hash(code + pepper) for code in codes]
            ).decode("utf-8"),
        )

    return prepare
