import subprocess
import sys

import pytest

pytestmark = pytest.mark.integration


def test_username_length_limit_is_shared_by_server(protected_test_config):
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
from pathlib import Path

from include.config.constants import USERNAME_DATABASE_MAX_LENGTH, USERNAME_MAX_LENGTH
from include.config.paths import EXECUTABLE_ABSPATH
from include.database.models.documents import DocumentMetadata
from include.database.models.identity import User
from include.database.models.security import AccountThrottle
from include.domains.identity.auth.providers.password import PasswordCredentialSchema
from include.domains.identity.auth.providers.publickey import PublicKeyLoginRequest
from include.domains.identity.handlers.users import (
    RequestCreateUserHandler,
)
from pydantic import ValidationError

assert EXECUTABLE_ABSPATH == Path.cwd()

handler_payloads = (
    (RequestCreateUserHandler, {"username": "u", "password": "secret"}),
)
for handler_type, payload in handler_payloads:
    handler_type.request_model.model_validate(
        payload | {"username": "u" * USERNAME_MAX_LENGTH}
    )
    try:
        handler_type.request_model.model_validate(
            payload | {"username": "u" * (USERNAME_MAX_LENGTH + 1)}
        )
    except ValidationError:
        pass
    else:
        raise AssertionError(f"{handler_type.__name__} accepted an oversized username")

for schema, credential in (
    (PasswordCredentialSchema, {"password": "secret"}),
    (PublicKeyLoginRequest, {"fingerprint": "f" * 64}),
):
    schema.model_validate(credential | {"username": "u" * USERNAME_MAX_LENGTH})
    try:
        schema.model_validate(credential | {"username": "u" * (USERNAME_MAX_LENGTH + 1)})
    except ValidationError:
        pass
    else:
        raise AssertionError(f"{schema.__name__} accepted an oversized username")

username_columns = (
    User.__table__.c.username,
    AccountThrottle.__table__.c.username,
)
for column in username_columns:
    assert column.type.length == USERNAME_DATABASE_MAX_LENGTH
""",
        ],
        cwd=protected_test_config.src_dir,
        capture_output=True,
        check=False,
        text=True,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
