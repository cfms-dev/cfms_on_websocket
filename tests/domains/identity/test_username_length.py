import subprocess
import sys
from pathlib import Path
from shutil import copyfile

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_username_length_limit_is_shared_by_server(tmp_path):
    database_model_constants = (
        (
            "src/include/database/models/identity.py",
            "VARCHAR(USERNAME_DATABASE_MAX_LENGTH)",
        ),
        (
            "src/include/database/models/security.py",
            "String(USERNAME_DATABASE_MAX_LENGTH)",
        ),
        (
            "src/include/database/models/documents.py",
            "VARCHAR(USERNAME_DATABASE_MAX_LENGTH)",
        ),
    )
    for relative_path, expected_usage in database_model_constants:
        source = (PROJECT_ROOT / relative_path).read_text(encoding="utf-8")
        assert expected_usage in source
        assert "USERNAME_MAX_LENGTH" not in source

    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    (tmp_path / "init").touch()

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            """
from include.config.constants import USERNAME_DATABASE_MAX_LENGTH, USERNAME_MAX_LENGTH
from include.database.models.documents import DocumentMetadata
from include.database.models.identity import User
from include.database.models.security import AccountThrottle
from include.domains.identity.handlers.auth import RequestLoginHandler
from include.domains.identity.handlers.users import (
    RequestCreateUserHandler,
    RequestSetPasswdHandler,
)
from include.domains.security.handlers.two_factor import RequestDisable2FAHandler
from pydantic import ValidationError

handler_payloads = (
    (RequestLoginHandler, {"username": "u", "password": "secret"}),
    (RequestCreateUserHandler, {"username": "u", "password": "secret"}),
    (
        RequestSetPasswdHandler,
        {"username": "u", "new_passwd": "secret"},
    ),
    (RequestDisable2FAHandler, {"username": "u"}),
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

username_columns = (
    User.__table__.c.username,
    AccountThrottle.__table__.c.username,
    DocumentMetadata.__table__.c.creator_username,
    DocumentMetadata.__table__.c.last_modified_by_username,
)
for column in username_columns:
    assert column.type.length == USERNAME_DATABASE_MAX_LENGTH
""",
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert result.returncode == 0, result.stderr
