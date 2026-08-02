import ast
import subprocess
import sys
from pathlib import Path
from shutil import copyfile

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _dict_value(node: ast.Dict, key: str) -> ast.expr:
    for key_node, value_node in zip(node.keys, node.values, strict=True):
        if isinstance(key_node, ast.Constant) and key_node.value == key:
            return value_node
    raise AssertionError(f"Key {key!r} was not found")


def _assert_schema_uses_username_max_length(relative_path: str, class_name: str):
    module = ast.parse((PROJECT_ROOT / relative_path).read_text(encoding="utf-8"))
    handler_class = next(
        node
        for node in module.body
        if isinstance(node, ast.ClassDef) and node.name == class_name
    )
    schema_assignment = next(
        node
        for node in handler_class.body
        if isinstance(node, ast.Assign)
        and any(
            isinstance(target, ast.Name) and target.id == "schema"
            for target in node.targets
        )
    )

    assert isinstance(schema_assignment.value, ast.Dict)
    properties = _dict_value(schema_assignment.value, "properties")
    assert isinstance(properties, ast.Dict)
    username = _dict_value(properties, "username")
    assert isinstance(username, ast.Dict)
    max_length = _dict_value(username, "maxLength")
    assert isinstance(max_length, ast.Name)
    assert max_length.id == "USERNAME_MAX_LENGTH"


def test_username_length_limit_is_shared_by_server(tmp_path):
    handler_schemas = (
        (
            "src/include/domains/identity/handlers/auth.py",
            "RequestLoginHandler",
        ),
        (
            "src/include/domains/identity/handlers/users.py",
            "RequestCreateUserHandler",
        ),
        (
            "src/include/domains/identity/handlers/users.py",
            "RequestSetPasswdHandler",
        ),
        (
            "src/include/domains/security/handlers/two_factor.py",
            "RequestDisable2FAHandler",
        ),
    )
    for relative_path, class_name in handler_schemas:
        _assert_schema_uses_username_max_length(relative_path, class_name)

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
from include.config.constants import USERNAME_DATABASE_MAX_LENGTH
from include.database.models.documents import DocumentMetadata
from include.database.models.identity import User
from include.database.models.security import AccountThrottle

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
