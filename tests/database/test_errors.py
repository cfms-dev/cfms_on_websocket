from types import SimpleNamespace

import pytest
from sqlalchemy import (
    Column,
    Integer,
    MetaData,
    String,
    Table,
    UniqueConstraint,
    insert,
)
from sqlalchemy.exc import IntegrityError

from include.database.errors import is_unique_constraint_violation


@pytest.mark.unit
@pytest.mark.parametrize("code_field", ["pgcode", "sqlstate"])
@pytest.mark.parametrize(
    ("code", "constraint", "expected"),
    [
        ("23505", "ix_users_username", True),
        ("23505", "other_index", False),
        ("23505", "ix_users_username_extra", False),
        ("23503", "ix_users_username", False),
        (None, "ix_users_username", False),
    ],
)
def test_postgresql_requires_unique_code_and_exact_constraint(
    code_field, code, constraint, expected
):
    original = SimpleNamespace(
        **{code_field: code}, diag=SimpleNamespace(constraint_name=constraint)
    )
    error = IntegrityError("UPDATE users", {}, original)

    assert (
        is_unique_constraint_violation(
            error,
            constraint_name="ix_users_username",
            sqlite_column_sets=(("users.username",),),
        )
        is expected
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "diagnostic", [None, SimpleNamespace(), SimpleNamespace(constraint_name=None)]
)
def test_postgresql_missing_diagnostics_does_not_match(diagnostic):
    error = IntegrityError(
        "UPDATE users", {}, SimpleNamespace(pgcode="23505", diag=diagnostic)
    )

    assert not is_unique_constraint_violation(
        error,
        constraint_name="ix_users_username",
        sqlite_column_sets=(("users.username",),),
    )


@pytest.mark.unit
@pytest.mark.parametrize("code_field", ["errno", "args"])
@pytest.mark.parametrize(
    ("code", "message", "expected"),
    [
        (1062, "Duplicate entry 'value' for key 'ix_users_username'", True),
        (1062, "Duplicate entry 'value' for key 'users.ix_users_username'", True),
        (1062, "Duplicate entry 'value' for key `ix_users_username`", True),
        (1062, "Duplicate entry 'value' for key \"ix_users_username\"", True),
        (1062, "Duplicate entry 'value' for key 'other_index'", False),
        (1062, "Duplicate entry 'ix_users_username' for key 'other_index'", False),
        (1062, "Duplicate entry 'value' for key 'ix_users_username_extra'", False),
        (1062, "Duplicate entry 'value' for key 'prefix_ix_users_username'", False),
        (1062, "Duplicate entry 'ix_users_username'", False),
        (1452, "Foreign key failure for key 'ix_users_username'", False),
        (None, "Duplicate entry 'value' for key 'ix_users_username'", False),
    ],
)
def test_mysql_requires_duplicate_code_and_exact_key(
    code_field, code, message, expected
):
    original = RuntimeError(message)
    if code_field == "errno":
        original.errno = code
        original.msg = message
    else:
        original.args = (code, message)
    error = IntegrityError("UPDATE users", {}, original)

    assert (
        is_unique_constraint_violation(
            error,
            constraint_name="ix_users_username",
            sqlite_column_sets=(("users.username",),),
        )
        is expected
    )


@pytest.mark.unit
def test_mysql_errno_takes_precedence_over_args():
    original = RuntimeError(1062, "Duplicate entry 'value' for key 'ix_users_username'")
    original.errno = 1452
    error = IntegrityError("UPDATE users", {}, original)

    assert not is_unique_constraint_violation(
        error,
        constraint_name="ix_users_username",
        sqlite_column_sets=(("users.username",),),
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    "error_name", ["SQLITE_CONSTRAINT_UNIQUE", "SQLITE_CONSTRAINT"]
)
@pytest.mark.parametrize(
    ("columns", "expected"),
    [
        ("nodes.parent_id, nodes.active_name", True),
        ("nodes.active_name, nodes.parent_id", True),
        ("nodes.active_parent_id, nodes.name", True),
        ("nodes.name, nodes.active_parent_id", True),
        ("nodes.parent_id", False),
        ("nodes.parent_id, nodes.active_name, nodes.id", False),
        ("nodes.parent_id, nodes.active_name_extra", False),
        ("nodes.parent_id, nodes.parent_id, nodes.active_name", False),
        ("other.parent_id, other.active_name", False),
    ],
)
def test_sqlite_requires_complete_column_set(error_name, columns, expected):
    original = RuntimeError(f"UNIQUE constraint failed: {columns}")
    original.sqlite_errorname = error_name
    error = IntegrityError("INSERT INTO nodes", {}, original)

    assert (
        is_unique_constraint_violation(
            error,
            constraint_name="uq_nodes_active_parent_name",
            sqlite_column_sets=(
                ("nodes.parent_id", "nodes.active_name"),
                ("nodes.active_parent_id", "nodes.name"),
            ),
        )
        is expected
    )


@pytest.mark.unit
@pytest.mark.parametrize(
    ("error_name", "message"),
    [
        ("SQLITE_CONSTRAINT_FOREIGNKEY", "UNIQUE constraint failed: users.username"),
        ("SQLITE_CONSTRAINT_TRIGGER", "UNIQUE constraint failed: users.username"),
        ("SQLITE_CONSTRAINT", "CHECK constraint failed: ix_users_username"),
        ("SQLITE_CONSTRAINT_UNIQUE", "users.username"),
        (None, "UNIQUE constraint failed: users.username"),
        (None, "ix_users_username"),
    ],
)
def test_sqlite_requires_unique_error_and_message_prefix(error_name, message):
    original = RuntimeError(message)
    if error_name is not None:
        original.sqlite_errorname = error_name
    error = IntegrityError("UPDATE users", {}, original)

    assert not is_unique_constraint_violation(
        error,
        constraint_name="ix_users_username",
        sqlite_column_sets=(("users.username",),),
    )


@pytest.mark.component
@pytest.mark.parametrize("duplicate_column", ["username", "email"])
def test_real_sqlite_unique_error_identifies_only_target_columns(
    sqlite_engine_factory, tmp_path, duplicate_column
):
    engine = sqlite_engine_factory(tmp_path / "constraints.db")
    users = Table(
        "users",
        MetaData(),
        Column("id", Integer, primary_key=True),
        Column("username", String),
        Column("email", String),
        UniqueConstraint("username", name="ix_users_username"),
        UniqueConstraint("email", name="uq_users_email"),
    )
    users.metadata.create_all(engine)
    with engine.begin() as connection:
        connection.execute(insert(users), {"username": "taken", "email": "taken"})
    with pytest.raises(IntegrityError) as caught, engine.begin() as connection:
        connection.execute(
            insert(users),
            {"username": "new", "email": "new", duplicate_column: "taken"},
        )

    assert is_unique_constraint_violation(
        caught.value,
        constraint_name="ix_users_username",
        sqlite_column_sets=(("users.username",),),
    ) is (duplicate_column == "username")
