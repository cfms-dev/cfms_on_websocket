from types import SimpleNamespace

import pytest
from sqlalchemy.exc import IntegrityError


@pytest.fixture(autouse=True)
def _run_from_src(monkeypatch, protected_test_config) -> None:
    monkeypatch.chdir(protected_test_config.src_dir)


class _OriginalError(Exception):
    pass


def _integrity_error(original: Exception) -> IntegrityError:
    return IntegrityError("INSERT INTO nodes", {}, original)


@pytest.mark.parametrize(
    "original",
    [
        _OriginalError("UNIQUE constraint failed: nodes.active_parent_id, nodes.name"),
        _OriginalError("Duplicate entry for key 'uq_nodes_active_parent_name'"),
        SimpleNamespace(
            sqlstate="23505",
            diag=SimpleNamespace(constraint_name="uq_nodes_active_parent_name"),
        ),
    ],
)
def test_node_name_conflict_is_recognized_across_dialects(original) -> None:
    from include.domains.documents.commands.name_conflicts import (
        is_node_name_conflict,
    )

    if isinstance(original, _OriginalError) and "UNIQUE constraint" in str(original):
        original.sqlite_errorname = "SQLITE_CONSTRAINT_UNIQUE"
    if isinstance(original, _OriginalError) and "Duplicate entry" in str(original):
        original.args = (1062, str(original))

    assert is_node_name_conflict(_integrity_error(original))


def test_unrelated_integrity_error_is_not_a_name_conflict() -> None:
    from include.domains.documents.commands.name_conflicts import (
        is_node_name_conflict,
    )

    original = _OriginalError("FOREIGN KEY constraint failed")
    original.sqlite_errorname = "SQLITE_CONSTRAINT_FOREIGNKEY"

    assert not is_node_name_conflict(_integrity_error(original))


def test_name_mutation_rolls_back_and_translates_name_conflict() -> None:
    from include.domains.documents.commands.name_conflicts import (
        NodeNameConflictError,
        node_name_mutation,
    )

    session = SimpleNamespace(rollback_calls=0)

    def rollback() -> None:
        session.rollback_calls += 1

    session.rollback = rollback
    original = _OriginalError(
        "UNIQUE constraint failed: nodes.active_parent_id, nodes.name"
    )
    original.sqlite_errorname = "SQLITE_CONSTRAINT_UNIQUE"

    with pytest.raises(NodeNameConflictError) as caught:
        with node_name_mutation(session, "parent", "report"):
            raise _integrity_error(original)

    assert session.rollback_calls == 1
    assert caught.value.parent_id == "parent"
    assert caught.value.name == "report"


def test_name_mutation_does_not_hide_other_integrity_errors() -> None:
    from include.domains.documents.commands.name_conflicts import node_name_mutation

    session = SimpleNamespace(rollback=lambda: None)
    error = _integrity_error(_OriginalError("NOT NULL constraint failed"))

    with pytest.raises(IntegrityError) as caught:
        with node_name_mutation(session, "parent", "report"):
            raise error

    assert caught.value is error
