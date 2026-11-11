from types import SimpleNamespace

import pytest
from sqlalchemy import event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


class _OriginalError(Exception):
    pass


def _integrity_error(original: Exception) -> IntegrityError:
    return IntegrityError("INSERT INTO nodes", {}, original)


@pytest.mark.unit
@pytest.mark.parametrize(
    ("columns", "expected"),
    [
        ("nodes.parent_id, nodes.active_name", True),
        ("nodes.active_parent_id, nodes.name", True),
        ("nodes.id", False),
        ("nodes.parent_id, nodes.name", False),
    ],
)
def test_node_name_conflict_matches_current_and_legacy_columns(
    columns, expected
) -> None:
    from include.domains.documents.commands.name_conflicts import (
        is_node_name_conflict,
    )

    original = _OriginalError(f"UNIQUE constraint failed: {columns}")
    original.sqlite_errorname = "SQLITE_CONSTRAINT_UNIQUE"

    assert is_node_name_conflict(_integrity_error(original)) is expected


@pytest.mark.unit
@pytest.mark.parametrize(
    ("code", "constraint", "expected"),
    [
        ("23505", "uq_nodes_active_parent_name", True),
        ("23505", "other_constraint", False),
        ("23503", "uq_nodes_active_parent_name", False),
    ],
)
def test_node_name_conflict_matches_only_its_named_constraint(
    code, constraint, expected
):
    from include.domains.documents.commands.name_conflicts import is_node_name_conflict

    original = SimpleNamespace(
        pgcode=code, diag=SimpleNamespace(constraint_name=constraint)
    )

    assert is_node_name_conflict(_integrity_error(original)) is expected


@pytest.mark.unit
def test_unrelated_integrity_error_is_not_a_name_conflict() -> None:
    from include.domains.documents.commands.name_conflicts import (
        is_node_name_conflict,
    )

    original = _OriginalError("FOREIGN KEY constraint failed")
    original.sqlite_errorname = "SQLITE_CONSTRAINT_FOREIGNKEY"

    assert not is_node_name_conflict(_integrity_error(original))


@pytest.mark.unit
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
        "UNIQUE constraint failed: nodes.parent_id, nodes.active_name"
    )
    original.sqlite_errorname = "SQLITE_CONSTRAINT_UNIQUE"

    error = _integrity_error(original)
    with (
        pytest.raises(NodeNameConflictError) as caught,
        node_name_mutation(session, "parent", "report"),
    ):
        raise error

    assert session.rollback_calls == 1
    assert caught.value.parent_id == "parent"
    assert caught.value.name == "report"
    assert caught.value.__cause__ is error


@pytest.mark.unit
@pytest.mark.parametrize(
    "message",
    [
        "NOT NULL constraint failed",
        "CHECK constraint failed: uq_nodes_active_parent_name",
    ],
)
def test_name_mutation_does_not_hide_other_integrity_errors(message) -> None:
    from include.domains.documents.commands.name_conflicts import node_name_mutation

    session = SimpleNamespace(rollback=lambda: None)
    error = _integrity_error(_OriginalError(message))

    with (
        pytest.raises(IntegrityError) as caught,
        node_name_mutation(session, "parent", "report"),
    ):
        raise error

    assert caught.value is error


@pytest.mark.component
@pytest.mark.parametrize("readable", [False, True])
def test_conflict_description_hides_unreadable_winner_id(
    monkeypatch, readable, sqlite_engine_factory
) -> None:
    import include.database.models  # noqa: F401
    from include.database.models.documents import Folder
    from include.database.session import Base
    from include.domains.documents.commands import name_conflicts
    from include.domains.documents.commands.name_conflicts import (
        describe_node_name_conflict,
    )

    engine = sqlite_engine_factory(":memory:")
    Base.metadata.create_all(engine)
    monkeypatch.setattr(
        name_conflicts,
        "check_access_requirements",
        lambda session, target, user, access_type: readable,
    )
    with Session(engine) as session:
        root = Folder(id="/", name="/")
        winner = Folder(id="winner", name="Report", parent=root)
        session.add_all([root, winner])
        session.commit()

        payload, _ = describe_node_name_conflict(
            session, SimpleNamespace(), "/", "Report"
        )

    assert payload["type"] == "directory"
    assert payload["id"] == ("winner" if readable else None)
    assert ("duplicate_id" in payload) is readable
    assert ("entity" in payload) is readable


@pytest.mark.unit
def test_conflict_description_rejects_unsupported_node_before_access_check(
    monkeypatch,
) -> None:
    from include.database.models.documents import Node
    from include.domains.documents.commands import name_conflicts

    monkeypatch.setattr(
        name_conflicts,
        "check_access_requirements",
        lambda *_args: pytest.fail("access check received an unsupported node"),
    )
    winner = Node(id="winner", type="node", name="Report", parent_id="/")

    with pytest.raises(TypeError, match="Unsupported conflicting node type"):
        name_conflicts._describe_node_name_conflict_winner(
            SimpleNamespace(), winner, SimpleNamespace()
        )


@pytest.mark.component
def test_successful_name_mutation_does_not_prequery_sibling_names(
    sqlite_engine_factory,
) -> None:
    import include.database.models  # noqa: F401
    from include.database.models.documents import Folder
    from include.database.session import Base
    from include.domains.documents.commands.name_conflicts import node_name_mutation

    engine = sqlite_engine_factory(":memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as session:
        root = Folder(id="/", name="/")
        session.add(root)
        session.commit()

        statements = []

        def collect_statement(_conn, _cursor, statement, *_args) -> None:
            statements.append(statement)

        event.listen(engine, "before_cursor_execute", collect_statement)
        try:
            with node_name_mutation(session, "/", "Report"):
                session.add(Folder(id="created", name="Report", parent_id="/"))
                session.commit()
        finally:
            event.remove(engine, "before_cursor_execute", collect_statement)

    assert not [
        statement
        for statement in statements
        if statement.lstrip().upper().startswith("SELECT") and "nodes.name" in statement
    ]


@pytest.mark.component
def test_subtree_restore_conflict_reports_descendant_winner(
    monkeypatch, sqlite_engine_factory
) -> None:
    import include.database.models  # noqa: F401
    from include.database.models.documents import EntityStatus, Folder
    from include.database.session import Base
    from include.domains.documents.commands import name_conflicts
    from include.domains.documents.commands.name_conflicts import (
        describe_subtree_restore_name_conflict,
    )

    engine = sqlite_engine_factory(":memory:")
    Base.metadata.create_all(engine)
    monkeypatch.setattr(
        name_conflicts,
        "check_access_requirements",
        lambda session, target, user, access_type: True,
    )
    with Session(engine) as session:
        root = Folder(id="/", name="/")
        parent = Folder(id="parent", name="Parent", parent=root)
        deleted = Folder(
            id="deleted",
            name="Conflict",
            parent=parent,
            status=EntityStatus.DELETED,
            status_operation_id="restore-op",
        )
        winner = Folder(id="winner", name="Conflict", parent=parent)
        session.add_all([root, parent, deleted, winner])
        session.commit()

        payload, _ = describe_subtree_restore_name_conflict(
            session,
            SimpleNamespace(),
            "restore-op",
            "/",
            "unrelated-root-name",
        )

    assert payload["duplicate_id"] == "winner"


@pytest.mark.unit
@pytest.mark.parametrize("duplicate_id", [None, "winner"])
def test_conflict_response_hides_entity_and_propagates_visible_winner(
    duplicate_id,
) -> None:
    from include.domains.documents.handlers.name_conflict_responses import (
        respond_to_node_name_conflict,
    )

    responses = []
    handler = SimpleNamespace(
        user_id="requester",
        conclude_request=lambda *args: responses.append(args),
    )
    entity = object()
    payload = {"type": "directory", "id": duplicate_id, "entity": entity}
    if duplicate_id is not None:
        payload["duplicate_id"] = duplicate_id
    result_data = {"title": "Report"}

    result = respond_to_node_name_conflict(
        handler,
        payload,
        "Name conflict",
        target="parent",
        result_data=result_data,
    )

    assert [response[:-1] for response in responses] == [(409, payload)]
    assert "entity" not in payload
    assert result.code == 409
    assert result.target == "parent"
    assert result.user_id == "requester"
    assert result.data == {
        "title": "Report",
        **({"duplicate_id": duplicate_id} if duplicate_id is not None else {}),
    }
    assert result_data == {"title": "Report"}
