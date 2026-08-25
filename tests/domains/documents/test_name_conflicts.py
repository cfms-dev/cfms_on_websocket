from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session


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
        _OriginalError("UNIQUE constraint failed: nodes.parent_id, nodes.active_name"),
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
        "UNIQUE constraint failed: nodes.parent_id, nodes.active_name"
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


@pytest.mark.parametrize("readable", [False, True])
def test_conflict_description_hides_unreadable_winner_id(monkeypatch, readable) -> None:
    import include.database.models  # noqa: F401
    from include.database.models.documents import Folder
    from include.database.session import Base
    from include.domains.documents.commands.name_conflicts import (
        describe_node_name_conflict,
    )
    from include.messages import Messages as smsg

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    monkeypatch.setattr(
        Folder,
        "check_access_requirements",
        lambda self, user, access_type: readable,
    )
    with Session(engine) as session:
        root = Folder(id="/", name="/")
        winner = Folder(id="winner", name="Report", parent=root)
        session.add_all([root, winner])
        session.commit()

        payload, message = describe_node_name_conflict(
            session, SimpleNamespace(), "/", "Report"
        )

    assert payload["type"] == "directory"
    assert payload["id"] == ("winner" if readable else None)
    assert ("duplicate_id" in payload) is readable
    assert ("entity" in payload) is readable
    assert message == smsg.DIRECTORY_NAME_DUPLICATE


def test_successful_name_mutation_does_not_prequery_sibling_names() -> None:
    import include.database.models  # noqa: F401
    from include.database.models.documents import Folder
    from include.database.session import Base
    from include.domains.documents.commands.name_conflicts import node_name_mutation

    engine = create_engine("sqlite:///:memory:")
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


def test_subtree_restore_conflict_reports_descendant_winner(monkeypatch) -> None:
    import include.database.models  # noqa: F401
    from include.database.models.documents import EntityStatus, Folder
    from include.database.session import Base
    from include.domains.documents.commands.name_conflicts import (
        describe_subtree_restore_name_conflict,
    )

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    monkeypatch.setattr(
        Folder,
        "check_access_requirements",
        lambda self, user, access_type: True,
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


@pytest.mark.parametrize("duplicate_id", [None, "winner"])
def test_conflict_response_hides_entity_and_propagates_visible_winner(
    duplicate_id,
) -> None:
    from include.domains.documents.handlers.name_conflict_responses import (
        respond_to_node_name_conflict,
    )

    responses = []
    handler = SimpleNamespace(
        username="requester",
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

    assert responses == [(409, payload, "Name conflict")]
    assert "entity" not in payload
    assert result.code == 409
    assert result.target == "parent"
    assert result.username == "requester"
    assert result.data == {
        "title": "Report",
        **({"duplicate_id": duplicate_id} if duplicate_id is not None else {}),
    }
    assert result_data == {"title": "Report"}
