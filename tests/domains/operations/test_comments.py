from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateTable


@pytest.fixture(autouse=True)
def _run_from_src(monkeypatch, protected_test_config) -> None:
    monkeypatch.chdir(protected_test_config.src_dir)


def _make_session() -> Session:
    from include.database.models.comments import Comment
    from include.database.session import Base

    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine, tables=[Comment.__table__])
    return Session(engine)


def test_comment_store_reuses_equal_comments() -> None:
    from include.database.models.comments import Comment
    from include.domains.operations.comments import CommentStore

    with _make_session() as session:
        first = CommentStore.get_or_create(
            session, "Routine maintenance", {"actor": "admin", "ticket": 42}
        )
        second = CommentStore.get_or_create(
            session, "Routine maintenance", {"ticket": 42, "actor": "admin"}
        )

        assert first.comment_id == second.comment_id
        assert len(session.scalars(select(Comment)).all()) == 1


def test_comment_digest_is_stable_binary() -> None:
    from include.domains.operations.comments import CommentStore

    first = CommentStore._digest(
        CommentStore._serialize("Routine maintenance", {"actor": "admin", "ticket": 42})
    )
    second = CommentStore._digest(
        CommentStore._serialize("Routine maintenance", {"ticket": 42, "actor": "admin"})
    )

    assert first == bytes.fromhex(
        "b9c8c9161e6eeb241b2c4f3b6519a8b9bb7300fe00dbccbed10bcf215b4b37a2"
    )
    assert second == first


def test_comment_id_store_uses_one_statement_for_new_sqlite_comment() -> None:
    from include.domains.operations.comments import CommentStore

    with _make_session() as session:
        statements = []

        @event.listens_for(session.bind, "before_cursor_execute")
        def _record_statement(
            _connection,
            _cursor,
            statement,
            _parameters,
            _context,
            _executemany,
        ) -> None:
            statements.append(statement)

        comment_id = CommentStore.get_or_create_id(session, "New reason")

        assert comment_id == 1
        assert len(statements) == 1
        assert statements[0].lstrip().upper().startswith("INSERT")


def test_comment_id_store_uses_insert_and_validation_for_duplicate() -> None:
    from include.domains.operations.comments import CommentStore

    with _make_session() as session:
        first_id = CommentStore.get_or_create_id(session, "Repeated reason")
        statements = []

        @event.listens_for(session.bind, "before_cursor_execute")
        def _record_statement(
            _connection,
            _cursor,
            statement,
            _parameters,
            _context,
            _executemany,
        ) -> None:
            statements.append(statement)

        second_id = CommentStore.get_or_create_id(session, "Repeated reason")

        assert second_id == first_id
        assert len(statements) == 2
        assert statements[0].lstrip().upper().startswith("INSERT")
        assert statements[1].lstrip().upper().startswith("SELECT")
        assert "FOR UPDATE" not in statements[1].upper()


def test_comment_store_rejects_digest_collisions(monkeypatch) -> None:
    from include.database.models.comments import Comment
    from include.domains.operations.comments import (
        CommentDigestCollisionError,
        CommentStore,
    )

    monkeypatch.setattr(CommentStore, "_digest", lambda serialized: b"\0" * 32)

    with _make_session() as session:
        CommentStore.get_or_create_id(session, "First reason")

        with pytest.raises(CommentDigestCollisionError):
            CommentStore.get_or_create_id(session, "Second reason")

        assert len(session.scalars(select(Comment)).all()) == 1


def test_comment_content_digest_constraint_is_unique() -> None:
    from include.database.models.comments import Comment

    constraint = next(
        constraint
        for constraint in Comment.__table__.constraints
        if constraint.name == "uq_comments_content_digest"
    )

    assert list(constraint.columns.keys()) == ["digest_version", "content_digest"]


@pytest.mark.parametrize(
    ("dialect_name", "expected_clauses"),
    [
        (
            "sqlite",
            ("ON CONFLICT (digest_version, content_digest) DO NOTHING",),
        ),
        (
            "postgresql",
            (
                "ON CONFLICT (digest_version, content_digest) DO NOTHING",
                "RETURNING comments.comment_id",
            ),
        ),
        (
            "mysql",
            (
                "ON DUPLICATE KEY UPDATE",
                "last_insert_id(comments.comment_id)",
            ),
        ),
    ],
)
def test_comment_store_builds_supported_upserts(
    dialect_name: str,
    expected_clauses: tuple[str, ...],
) -> None:
    from sqlalchemy.dialects import mysql, postgresql, sqlite

    from include.domains.operations.comments import CommentStore

    dialects = {
        "sqlite": sqlite.dialect(),
        "postgresql": postgresql.dialect(),
        "mysql": mysql.dialect(),
    }
    statement = CommentStore._build_insert_statement(
        dialect_name,
        {
            "digest_version": 1,
            "content_digest": b"\0" * 32,
            "comment_text": "Reason",
            "comment_data": None,
        },
    )

    compiled = str(statement.compile(dialect=dialects[dialect_name]))
    for expected_clause in expected_clauses:
        assert expected_clause in compiled


@pytest.mark.parametrize(
    ("dialect_name", "expected_type"),
    [
        ("sqlite", "BLOB"),
        ("postgresql", "BYTEA"),
        ("mysql", "BINARY(32)"),
    ],
)
def test_comment_digest_uses_compact_binary_type(
    dialect_name: str,
    expected_type: str,
) -> None:
    from sqlalchemy.dialects import mysql, postgresql, sqlite

    from include.database.models.comments import Comment

    dialects = {
        "sqlite": sqlite.dialect(),
        "postgresql": postgresql.dialect(),
        "mysql": mysql.dialect(),
    }
    ddl = str(CreateTable(Comment.__table__).compile(dialect=dialects[dialect_name]))

    assert expected_type in ddl


def test_comment_store_deduplicates_concurrent_transactions(tmp_path) -> None:
    from include.database.models.comments import Comment
    from include.database.session import Base
    from include.domains.operations.comments import CommentStore

    engine = create_engine(
        f"sqlite:///{tmp_path / 'comments.db'}",
        connect_args={"timeout": 10},
    )
    Base.metadata.create_all(engine, tables=[Comment.__table__])
    barrier = Barrier(2)

    def store_comment() -> int:
        with Session(engine) as session:
            barrier.wait()
            comment_id = CommentStore.get_or_create_id(
                session,
                "Concurrent maintenance",
                {"ticket": 42},
            )
            session.commit()
            return comment_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        ids = list(executor.map(lambda _: store_comment(), range(2)))

    with Session(engine) as session:
        assert ids[0] == ids[1]
        assert len(session.scalars(select(Comment)).all()) == 1
