from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session


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


def test_comment_digest_is_stable() -> None:
    from include.domains.operations.comments import CommentStore

    first = CommentStore._digest(
        "Routine maintenance", {"actor": "admin", "ticket": 42}
    )
    second = CommentStore._digest(
        "Routine maintenance", {"ticket": 42, "actor": "admin"}
    )

    assert first == "b9c8c9161e6eeb241b2c4f3b6519a8b9bb7300fe00dbccbed10bcf215b4b37a2"
    assert second == first


def test_comment_store_rejects_digest_collisions(monkeypatch) -> None:
    from include.database.models.comments import Comment
    from include.domains.operations.comments import (
        CommentDigestCollisionError,
        CommentStore,
    )

    monkeypatch.setattr(CommentStore, "_digest", lambda text, data: "0" * 64)

    with _make_session() as session:
        CommentStore.get_or_create(session, "First reason")

        with pytest.raises(CommentDigestCollisionError):
            CommentStore.get_or_create(session, "Second reason")

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
    ("dialect_name", "expected_clause"),
    [
        (
            "sqlite",
            "ON CONFLICT (digest_version, content_digest) DO NOTHING",
        ),
        (
            "postgresql",
            "ON CONFLICT (digest_version, content_digest) DO NOTHING",
        ),
        ("mysql", "ON DUPLICATE KEY UPDATE"),
    ],
)
def test_comment_store_builds_supported_upserts(
    dialect_name: str,
    expected_clause: str,
) -> None:
    from sqlalchemy.dialects import mysql, postgresql, sqlite

    from include.domains.operations.comments import CommentStore

    class StubSession:
        def __init__(self) -> None:
            dialect = type("Dialect", (), {"name": dialect_name})()
            self.bind = type("Bind", (), {"dialect": dialect})()
            self.statement = None

        def get_bind(self):
            return self.bind

        def execute(self, statement) -> None:
            self.statement = statement

    dialects = {
        "sqlite": sqlite.dialect(),
        "postgresql": postgresql.dialect(),
        "mysql": mysql.dialect(),
    }
    session = StubSession()
    CommentStore._insert_if_missing(
        session,
        {
            "digest_version": 1,
            "content_digest": "0" * 64,
            "comment_text": "Reason",
            "comment_data": None,
        },
    )

    compiled = str(session.statement.compile(dialect=dialects[dialect_name]))
    assert expected_clause in compiled


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
            comment = CommentStore.get_or_create(
                session,
                "Concurrent maintenance",
                {"ticket": 42},
            )
            session.commit()
            return comment.comment_id

    with ThreadPoolExecutor(max_workers=2) as executor:
        ids = list(executor.map(lambda _: store_comment(), range(2)))

    with Session(engine) as session:
        assert ids[0] == ids[1]
        assert len(session.scalars(select(Comment)).all()) == 1
