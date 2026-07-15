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


def test_comment_store_compares_candidates_after_hash_match(monkeypatch) -> None:
    from include.database.models.comments import Comment
    from include.domains.operations.comments import CommentStore

    monkeypatch.setattr(CommentStore, "_hash", lambda text, data: 1)

    with _make_session() as session:
        first = CommentStore.get_or_create(session, "First reason")
        second = CommentStore.get_or_create(session, "Second reason")

        assert first.comment_id != second.comment_id
        assert len(session.scalars(select(Comment)).all()) == 2


def test_comment_hash_index_is_not_unique() -> None:
    from include.database.models.comments import Comment

    index = next(
        index
        for index in Comment.__table__.indexes
        if index.name == "ix_comments_comment_hash"
    )

    assert index.unique is False
