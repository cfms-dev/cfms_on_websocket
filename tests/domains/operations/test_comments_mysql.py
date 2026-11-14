from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from include.database.models.comments import Comment
from include.domains.operations.comments import (
    CommentDigestCollisionError,
    CommentStore,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def mysql_comment_sessions(isolated_metadata, mysql_pure_engine):
    tables = [isolated_metadata.tables[Comment.__tablename__]]
    isolated_metadata.drop_all(mysql_pure_engine, tables=tables, checkfirst=True)
    try:
        isolated_metadata.create_all(mysql_pure_engine, tables=tables)
        yield sessionmaker(bind=mysql_pure_engine)
    finally:
        isolated_metadata.drop_all(mysql_pure_engine, tables=tables, checkfirst=True)


def test_mysql_comment_store_creates_and_reuses_equal_comments(mysql_comment_sessions):
    with mysql_comment_sessions.begin() as session:
        first = CommentStore.get_or_create(
            session, "Routine maintenance", {"actor": "admin", "ticket": 42}
        )
        second = CommentStore.get_or_create(
            session, "Routine maintenance", {"ticket": 42, "actor": "admin"}
        )

        assert first.comment_id == second.comment_id
        comment_id = first.comment_id

    with mysql_comment_sessions() as session:
        stored = list(session.scalars(select(Comment)))
        assert len(stored) == 1
        assert stored[0].comment_id == comment_id
        assert stored[0].comment_text == "Routine maintenance"
        assert stored[0].comment_data == {"actor": "admin", "ticket": 42}


def test_mysql_comment_store_rejects_digest_collisions(
    mysql_comment_sessions, monkeypatch
):
    monkeypatch.setattr(CommentStore, "_digest", lambda _serialized: b"\0" * 32)

    with mysql_comment_sessions.begin() as session:
        CommentStore.get_or_create_id(session, "First reason")

    with (
        mysql_comment_sessions.begin() as session,
        pytest.raises(CommentDigestCollisionError),
    ):
        CommentStore.get_or_create_id(session, "Second reason")

    with mysql_comment_sessions() as session:
        assert len(list(session.scalars(select(Comment)))) == 1


def test_mysql_comment_store_deduplicates_concurrent_transactions(
    mysql_comment_sessions,
):
    ready = Barrier(4, timeout=10)

    def store_comment(_index: int) -> int:
        with mysql_comment_sessions.begin() as session:
            ready.wait(timeout=10)
            return CommentStore.get_or_create_id(
                session,
                "Concurrent MySQL maintenance",
                {"ticket": 42},
            )

    with ThreadPoolExecutor(max_workers=4) as executor:
        ids = list(executor.map(store_comment, range(4)))

    assert len(set(ids)) == 1
    with mysql_comment_sessions() as session:
        stored = list(session.scalars(select(Comment)))
        assert len(stored) == 1
        assert stored[0].comment_id == ids[0]
