"""File reference counts against disposable SQLite databases.

A minimal schema exercises reflected foreign keys and cache isolation. The
production schema verifies batch_count_other_revisions exclusions, references
from other domains, and parameter chunk boundaries.
"""

import sys
import warnings
from pathlib import Path
from typing import Any

import pytest
from sqlalchemy import (
    VARCHAR,
    Float,
    ForeignKey,
    Integer,
    Text,
    create_engine,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
)

# ---------------------------------------------------------------------------
# Keep production imports available when this module is run individually.
# ---------------------------------------------------------------------------
_src = str(Path(__file__).resolve().parents[3] / "src")
if _src not in sys.path:
    sys.path.insert(0, _src)

from include.config.constants import MAX_PARAM_SIZE, QUERY_CHUNK_SIZE
from include.database import models
from include.database.session import Base
from include.domains.documents.queries.file_references import (
    _clear_file_references_cache,
    count_file_references,
)
from include.domains.documents.queries.revisions import (
    batch_count_other_revisions,
)

# ========================== Mirror ORM models ==============================
# These replicate ONLY the FK structure relevant to file reference counting.
# Table/column names MUST match production so reflected metadata lines up.
# ==========================================================================


class _Base(DeclarativeBase):
    pass


class MFile(_Base):
    """Mirror of ``files`` table."""

    __tablename__ = "files"
    id: Mapped[str] = mapped_column(VARCHAR(255), primary_key=True)
    path: Mapped[str] = mapped_column(Text, nullable=False, default="/dev/null")
    created_time: Mapped[float] = mapped_column(Float, nullable=False, default=0.0)


class MDocument(_Base):
    """Mirror of ``documents`` table (minimal)."""

    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(VARCHAR(255), primary_key=True)


class MDocumentRevision(_Base):
    """Mirror of ``document_revisions`` table — FK to files WITHOUT cascade."""

    __tablename__ = "document_revisions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    document_id: Mapped[str] = mapped_column(
        VARCHAR(255), ForeignKey("documents.id"), nullable=False
    )
    file_id: Mapped[str] = mapped_column(ForeignKey("files.id"))


class MUser(_Base):
    """Mirror of ``users`` table — avatar_id FK to files WITHOUT cascade."""

    __tablename__ = "users"
    username: Mapped[str] = mapped_column(VARCHAR(64), primary_key=True)
    avatar_id: Mapped[str | None] = mapped_column(ForeignKey("files.id"), nullable=True)


class MFileTask(_Base):
    """Mirror of ``file_tasks`` table — FK to files WITH CASCADE.

    This table should be EXCLUDED from reference counting because its rows
    are auto-removed when the parent file is deleted.
    """

    __tablename__ = "file_tasks"
    id: Mapped[str] = mapped_column(VARCHAR(255), primary_key=True)
    file_id: Mapped[str] = mapped_column(
        VARCHAR(255), ForeignKey("files.id", ondelete="CASCADE"), nullable=False
    )


# =========================== Pytest fixtures ===============================


@pytest.fixture
def engine():
    """Create a fresh in-memory SQLite engine for each test."""
    _clear_file_references_cache()
    eng = create_engine("sqlite:///:memory:")
    try:
        _Base.metadata.create_all(eng)
        yield eng
    finally:
        eng.dispose()
        _clear_file_references_cache()


@pytest.fixture
def session(engine):
    """Provide a session bound to the in-memory engine."""
    with Session(engine) as sess:
        yield sess


# ======================== Helper: seed data ================================


def _seed(session: Session, *objects) -> None:
    """Add objects to the session, commit, then clear the reflection cache
    so ``count_file_references`` re-reflects the (now visible) schema."""
    session.add_all(objects)
    session.commit()
    _clear_file_references_cache()


def _file(fid: str) -> MFile:
    return MFile(id=fid, path=f"/tmp/{fid}", created_time=0.0)


def _doc(did: str) -> MDocument:
    return MDocument(id=did)


def _rev(doc_id: str, file_id: str) -> MDocumentRevision:
    return MDocumentRevision(document_id=doc_id, file_id=file_id)


def _user(name: str, avatar_id: str | None = None) -> MUser:
    return MUser(username=name, avatar_id=avatar_id)


def _task(tid: str, file_id: str) -> MFileTask:
    return MFileTask(id=tid, file_id=file_id)


# ============================== Tests =====================================
# ------------ count_file_references: basic counting -----------------------


class TestCountFileReferences:
    """Core tests for the count_file_references utility."""

    def test_empty_file_ids_returns_empty(self, session):
        """Passing an empty list should return {} immediately."""
        assert count_file_references(session, []) == {}

    def test_none_file_ids_counts_all(self, session):
        """Passing None should count references for every file in the DB."""
        _seed(session, _file("f1"), _doc("d1"), _rev("d1", "f1"))

        result = count_file_references(session, None)
        assert result["f1"] == 1

    def test_unreferenced_file_omitted(self, session):
        """A file with zero references should not appear in the result."""
        _seed(session, _file("f_orphan"))

        result = count_file_references(session, ["f_orphan"])
        assert "f_orphan" not in result

    def test_nonexistent_file_ids_returns_empty(self, session):
        """IDs that don't exist in any table should yield an empty result."""
        _seed(session, _file("f_real"), _doc("d1"), _rev("d1", "f_real"))

        result = count_file_references(session, ["missing1", "missing2"])
        assert result == {}

    def test_mix_of_existing_and_nonexistent_ids(self, session):
        """Only existing *referenced* IDs should appear in the result;
        non-existent IDs must be silently omitted."""
        _seed(
            session,
            _file("f_exists"),
            _doc("d1"),
            _rev("d1", "f_exists"),
            _file("f_no_refs"),
        )

        result = count_file_references(
            session, ["f_exists", "f_no_refs", "totally_missing"]
        )
        assert result == {"f_exists": 1}

    def test_single_revision_reference(self, session):
        """A file referenced by one DocumentRevision should have count=1."""
        _seed(session, _file("f1"), _doc("d1"), _rev("d1", "f1"))

        result = count_file_references(session, ["f1"])
        assert result["f1"] == 1

    def test_multiple_revision_references(self, session):
        """A file referenced by three revisions should have count=3."""
        _seed(
            session,
            _file("f1"),
            _doc("d1"),
            _doc("d2"),
            _doc("d3"),
            _rev("d1", "f1"),
            _rev("d2", "f1"),
            _rev("d3", "f1"),
        )

        result = count_file_references(session, ["f1"])
        assert result["f1"] == 3

    # ---------- Counting across multiple FK tables -------------------------

    def test_avatar_reference_counted(self, session):
        """User.avatar_id should be counted as an independent reference."""
        _seed(session, _file("f1"), _user("alice", avatar_id="f1"))

        result = count_file_references(session, ["f1"])
        assert result["f1"] == 1

    def test_cross_table_aggregation(self, session):
        """References from both document_revisions and users should sum up."""
        _seed(
            session,
            _file("f1"),
            _doc("d1"),
            _rev("d1", "f1"),
            _user("bob", avatar_id="f1"),
        )

        result = count_file_references(session, ["f1"])
        assert result["f1"] == 2  # 1 revision + 1 avatar

    # ---------- CASCADE FK exclusion (file_tasks) --------------------------

    def test_cascade_fk_excluded(self, session):
        """file_tasks (CASCADE FK) must NOT inflate the reference count."""
        _seed(session, _file("f1"), _task("t1", "f1"), _task("t2", "f1"))

        result = count_file_references(session, ["f1"])
        # file_tasks should be excluded → file has zero independent references
        assert result.get("f1", 0) == 0

    def test_cascade_fk_does_not_block_deletion(self, session):
        """A file with only CASCADE refs + 1 revision should have count=1,
        proving the tasks don't inflate the total."""
        _seed(
            session,
            _file("f1"),
            _doc("d1"),
            _rev("d1", "f1"),
            _task("t1", "f1"),
            _task("t2", "f1"),
            _task("t3", "f1"),
        )

        result = count_file_references(session, ["f1"])
        assert result["f1"] == 1  # Only the revision counts

    # ---------- Multiple file IDs in a single call -------------------------

    def test_multiple_files(self, session):
        """Counting multiple files in one call should return correct
        per-file totals."""
        _seed(
            session,
            _file("fa"),
            _file("fb"),
            _file("fc"),
            _doc("d1"),
            _doc("d2"),
            _rev("d1", "fa"),
            _rev("d1", "fb"),
            _rev("d2", "fb"),
            _user("alice", avatar_id="fc"),
        )

        result = count_file_references(session, ["fa", "fb", "fc"])
        assert result["fa"] == 1
        assert result["fb"] == 2
        assert result["fc"] == 1

    # ---------- QUERY_CHUNK_SIZE chunking ----------------------------------

    def test_chunking_correctness(self, session):
        """Verify correct totals when file_ids exceeds QUERY_CHUNK_SIZE.

        We create more files than QUERY_CHUNK_SIZE, each referenced once,
        and confirm every single one gets count=1.
        """
        n = QUERY_CHUNK_SIZE + 50  # spans 2 chunks

        objs: list[Any] = [_doc("d_bulk")]
        file_ids = []
        for i in range(n):
            fid = f"file_{i:04d}"
            file_ids.append(fid)
            objs.append(_file(fid))
            objs.append(_rev("d_bulk", fid))
        _seed(session, *objs)

        result = count_file_references(session, file_ids)
        assert len(result) == n
        for fid in file_ids:
            assert result[fid] == 1, (
                f"Expected count=1 for {fid}, got {result.get(fid)}"
            )

    # ---------- Cache isolation --------------------------------------------

    def test_cache_isolation_across_engines(self, tmp_path):
        first = create_engine(f"sqlite:///{tmp_path / 'first.db'}")
        second = create_engine(f"sqlite:///{tmp_path / 'second.db'}")
        _clear_file_references_cache()
        try:
            for engine in (first, second):
                _Base.metadata.create_all(engine)
                with engine.begin() as connection:
                    connection.exec_driver_sql(
                        "INSERT INTO files (id, path, created_time) VALUES ('f1', 'file', 0)"
                    )
                    connection.exec_driver_sql(
                        "INSERT INTO users (username, avatar_id) VALUES ('alice', 'f1')"
                    )
            with second.begin() as connection:
                connection.exec_driver_sql(
                    "CREATE TABLE extra_refs (id INTEGER PRIMARY KEY, "
                    "file_id VARCHAR(255) REFERENCES files(id))"
                )
                connection.exec_driver_sql(
                    "INSERT INTO extra_refs (id, file_id) VALUES (1, 'f1')"
                )

            with Session(first) as session:
                first_counts = count_file_references(session, ["f1"])
            with Session(second) as session:
                second_counts = count_file_references(session, ["f1"])

            assert first_counts == {"f1": 1}
            assert second_counts == {"f1": 2}
        finally:
            first.dispose()
            second.dispose()
            _clear_file_references_cache()

    def test_cache_reset_discovers_new_reference_tables(self, engine, session):
        _seed(session, _file("f1"), _user("alice", avatar_id="f1"))
        assert count_file_references(session, ["f1"]) == {"f1": 1}
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE extra_refs (id INTEGER PRIMARY KEY, "
                "file_id VARCHAR(255) REFERENCES files(id))"
            )
            connection.exec_driver_sql(
                "INSERT INTO extra_refs (id, file_id) VALUES (1, 'f1')"
            )

        _clear_file_references_cache()

        assert count_file_references(session, ["f1"]) == {"f1": 2}

    def test_unrelated_expression_index_does_not_warn(self, engine):
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE indexed_names (id INTEGER PRIMARY KEY, name TEXT)"
            )
            connection.exec_driver_sql(
                "CREATE INDEX ix_indexed_names_lower_name "
                "ON indexed_names (lower(name))"
            )

        _clear_file_references_cache()
        with warnings.catch_warnings(), Session(engine) as session:
            warnings.simplefilter("error")
            counts = count_file_references(session, ["missing"])

        assert counts == {}

    # ---------- Return type guarantees ------------------------------------

    def test_return_values_are_int(self, session):
        """All returned counts must be plain int, not SQLAlchemy numerics."""
        _seed(session, _file("f1"), _doc("d1"), _rev("d1", "f1"))

        result = count_file_references(session, ["f1"])
        for v in result.values():
            assert type(v) is int


@pytest.fixture
def production_reference_session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'production-references.db'}")
    try:
        Base.metadata.create_all(engine)
        _clear_file_references_cache()
        with Session(engine) as session:
            session.add(models.Folder(id="/", name="/", inherit=False))
            session.commit()
            yield session
    finally:
        engine.dispose()
        _clear_file_references_cache()


def _seed_other_references(session, file_ids, revisions, *, avatars=(), tasks=()):
    session.add_all(
        models.File(id=file_id, path=f"uploads/{file_id}", active=True)
        for file_id in file_ids
    )
    document_ids = {document_id for document_id, _file_id in revisions}
    session.add_all(
        models.Document(id=document_id, title=document_id, inherit=False)
        for document_id in document_ids
    )
    session.flush()
    session.add_all(
        models.DocumentRevision(document_id=document_id, file_id=file_id)
        for document_id, file_id in revisions
    )
    session.add_all(
        models.User(
            username=username, pass_hash="hash", created_time=0, avatar_id=file_id
        )
        for username, file_id in avatars
    )
    session.add_all(
        models.FileTask(
            id=task_id,
            file_id=file_id,
            mode=1,
            status=0,
            start_time=0,
            end_time=1000,
        )
        for task_id, file_id in tasks
    )
    session.commit()


class TestBatchCountOtherRevisions:
    def test_excluded_doc_does_not_block_deletion(self, production_reference_session):
        session = production_reference_session
        _seed_other_references(session, ["f1"], [("d_excluded", "f1")])

        result = batch_count_other_revisions(session, ["f1"], ["d_excluded"])

        assert result == {"f1": 0}

    def test_other_doc_blocks_deletion(self, production_reference_session):
        session = production_reference_session
        _seed_other_references(
            session, ["f1"], [("d_excluded", "f1"), ("d_other", "f1")]
        )

        result = batch_count_other_revisions(session, ["f1"], ["d_excluded"])

        assert result == {"f1": 1}

    def test_avatar_blocks_deletion(self, production_reference_session):
        session = production_reference_session
        _seed_other_references(
            session, ["f1"], [("d_excluded", "f1")], avatars=[("alice", "f1")]
        )

        result = batch_count_other_revisions(session, ["f1"], ["d_excluded"])

        assert result == {"f1": 1}

    def test_cascade_task_does_not_block(self, production_reference_session):
        session = production_reference_session
        _seed_other_references(
            session,
            ["f1"],
            [("d_excluded", "f1")],
            tasks=[("t1", "f1"), ("t2", "f1")],
        )

        result = batch_count_other_revisions(session, ["f1"], ["d_excluded"])

        assert result == {"f1": 0}

    def test_multi_chunk_file_ids(self, production_reference_session):
        session = production_reference_session
        count = QUERY_CHUNK_SIZE + 20
        deletable_ids = [f"del_{index:04d}" for index in range(count // 2)]
        kept_ids = [f"kept_{index:04d}" for index in range(count // 2, count)]
        file_ids = deletable_ids + kept_ids
        revisions = [("d_excluded", file_id) for file_id in file_ids]
        revisions.extend(("d_other", file_id) for file_id in kept_ids)
        _seed_other_references(session, file_ids, revisions)

        result = batch_count_other_revisions(session, file_ids, ["d_excluded"])

        assert result == {
            **dict.fromkeys(deletable_ids, 0),
            **dict.fromkeys(kept_ids, 1),
        }

    def test_multi_chunk_exclude_doc_ids(self, production_reference_session):
        session = production_reference_session
        count = MAX_PARAM_SIZE - QUERY_CHUNK_SIZE + 10
        document_ids = [f"d_excl_{index:04d}" for index in range(count)]
        _seed_other_references(
            session, ["f1"], [(document_id, "f1") for document_id in document_ids]
        )

        result = batch_count_other_revisions(session, ["f1"], document_ids)

        assert result == {"f1": 0}
