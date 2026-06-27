"""
Unit tests for centralized file reference counting.

Tests cover:
  - count_file_references(): reflected-FK based counting across multiple tables
  - CASCADE FK exclusion (file_tasks should not be counted)
  - QUERY_CHUNK_SIZE chunking correctness
  - The "total minus excluded" pattern used by _batch_count_other_revisions
  - Cache isolation across different engines

These tests are fully self-contained: they use an in-memory SQLite database
with mirror models that replicate the production FK structure, so they do NOT
require a running server or config.toml.

NOTE: seed data is *committed* (not merely flushed) before counting because
``count_file_references`` uses reflected Table objects from a separate
``MetaData`` instance.  Reflected-table queries may open a different
connection than the Session's ORM connection, so uncommitted data is
invisible to them.  In production this is not a problem because references
being counted were committed in earlier transactions.
"""

import sys
from itertools import batched
from pathlib import Path
from typing import Any, List, Optional

import pytest
from sqlalchemy import (
    VARCHAR,
    Float,
    ForeignKey,
    Integer,
    Text,
    create_engine,
    func,
)
from sqlalchemy.orm import (
    DeclarativeBase,
    Mapped,
    Session,
    mapped_column,
    sessionmaker,
)

# ---------------------------------------------------------------------------
# Make ``include`` importable without the full project config.
# file_references.py -> include.config.constants -> include.config.version (no config needed).
# ---------------------------------------------------------------------------
_src = str(Path(__file__).resolve().parent.parent / "src")
if _src not in sys.path:
    sys.path.insert(0, _src)

from include.config.constants import MAX_PARAM_SIZE, QUERY_CHUNK_SIZE  # noqa: E402
from include.domains.documents.queries.file_references import (  # noqa: E402
    _clear_file_references_cache,
    _get_file_references,
    count_file_references,
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
    avatar_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("files.id"), nullable=True
    )


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


@pytest.fixture()
def engine():
    """Create a fresh in-memory SQLite engine for each test."""
    _clear_file_references_cache()
    eng = create_engine("sqlite:///:memory:")
    _Base.metadata.create_all(eng)
    yield eng
    eng.dispose()
    _clear_file_references_cache()


@pytest.fixture()
def session(engine):
    """Provide a session bound to the in-memory engine."""
    factory = sessionmaker(bind=engine)
    sess = factory()
    yield sess
    sess.close()


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


def _user(name: str, avatar_id: Optional[str] = None) -> MUser:
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
        """Different engines (different URLs) should each get their own
        reflected FK list."""
        _clear_file_references_cache()

        db1 = tmp_path / "db1.sqlite"
        db2 = tmp_path / "db2.sqlite"
        eng1 = create_engine(f"sqlite:///{db1}")
        eng2 = create_engine(f"sqlite:///{db2}")
        _Base.metadata.create_all(eng1)
        _Base.metadata.create_all(eng2)

        refs1 = _get_file_references(eng1)
        refs2 = _get_file_references(eng2)

        # Both should have results and be independent objects.
        assert len(refs1) > 0
        assert len(refs2) > 0
        assert refs1 is not refs2

        eng1.dispose()
        eng2.dispose()
        _clear_file_references_cache()

    def test_cache_cleared(self):
        """_clear_file_references_cache should empty the cache."""
        _clear_file_references_cache()

        eng = create_engine("sqlite:///:memory:")
        _Base.metadata.create_all(eng)
        _get_file_references(eng)

        _clear_file_references_cache()
        from include.domains.documents.queries.file_references import _CACHED_REFS

        assert len(_CACHED_REFS) == 0

        eng.dispose()

    # ---------- Return type guarantees ------------------------------------

    def test_return_values_are_int(self, session):
        """All returned counts must be plain int, not SQLAlchemy numerics."""
        _seed(session, _file("f1"), _doc("d1"), _rev("d1", "f1"))

        result = count_file_references(session, ["f1"])
        for v in result.values():
            assert type(v) is int


# ========= _batch_count_other_revisions algorithm pattern =================
# The actual function lives in entity.py and has deep import dependencies
# (config, handler, etc.) so we test the ALGORITHM here: total_refs minus
# excluded_refs should yield the "other" reference count.
# =========================================================================


class TestBatchCountOtherRevisionsPattern:
    """Tests for the 'total minus excluded' pattern used by
    _batch_count_other_revisions."""

    @staticmethod
    def _count_other_refs(
        session: Session,
        file_ids: List[str],
        exclude_doc_ids: List[str],
    ) -> dict:
        """Local reimplementation of _batch_count_other_revisions's algorithm.

        Uses count_file_references for total, then subtracts the references
        from the excluded documents.
        """
        if not file_ids:
            return {}

        total_refs = count_file_references(session, file_ids)

        # Count references from excluded documents (DocumentRevision only).
        exclude_chunk_size = max(1, MAX_PARAM_SIZE - QUERY_CHUNK_SIZE)
        excluded_counts: dict = {}
        for f_chunk in batched(file_ids, QUERY_CHUNK_SIZE):
            for e_chunk in batched(exclude_doc_ids, exclude_chunk_size):
                rows = (
                    session.query(
                        MDocumentRevision.file_id,
                        func.count(MDocumentRevision.id),
                    )
                    .filter(MDocumentRevision.file_id.in_(list(f_chunk)))
                    .filter(MDocumentRevision.document_id.in_(list(e_chunk)))
                    .group_by(MDocumentRevision.file_id)
                    .all()
                )
                for file_id, count in rows:
                    excluded_counts[file_id] = excluded_counts.get(file_id, 0) + count

        result = {}
        for fid in file_ids:
            total = total_refs.get(fid, 0)
            excluded = excluded_counts.get(fid, 0)
            result[fid] = max(0, total - excluded)
        return result

    def test_excluded_doc_does_not_block_deletion(self, session):
        """A file referenced ONLY by an excluded document should have
        other_count=0, meaning it is safe to delete."""
        _seed(session, _file("f1"), _doc("d_excluded"), _rev("d_excluded", "f1"))

        result = self._count_other_refs(session, ["f1"], ["d_excluded"])
        assert result["f1"] == 0  # safe to delete

    def test_other_doc_blocks_deletion(self, session):
        """A file referenced by a non-excluded document should have
        other_count > 0, blocking deletion."""
        _seed(
            session,
            _file("f1"),
            _doc("d_excluded"),
            _doc("d_other"),
            _rev("d_excluded", "f1"),
            _rev("d_other", "f1"),
        )

        result = self._count_other_refs(session, ["f1"], ["d_excluded"])
        assert result["f1"] == 1  # d_other still references it

    def test_avatar_blocks_deletion(self, session):
        """A file used as User.avatar_id should block deletion even if
        all DocumentRevision references are excluded."""
        _seed(
            session,
            _file("f1"),
            _doc("d_excluded"),
            _rev("d_excluded", "f1"),
            _user("alice", avatar_id="f1"),
        )

        result = self._count_other_refs(session, ["f1"], ["d_excluded"])
        # total = 2 (1 revision + 1 avatar), excluded = 1 → other = 1
        assert result["f1"] == 1  # avatar blocks deletion

    def test_cascade_task_does_not_block(self, session):
        """file_tasks (CASCADE FK) should NOT block deletion, even if
        many tasks exist for the file."""
        _seed(
            session,
            _file("f1"),
            _doc("d_excluded"),
            _rev("d_excluded", "f1"),
            _task("t1", "f1"),
            _task("t2", "f1"),
        )

        result = self._count_other_refs(session, ["f1"], ["d_excluded"])
        # total = 1 (revision only, tasks excluded), excluded = 1 → other = 0
        assert result["f1"] == 0  # safe to delete

    def test_multi_chunk_file_ids(self, session):
        """Verify correct results when file_ids spans multiple chunks,
        with a mix of deletable and non-deletable files."""
        n = QUERY_CHUNK_SIZE + 20

        objs: list[Any] = [_doc("d_excluded"), _doc("d_other")]

        # First half: referenced only by excluded doc → should be deletable
        deletable_ids = [f"del_{i:04d}" for i in range(n // 2)]
        for fid in deletable_ids:
            objs.extend([_file(fid), _rev("d_excluded", fid)])

        # Second half: also referenced by d_other → should NOT be deletable
        kept_ids = [f"kept_{i:04d}" for i in range(n // 2, n)]
        for fid in kept_ids:
            objs.extend([_file(fid), _rev("d_excluded", fid), _rev("d_other", fid)])

        _seed(session, *objs)

        all_ids = deletable_ids + kept_ids
        result = self._count_other_refs(session, all_ids, ["d_excluded"])

        for fid in deletable_ids:
            assert result[fid] == 0, (
                f"{fid} should be deletable but count={result[fid]}"
            )
        for fid in kept_ids:
            assert result[fid] == 1, f"{fid} should be kept but count={result[fid]}"

    def test_multi_chunk_exclude_doc_ids(self, session):
        """Verify correct results when exclude_doc_ids exceeds the
        exclude chunk size (MAX_PARAM_SIZE - QUERY_CHUNK_SIZE)."""
        exclude_chunk = MAX_PARAM_SIZE - QUERY_CHUNK_SIZE
        n_docs = exclude_chunk + 10  # force at least 2 chunks

        objs: list[Any] = [_file("f1")]
        doc_ids = []
        for i in range(n_docs):
            did = f"d_excl_{i:04d}"
            doc_ids.append(did)
            objs.extend([_doc(did), _rev(did, "f1")])
        _seed(session, *objs)

        result = self._count_other_refs(session, ["f1"], doc_ids)
        # All references are from excluded docs → safe to delete
        assert result["f1"] == 0
