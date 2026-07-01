import importlib.util
import sys
import types
from pathlib import Path

import pytest
from sqlalchemy import VARCHAR, ForeignKey, Integer, Text, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

_src = str(Path(__file__).resolve().parent.parent / "src")
if _src not in sys.path:
    sys.path.insert(0, _src)


class _Base(DeclarativeBase):
    pass


class MFile(_Base):
    __tablename__ = "files"

    id: Mapped[str] = mapped_column(VARCHAR(255), primary_key=True)
    path: Mapped[str] = mapped_column(Text, nullable=False)


class MDocument(_Base):
    __tablename__ = "documents"

    id: Mapped[str] = mapped_column(VARCHAR(255), primary_key=True)
    current_revision_id: Mapped[str | None] = mapped_column(
        VARCHAR(64), ForeignKey("document_revisions.id"), nullable=True
    )


class MDocumentRevision(_Base):
    __tablename__ = "document_revisions"

    id: Mapped[str] = mapped_column(VARCHAR(64), primary_key=True)
    document_id: Mapped[str] = mapped_column(
        VARCHAR(255), ForeignKey("documents.id"), nullable=False
    )
    file_id: Mapped[str] = mapped_column(ForeignKey("files.id"))
    parent_revision_id: Mapped[str | None] = mapped_column(
        VARCHAR(64), ForeignKey("document_revisions.id"), nullable=True
    )


class MDocumentAccessRule(_Base):
    __tablename__ = "document_access_rules"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    document_id: Mapped[str] = mapped_column(ForeignKey("documents.id"), nullable=False)


class MFileTask(_Base):
    __tablename__ = "file_tasks"

    id: Mapped[str] = mapped_column(VARCHAR(255), primary_key=True)
    file_id: Mapped[str] = mapped_column(
        VARCHAR(255), ForeignKey("files.id", ondelete="CASCADE"), nullable=False
    )


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    _Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine)
    sess = factory()
    yield sess
    sess.close()
    engine.dispose()


@pytest.fixture()
def bulk_purge_module(monkeypatch):
    entity_module = types.ModuleType("include.database.models.documents")
    entity_module.Document = MDocument
    entity_module.DocumentAccessRule = MDocumentAccessRule
    entity_module.DocumentRevision = MDocumentRevision

    file_module = types.ModuleType("include.database.models.files")
    file_module.File = MFile
    file_module.FileTask = MFileTask
    file_module._queue_deferred_file_deletion = lambda session, path: (
        session.info.setdefault("queued_paths", []).append(path)
    )

    monkeypatch.setitem(sys.modules, "include.database.models.documents", entity_module)
    monkeypatch.setitem(sys.modules, "include.database.models.files", file_module)

    module_path = (
        Path(__file__).resolve().parent.parent
        / "src"
        / "include"
        / "domains"
        / "documents"
        / "commands"
        / "bulk_purge.py"
    )
    spec = importlib.util.spec_from_file_location("bulk_purge_under_test", module_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


def _seed_document_with_revision(
    session: Session, doc_id: str, rev_id: str, file_id: str
) -> None:
    session.add(MFile(id=file_id, path=f"/tmp/{file_id}"))
    session.add(MDocument(id=doc_id))
    session.flush()
    session.add(MDocumentRevision(id=rev_id, document_id=doc_id, file_id=file_id))
    session.flush()
    session.query(MDocument).filter(MDocument.id == doc_id).update(
        {MDocument.current_revision_id: rev_id}
    )


def test_purge_documents_bulk_deletes_revisions_before_files(
    session, bulk_purge_module, monkeypatch
):
    _seed_document_with_revision(session, "doc1", "rev1", "file1")
    session.add(MFileTask(id="task1", file_id="file1"))
    session.add(MDocumentAccessRule(document_id="doc1"))
    session.commit()

    monkeypatch.setattr(
        bulk_purge_module,
        "batch_count_other_revisions",
        lambda *_args: {"file1": 0},
    )

    bulk_purge_module.purge_documents_bulk(session, ["doc1"])
    session.commit()

    assert session.query(MDocument).count() == 0
    assert session.query(MDocumentRevision).count() == 0
    assert session.query(MDocumentAccessRule).count() == 0
    assert session.query(MFileTask).count() == 0
    assert session.query(MFile).count() == 0
    assert session.info["queued_paths"] == ["/tmp/file1"]


def test_purge_documents_bulk_keeps_shared_files(
    session, bulk_purge_module, monkeypatch
):
    session.add(MFile(id="shared", path="/tmp/shared"))
    session.add_all([MDocument(id="doc1"), MDocument(id="doc2")])
    session.flush()
    session.add_all(
        [
            MDocumentRevision(id="rev1", document_id="doc1", file_id="shared"),
            MDocumentRevision(id="rev2", document_id="doc2", file_id="shared"),
        ]
    )
    session.flush()
    session.query(MDocument).filter(MDocument.id == "doc1").update(
        {MDocument.current_revision_id: "rev1"}
    )
    session.query(MDocument).filter(MDocument.id == "doc2").update(
        {MDocument.current_revision_id: "rev2"}
    )
    session.commit()

    monkeypatch.setattr(
        bulk_purge_module,
        "batch_count_other_revisions",
        lambda *_args: {"shared": 1},
    )

    bulk_purge_module.purge_documents_bulk(session, ["doc1"])
    session.commit()

    assert session.get(MDocument, "doc1") is None
    assert session.get(MDocumentRevision, "rev1") is None
    assert session.get(MDocument, "doc2") is not None
    assert session.get(MDocumentRevision, "rev2") is not None
    assert session.get(MFile, "shared") is not None
    assert "queued_paths" not in session.info
