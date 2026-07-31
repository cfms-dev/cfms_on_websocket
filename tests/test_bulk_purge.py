import importlib.util
import sys
import types
from pathlib import Path

import pytest
from sqlalchemy import VARCHAR, ForeignKey, Text, create_engine, event
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


class MFolder(_Base):
    __tablename__ = "folders"

    id: Mapped[str] = mapped_column(VARCHAR(255), primary_key=True)


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


class MCompiledAccessRuleSet(_Base):
    __tablename__ = "compiled_access_rule_sets"

    id: Mapped[str] = mapped_column(VARCHAR(32), primary_key=True)
    node_id: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)


class MFileTask(_Base):
    __tablename__ = "file_tasks"

    id: Mapped[str] = mapped_column(VARCHAR(255), primary_key=True)
    file_id: Mapped[str] = mapped_column(
        VARCHAR(255), ForeignKey("files.id", ondelete="CASCADE"), nullable=False
    )
    upload_session_id: Mapped[str | None] = mapped_column(Text, nullable=True)


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
    entity_module.DocumentRevision = MDocumentRevision
    entity_module.Folder = MFolder

    file_module = types.ModuleType("include.database.models.files")
    file_module.File = MFile
    file_module.FileTask = MFileTask

    def queue_deferred_file_deletion(session, path, upload_session_ids=()):
        session.info.setdefault("queued_files", []).append((path, upload_session_ids))

    file_module._queue_deferred_file_deletion = queue_deferred_file_deletion

    compiled_rules_module = types.ModuleType(
        "include.domains.access.authorization.compiled_rules"
    )

    def delete_compiled_access_rules_for_targets(session, targets):
        for target_type, target_id in targets:
            session.query(MCompiledAccessRuleSet).filter(
                MCompiledAccessRuleSet.node_id == target_id,
            ).delete(synchronize_session=False)

    compiled_rules_module.delete_compiled_access_rules_for_targets = (
        delete_compiled_access_rules_for_targets
    )

    monkeypatch.setitem(sys.modules, "include.database.models.documents", entity_module)
    monkeypatch.setitem(sys.modules, "include.database.models.files", file_module)
    monkeypatch.setitem(
        sys.modules,
        "include.domains.access.authorization.compiled_rules",
        compiled_rules_module,
    )

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
    session.add_all(
        [
            MFileTask(
                id="task1", file_id="file1", upload_session_id="upload-session-1"
            ),
            MFileTask(id="task2", file_id="file1", upload_session_id=None),
        ]
    )
    session.add(MCompiledAccessRuleSet(id="rule-set-doc1", node_id="doc1"))
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
    assert session.query(MCompiledAccessRuleSet).count() == 0
    assert session.query(MFileTask).count() == 0
    assert session.query(MFile).count() == 0
    assert session.info["queued_files"] == [("/tmp/file1", ("upload-session-1",))]


def test_purge_documents_bulk_keeps_shared_files(
    session, bulk_purge_module, monkeypatch
):
    session.add(MFile(id="shared", path="/tmp/shared"))
    session.add_all([MDocument(id="doc1"), MDocument(id="doc2")])
    session.flush()
    session.add(MCompiledAccessRuleSet(id="rule-set-doc1", node_id="doc1"))
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
    assert session.query(MCompiledAccessRuleSet).count() == 0
    assert session.get(MFile, "shared") is not None
    assert "queued_files" not in session.info
