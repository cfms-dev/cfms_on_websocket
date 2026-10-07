"""Bulk purge against the production schema and reference queries."""

from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

from include.database import models
from include.database.session import Base
from include.domains.documents.commands import bulk_purge
from include.domains.documents.queries.file_references import (
    _clear_file_references_cache,
)


@pytest.fixture
def purge_context(monkeypatch, tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'bulk-purge.db'}")

    @event.listens_for(engine, "connect")
    def enable_foreign_keys(connection, _record):
        connection.execute("PRAGMA foreign_keys=ON")

    try:
        Base.metadata.create_all(engine)
        sessions = sessionmaker(bind=engine)
        queued = []

        def queue_file_deletion(session, path, upload_session_ids=()):
            queued.append((path, upload_session_ids))

        monkeypatch.setattr(
            bulk_purge, "_queue_deferred_file_deletion", queue_file_deletion
        )
        _clear_file_references_cache()
        with sessions.begin() as session:
            session.add(models.Folder(id="/", name="/", inherit=False))
        yield SimpleNamespace(sessions=sessions, queued=queued)
    finally:
        engine.dispose()
        _clear_file_references_cache()


def _seed_document_with_revision(
    session: Session,
    doc_id: str,
    rev_id: str,
    file_id: str,
):
    if session.get(models.File, file_id) is None:
        session.add(models.File(id=file_id, path=f"uploads/{file_id}", active=True))
        session.flush()
    document = models.Document(id=doc_id, title=doc_id, inherit=False)
    session.add(document)
    session.flush()
    revision = models.DocumentRevision(
        id=rev_id,
        document_id=doc_id,
        file_id=file_id,
    )
    session.add(revision)
    session.flush()
    document.current_revision_id = rev_id
    return document


def test_purge_documents_bulk_deletes_revisions_before_files(purge_context):
    with purge_context.sessions.begin() as session:
        document = _seed_document_with_revision(session, "doc1", "rev1", "file1")
        session.add_all(
            [
                models.FileTask(
                    id="task1",
                    file_id="file1",
                    mode=1,
                    status=0,
                    start_time=0,
                    end_time=1000,
                    upload_session_id="upload-session-1",
                ),
                models.FileTask(
                    id="task2",
                    file_id="file1",
                    mode=1,
                    status=0,
                    start_time=0,
                    end_time=1000,
                ),
            ]
        )
        document.access_rule_sets.append(
            models.CompiledAccessRuleSet(id="rule-set-doc1")
        )

    with purge_context.sessions.begin() as session:
        bulk_purge.purge_documents_bulk(session, ["doc1"])

    with purge_context.sessions() as session:
        assert session.get(models.Document, "doc1") is None
        assert session.get(models.Node, "doc1") is None
        assert session.scalars(select(models.DocumentRevision)).all() == []
        assert session.scalars(select(models.CompiledAccessRuleSet)).all() == []
        assert session.scalars(select(models.FileTask)).all() == []
        assert session.scalars(select(models.File)).all() == []
    assert purge_context.queued == [("uploads/file1", ("upload-session-1",))]


def test_purge_documents_bulk_keeps_shared_files(purge_context):
    with purge_context.sessions.begin() as session:
        document = _seed_document_with_revision(session, "doc1", "rev1", "shared")
        _seed_document_with_revision(session, "doc2", "rev2", "shared")
        document.access_rule_sets.append(
            models.CompiledAccessRuleSet(id="rule-set-doc1")
        )

    with purge_context.sessions.begin() as session:
        bulk_purge.purge_documents_bulk(session, ["doc1"])

    with purge_context.sessions() as session:
        assert session.get(models.Document, "doc1") is None
        assert session.get(models.Node, "doc1") is None
        assert session.get(models.DocumentRevision, "rev1") is None
        assert session.get(models.Document, "doc2") is not None
        assert session.get(models.Node, "doc2") is not None
        assert session.get(models.DocumentRevision, "rev2") is not None
        assert session.scalars(select(models.CompiledAccessRuleSet)).all() == []
        assert session.get(models.File, "shared") is not None
    assert purge_context.queued == []


def test_purge_documents_bulk_removes_empty_document_node(purge_context):
    with purge_context.sessions.begin() as session:
        session.add(models.Document(id="empty", title="Empty", inherit=False))

    with purge_context.sessions.begin() as session:
        bulk_purge.purge_documents_bulk(session, ["empty"])

    with purge_context.sessions() as session:
        assert session.get(models.Document, "empty") is None
        assert session.get(models.Node, "empty") is None
        assert session.get(models.Folder, "/") is not None
