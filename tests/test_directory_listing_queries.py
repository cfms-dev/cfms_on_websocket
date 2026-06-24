import os
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import joinedload, raiseload, sessionmaker


@pytest.fixture(scope="module")
def directory_models(protected_test_config):
    repo_root = Path(__file__).resolve().parents[1]
    src_path = repo_root / "src"
    if str(src_path) not in sys.path:
        sys.path.insert(0, str(src_path))

    original_cwd = Path.cwd()
    try:
        os.chdir(src_path)
        import include.database.models.blocking as blocking
        import include.database.models.keyring as keyring
        from include.database.handler import Base
        from include.database.models.entity import Document, DocumentRevision, Folder
        from include.database.models.file import File
        from include.handlers.directory import (
            _fetch_latest_active_revisions_by_document,
        )
    finally:
        os.chdir(original_cwd)

    _ = (blocking, keyring)

    return SimpleNamespace(
        Base=Base,
        Document=Document,
        DocumentRevision=DocumentRevision,
        File=File,
        Folder=Folder,
        fetch_latest_active_revisions=_fetch_latest_active_revisions_by_document,
    )


@pytest.fixture()
def directory_session(directory_models):
    engine = create_engine("sqlite:///:memory:")
    directory_models.Base.metadata.create_all(
        engine,
        tables=[
            directory_models.File.__table__,
            directory_models.Folder.__table__,
            directory_models.Document.__table__,
            directory_models.DocumentRevision.__table__,
        ],
    )
    SessionLocal = sessionmaker(bind=engine)
    with SessionLocal() as session:
        yield session


def _file(models, file_id: str, *, active: bool, size: int = 1):
    file = models.File(
        id=file_id,
        path=f"/tmp/{file_id}",
        sha256=file_id.rjust(64, "0")[-64:],
        active=active,
    )
    file.size = size
    return file


def _document(models, session, doc_id: str, folder_id: str):
    document = models.Document(id=doc_id, title=doc_id, folder_id=folder_id)
    session.add(document)
    session.flush()
    return document


def _revision(
    models,
    session,
    revision_id: str,
    document_id: str,
    file,
    *,
    created_time: float,
    parent_revision_id: str | None = None,
):
    session.add(file)
    revision = models.DocumentRevision(
        id=revision_id,
        document_id=document_id,
        file_id=file.id,
        created_time=created_time,
        parent_revision_id=parent_revision_id,
    )
    session.add(revision)
    session.flush()
    return revision


def test_document_active_does_not_load_all_revisions_when_current_is_active(
    directory_models,
    directory_session,
):
    folder = directory_models.Folder(id="folder", name="folder")
    directory_session.add(folder)
    document = _document(directory_models, directory_session, "doc", folder.id)
    revision = _revision(
        directory_models,
        directory_session,
        "current",
        document.id,
        _file(directory_models, "current-file", active=True),
        created_time=1,
    )
    _revision(
        directory_models,
        directory_session,
        "newer-history",
        document.id,
        _file(directory_models, "newer-history-file", active=True),
        created_time=2,
    )
    document.current_revision_id = revision.id
    directory_session.commit()

    loaded_document = (
        directory_session.query(directory_models.Document)
        .options(
            joinedload(directory_models.Document.current_revision).joinedload(
                directory_models.DocumentRevision.file
            ),
            raiseload(directory_models.Document.revisions),
        )
        .filter(directory_models.Document.id == document.id)
        .one()
    )

    assert loaded_document.active is True
    assert loaded_document.get_latest_revision().id == revision.id


def test_fetch_latest_active_revisions_batches_without_lazy_revision_loads(
    directory_models,
    directory_session,
):
    folder = directory_models.Folder(id="folder", name="folder")
    directory_session.add(folder)

    doc_current = _document(
        directory_models, directory_session, "doc-current", folder.id
    )
    current_revision = _revision(
        directory_models,
        directory_session,
        "rev-current",
        doc_current.id,
        _file(directory_models, "file-current", active=True, size=10),
        created_time=1,
    )
    _revision(
        directory_models,
        directory_session,
        "rev-current-newer-history",
        doc_current.id,
        _file(directory_models, "file-current-newer-history", active=True, size=20),
        created_time=2,
    )
    doc_current.current_revision_id = current_revision.id

    doc_parent = _document(directory_models, directory_session, "doc-parent", folder.id)
    parent_revision = _revision(
        directory_models,
        directory_session,
        "rev-parent-active",
        doc_parent.id,
        _file(directory_models, "file-parent-active", active=True, size=30),
        created_time=3,
    )
    inactive_child = _revision(
        directory_models,
        directory_session,
        "rev-parent-inactive-child",
        doc_parent.id,
        _file(directory_models, "file-parent-inactive-child", active=False, size=40),
        created_time=4,
        parent_revision_id=parent_revision.id,
    )
    doc_parent.current_revision_id = inactive_child.id

    doc_fallback = _document(
        directory_models, directory_session, "doc-fallback", folder.id
    )
    inactive_current = _revision(
        directory_models,
        directory_session,
        "rev-fallback-inactive",
        doc_fallback.id,
        _file(directory_models, "file-fallback-inactive", active=False, size=50),
        created_time=5,
    )
    fallback_revision = _revision(
        directory_models,
        directory_session,
        "rev-fallback-active",
        doc_fallback.id,
        _file(directory_models, "file-fallback-active", active=True, size=60),
        created_time=6,
    )
    doc_fallback.current_revision_id = inactive_current.id

    doc_without_current = _document(
        directory_models, directory_session, "doc-without-current", folder.id
    )
    _revision(
        directory_models,
        directory_session,
        "rev-without-current-old",
        doc_without_current.id,
        _file(directory_models, "file-without-current-old", active=True, size=70),
        created_time=7,
    )
    latest_without_current = _revision(
        directory_models,
        directory_session,
        "rev-without-current-new",
        doc_without_current.id,
        _file(directory_models, "file-without-current-new", active=True, size=80),
        created_time=8,
    )

    doc_inactive = _document(
        directory_models, directory_session, "doc-inactive", folder.id
    )
    inactive_only = _revision(
        directory_models,
        directory_session,
        "rev-inactive-only",
        doc_inactive.id,
        _file(directory_models, "file-inactive-only", active=False, size=90),
        created_time=9,
    )
    doc_inactive.current_revision_id = inactive_only.id
    directory_session.commit()

    documents = (
        directory_session.query(directory_models.Document)
        .options(raiseload("*"))
        .filter(directory_models.Document.folder_id == folder.id)
        .order_by(directory_models.Document.id)
        .all()
    )

    statements = []

    def count_statement(*args):
        statements.append(args)

    event.listen(directory_session.bind, "before_cursor_execute", count_statement)
    try:
        latest_by_document = directory_models.fetch_latest_active_revisions(
            directory_session, [document.id for document in documents]
        )
        payload = {
            document.id: latest_by_document[document.id].file.size
            for document in documents
            if document.id in latest_by_document
        }
    finally:
        event.remove(directory_session.bind, "before_cursor_execute", count_statement)

    assert latest_by_document[doc_current.id].id == current_revision.id
    assert latest_by_document[doc_parent.id].id == parent_revision.id
    assert latest_by_document[doc_fallback.id].id == fallback_revision.id
    assert latest_by_document[doc_without_current.id].id == latest_without_current.id
    assert doc_inactive.id not in latest_by_document
    assert payload == {
        doc_current.id: 10,
        doc_parent.id: 30,
        doc_fallback.id: 60,
        doc_without_current.id: 80,
    }
    assert len(statements) <= 3
