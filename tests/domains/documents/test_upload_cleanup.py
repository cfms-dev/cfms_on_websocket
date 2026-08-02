import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[3]


@pytest.fixture
def upload_cleanup_context(monkeypatch, tmp_path):
    shutil.copy(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    (tmp_path / "init").write_text("", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    src_path = str(PROJECT_ROOT / "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)

    from include.database import models
    from include.database.models import files as file_models
    from include.database.session import Base, global_config
    from include.domains.documents.commands import upload_cleanup

    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    session_factory = sessionmaker(bind=engine)
    removed_paths = []
    fake_manager = SimpleNamespace(
        storage=SimpleNamespace(remove=lambda path: removed_paths.append(path))
    )
    monkeypatch.setattr(file_models, "ProviderManager", lambda: fake_manager)
    monkeypatch.setattr(upload_cleanup, "Session", session_factory)
    monkeypatch.setattr(
        upload_cleanup, "publish_cancelled_file_tasks", lambda _task_ids: None
    )

    yield SimpleNamespace(
        cleanup=upload_cleanup,
        models=models,
        removed_paths=removed_paths,
        session=session_factory,
    )

    global_config.stop()
    engine.dispose()


def _add_pending_document(context, *, status):
    models = context.models
    with context.session.begin() as session:
        root = models.Folder(id="/", name="/", inherit=False)
        document = models.Document(id="document", title="reserved", folder=root)
        file = models.File(id="file", path="pending-file")
        revision = models.DocumentRevision(id="revision", document=document, file=file)
        document.current_revision = revision
        task = models.FileTask(
            id="task",
            file=file,
            mode=models.TransferMode.UPLOAD,
            status=status,
            start_time=1.0,
            end_time=2.0,
        )
        session.add_all([root, document, file, revision, task])


@pytest.mark.parametrize("status_name", ["PENDING", "EXPIRED"])
def test_expired_initial_upload_removes_empty_document(
    upload_cleanup_context, status_name
):
    context = upload_cleanup_context
    status = getattr(context.models.FileTaskStatus, status_name)
    _add_pending_document(context, status=status)

    result = context.cleanup.reclaim_abandoned_uploads(
        now=3.0, folder_id="/", title="reserved"
    )

    assert result.matched_tasks == 1
    assert result.expired_tasks == (status_name == "PENDING")
    assert result.removed_documents == 1
    assert result.storage_cleanup_failures == 0
    assert context.removed_paths == ["pending-file"]
    with context.session() as session:
        assert (
            session.get(
                context.models.Document,
                "document",
                execution_options={"include_deleted": True},
            )
            is None
        )
        assert session.get(context.models.FileTask, "task") is None


def test_expired_later_upload_removes_only_inactive_revision(
    upload_cleanup_context,
):
    context = upload_cleanup_context
    models = context.models
    with context.session.begin() as session:
        root = models.Folder(id="/", name="/", inherit=False)
        document = models.Document(id="document", title="existing", folder=root)
        active_file = models.File(id="active-file", path="active", active=True)
        active_revision = models.DocumentRevision(
            id="active-revision", document=document, file=active_file
        )
        pending_file = models.File(id="pending-file", path="pending")
        pending_revision = models.DocumentRevision(
            id="pending-revision",
            document=document,
            file=pending_file,
            parent_revision=active_revision,
        )
        document.current_revision = pending_revision
        task = models.FileTask(
            id="task",
            file=pending_file,
            mode=models.TransferMode.UPLOAD,
            status=models.FileTaskStatus.EXPIRED,
            start_time=1.0,
            end_time=2.0,
        )
        session.add_all(
            [root, document, active_file, active_revision, pending_file, task]
        )

    result = context.cleanup.reclaim_abandoned_uploads(now=3.0, document_id="document")

    assert result.removed_documents == 0
    assert result.removed_revisions == 1
    assert context.removed_paths == ["pending"]
    with context.session() as session:
        document = session.get(models.Document, "document")
        assert document.current_revision_id == "active-revision"
        assert session.get(models.DocumentRevision, "pending-revision") is None
        assert session.get(models.File, "active-file") is not None
