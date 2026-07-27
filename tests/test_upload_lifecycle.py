import shutil
import sys
from pathlib import Path
from types import SimpleNamespace

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def test_expired_initial_upload_removes_empty_document(monkeypatch, tmp_path):
    shutil.copy(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    (tmp_path / "init").write_text("", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    src_path = str(PROJECT_ROOT / "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)

    from include.database import models
    from include.database.models import files as file_models
    from include.database.session import Base, global_config
    from include.domains.documents import upload_lifecycle

    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)
    removed_paths = []
    fake_manager = SimpleNamespace(
        storage=SimpleNamespace(remove=lambda path: removed_paths.append(path))
    )
    monkeypatch.setattr(file_models, "ProviderManager", lambda: fake_manager)
    monkeypatch.setattr(upload_lifecycle, "Session", SessionLocal)
    monkeypatch.setattr(
        upload_lifecycle, "publish_cancelled_file_tasks", lambda _task_ids: None
    )

    with SessionLocal.begin() as session:
        root = models.Folder(id="/", name="/", inherit=False)
        document = models.Document(id="document", title="reserved", folder=root)
        file = models.File(id="file", path="pending-file")
        revision = models.DocumentRevision(id="revision", document=document, file=file)
        document.current_revision = revision
        task = models.FileTask(
            id="task",
            file=file,
            mode=models.TransferMode.UPLOAD,
            status=models.FileTaskStatus.PENDING,
            start_time=1.0,
            end_time=2.0,
        )
        session.add_all([root, document, file, revision, task])

    result = upload_lifecycle.expire_abandoned_uploads(now=3.0)

    assert result.expired_tasks == 1
    assert result.removed_documents == 1
    assert removed_paths == ["pending-file"]
    with SessionLocal() as session:
        assert (
            session.get(
                models.Document,
                "document",
                execution_options={"include_deleted": True},
            )
            is None
        )
        assert session.get(models.FileTask, "task") is None

    global_config.stop()
