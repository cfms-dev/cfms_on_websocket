import os
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[3]

pytestmark = pytest.mark.skipif(
    "CFMS_TEST_MYSQL_URL" not in os.environ,
    reason="CFMS_TEST_MYSQL_URL is required for MySQL upload cleanup tests",
)


@pytest.mark.integration
def test_abandoned_upload_cleanup_runs_on_mysql(monkeypatch, request):
    from include.database import models
    from include.database.models import files as file_models
    from include.database.session import Base
    from include.domains.documents.commands import upload_cleanup

    engine = create_engine(os.environ["CFMS_TEST_MYSQL_URL"])
    request.addfinalizer(engine.dispose)
    _clear_mysql_database(engine)
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

    try:
        with session_factory.begin() as session:
            root = models.Folder(id="/", name="/", inherit=False)
            document = models.Document(id="document", title="reserved", folder=root)
            file = models.File(id="file", path="pending-file")
            revision = models.DocumentRevision(
                id="revision", document=document, file=file
            )
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

        result = upload_cleanup.reclaim_abandoned_uploads(now=3.0)

        assert result.matched_tasks == 1
        assert result.expired_tasks == 1
        assert result.removed_documents == 1
        assert removed_paths == ["pending-file"]
        with session_factory() as session:
            assert session.get(models.FileTask, "task") is None
    finally:
        _clear_mysql_database(engine)


def _clear_mysql_database(engine) -> None:
    with engine.connect() as connection:
        connection.execute(text("SET FOREIGN_KEY_CHECKS=0"))
        for table_name in inspect(connection).get_table_names():
            quoted_name = connection.dialect.identifier_preparer.quote(table_name)
            connection.execute(text(f"DROP TABLE {quoted_name}"))
        connection.execute(text("SET FOREIGN_KEY_CHECKS=1"))
        connection.commit()
