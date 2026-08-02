import sys
from pathlib import Path
from shutil import copyfile

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _prepare_config(monkeypatch, tmp_path):
    copyfile(PROJECT_ROOT / "src" / "config.toml.sample", tmp_path / "config.toml")
    monkeypatch.chdir(tmp_path)

    src_path = str(PROJECT_ROOT / "src")
    if src_path not in sys.path:
        sys.path.insert(0, src_path)


def test_mark_nodes_deleted_updates_node_table_for_joined_inheritance(
    monkeypatch, tmp_path
):
    _prepare_config(monkeypatch, tmp_path)

    from include.database import models
    from include.database.session import Base, global_config
    from include.domains.documents.handlers.directories import _mark_nodes_deleted

    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as session:
        session.add(models.Folder(id="/", name="/", inherit=False))
        session.commit()
        folder = models.Folder(id="folder-1", name="folder")
        document = models.Document(id="document-1", title="document", folder=folder)
        session.add_all([folder, document])
        session.commit()

        _mark_nodes_deleted(session, [folder.id, document.id], "operation-1")
        session.commit()

        folder_node = session.get(
            models.Node, folder.id, execution_options={"include_deleted": True}
        )
        document_node = session.get(
            models.Node, document.id, execution_options={"include_deleted": True}
        )

        assert folder_node.status == models.EntityStatus.DELETED
        assert folder_node.status_operation_id == "operation-1"
        assert document_node.status == models.EntityStatus.DELETED
        assert document_node.status_operation_id == "operation-1"

    global_config.stop()


def test_deleting_revision_sets_document_and_child_revision_references_null(
    monkeypatch, tmp_path
):
    _prepare_config(monkeypatch, tmp_path)

    from include.database import models
    from include.database.session import Base, global_config

    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as session:
        session.add(models.Folder(id="/", name="/", inherit=False))
        session.commit()
        document = models.Document(id="document-1", title="document")
        first_file = models.File(id="file-1", path="/missing/file-1", active=True)
        second_file = models.File(id="file-2", path="/missing/file-2", active=True)
        session.add_all([document, first_file, second_file])
        session.flush()

        first_revision = models.DocumentRevision(
            id="revision-1",
            document=document,
            file=first_file,
        )
        second_revision = models.DocumentRevision(
            id="revision-2",
            document=document,
            file=second_file,
            parent_revision=first_revision,
        )
        session.add_all([first_revision, second_revision])
        session.flush()

        document.current_revision = first_revision
        session.commit()

        session.execute(
            models.DocumentRevision.__table__.delete().where(
                models.DocumentRevision.id == first_revision.id
            )
        )
        session.commit()

        session.expire_all()
        assert session.get(models.Document, document.id).current_revision_id is None
        assert (
            session.get(models.DocumentRevision, second_revision.id).parent_revision_id
            is None
        )

    global_config.stop()


def test_document_task_cancellation_uses_remaining_file_reachability(
    monkeypatch, tmp_path
):
    _prepare_config(monkeypatch, tmp_path)

    from include.database import models
    from include.database.session import Base, global_config
    from include.domains.documents.commands.file_tasks import (
        cancel_file_tasks_for_files,
    )
    from include.domains.documents.queries.file_references import (
        _clear_file_references_cache,
        find_unreachable_document_file_ids,
    )

    engine = create_engine("sqlite:///:memory:")

    @event.listens_for(engine, "connect")
    def _enable_sqlite_foreign_keys(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal.begin() as session:
        root = models.Folder(id="/", name="/", inherit=False)
        first = models.Document(id="document-1", title="first", folder=root)
        second = models.Document(id="document-2", title="second", folder=root)
        exclusive = models.File(id="exclusive", path="exclusive")
        shared = models.File(id="shared", path="shared", active=True)
        avatar = models.File(id="avatar", path="avatar", active=True)
        session.add_all([root, first, second, exclusive, shared, avatar])
        session.flush()
        session.add_all(
            [
                models.DocumentRevision(document=first, file=exclusive),
                models.DocumentRevision(document=first, file=shared),
                models.DocumentRevision(document=second, file=shared),
                models.DocumentRevision(document=first, file=avatar),
                models.User(
                    username="avatar-owner",
                    pass_hash="hash",
                    avatar=avatar,
                    created_time=0.0,
                ),
            ]
        )
        session.add_all(
            [
                models.FileTask(
                    id=f"task-{file_id}",
                    file_id=file_id,
                    mode=models.TransferMode.DOWNLOAD,
                    status=models.FileTaskStatus.PENDING,
                    start_time=0.0,
                    end_time=100.0,
                )
                for file_id in ("exclusive", "shared", "avatar")
            ]
        )

    _clear_file_references_cache()
    with SessionLocal.begin() as session:
        unreachable = find_unreachable_document_file_ids(session, ["document-1"])
        assert unreachable == {"exclusive"}
        assert cancel_file_tasks_for_files(session, unreachable) == ["task-exclusive"]

    with SessionLocal() as session:
        assert (
            session.get(models.FileTask, "task-exclusive").status
            == models.FileTaskStatus.CANCELLED
        )
        assert (
            session.get(models.FileTask, "task-shared").status
            == models.FileTaskStatus.PENDING
        )
        assert (
            session.get(models.FileTask, "task-avatar").status
            == models.FileTaskStatus.PENDING
        )

    _clear_file_references_cache()
    global_config.stop()
