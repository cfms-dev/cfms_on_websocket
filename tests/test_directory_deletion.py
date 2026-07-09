import sys
from pathlib import Path
from shutil import copyfile

from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

PROJECT_ROOT = Path(__file__).resolve().parents[1]


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
