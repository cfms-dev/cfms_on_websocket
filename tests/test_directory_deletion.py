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
