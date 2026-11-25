from pathlib import Path

import pytest
from sqlalchemy import text
from sqlalchemy.orm import sessionmaker

pytestmark = pytest.mark.component

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_mark_nodes_deleted_updates_node_table_for_joined_inheritance(
    sqlite_engine_factory,
):
    from include.database import models
    from include.database.session import Base
    from include.domains.documents.handlers.directories import _mark_nodes_deleted

    engine = sqlite_engine_factory(":memory:")

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


def test_deleting_revision_sets_document_and_child_revision_references_null(
    sqlite_engine_factory,
):
    from include.database import models
    from include.database.session import Base

    engine = sqlite_engine_factory(":memory:")

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


def test_document_task_cancellation_uses_remaining_file_reachability(
    sqlite_engine_factory,
):
    from include.database import models
    from include.database.session import Base
    from include.domains.documents.commands.file_tasks import (
        cancel_file_tasks_for_files,
    )
    from include.domains.documents.queries.file_references import (
        _clear_file_references_cache,
        find_unreachable_document_file_ids,
    )

    engine = sqlite_engine_factory(":memory:")

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


def test_fetch_subtree_guards_against_cycle_and_depth_limit(
    sqlite_engine_factory, monkeypatch
):
    from include.database import models
    from include.database.session import Base
    from include.domains.documents.queries import deletion_tree as deletion_tree_mod

    engine = sqlite_engine_factory(":memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal() as session:
        session.add(models.Folder(id="/", name="/", inherit=False))
        session.flush()
        f1 = models.Folder(id="cyc-1", name="c1", parent_id="/")
        session.add(f1)
        session.flush()
        f2 = models.Folder(id="cyc-2", name="c2", parent_id="cyc-1")
        session.add(f2)
        session.commit()

        # Introduce a corrupted cycle cyc-1 <-> cyc-2 directly in SQL.
        session.execute(text("UPDATE nodes SET parent_id = 'cyc-2' WHERE id = 'cyc-1'"))
        session.commit()

        with pytest.raises(RuntimeError, match="Cycle detected"):
            deletion_tree_mod.fetch_subtree_metadata_for_soft_delete(session, "cyc-1")

    with SessionLocal() as session:
        parent_id = "/"
        for idx in range(5):
            node = models.Folder(
                id=f"deep-sub-{idx}",
                name=f"d{idx}",
                parent_id=parent_id,
            )
            session.add(node)
            session.flush()
            parent_id = node.id
        session.commit()

        monkeypatch.setattr(deletion_tree_mod, "MAX_HIERARCHY_DEPTH", 2)
        with pytest.raises(RuntimeError, match="depth exceeded"):
            deletion_tree_mod.fetch_subtree_metadata_for_soft_delete(
                session, "deep-sub-0"
            )


def test_fetch_subtree_handles_locked_nodes_and_scoped_restore(sqlite_engine_factory):
    from include.database import models
    from include.database.session import Base
    from include.domains.documents.queries.deletion_tree import (
        fetch_subtree_metadata_for_restore,
        fetch_subtree_metadata_for_soft_delete,
    )

    engine = sqlite_engine_factory(":memory:")
    Base.metadata.create_all(engine)
    SessionLocal = sessionmaker(bind=engine)

    with SessionLocal.begin() as session:
        root = models.Folder(id="/", name="/", inherit=False)
        session.add(root)
        session.flush()
        parent = models.Folder(id="p-tree", name="Parent", parent=root)
        locked_dir = models.Folder(
            id="locked-sub",
            name="LockedSub",
            parent=parent,
            status=models.EntityStatus.LOCKED,
        )
        locked_doc = models.Document(
            id="locked-doc",
            title="LockedDoc",
            folder=locked_dir,
            status=models.EntityStatus.LOCKED,
        )
        del_root = models.Folder(
            id="del-root",
            name="DelRoot",
            parent=root,
            status=models.EntityStatus.DELETED,
            status_operation_id="op-batch",
        )
        del_sibling = models.Folder(
            id="del-sibling",
            name="DelSibling",
            parent=del_root,
            status=models.EntityStatus.DELETED,
            status_operation_id="op-batch",
        )
        del_target = models.Folder(
            id="del-target",
            name="DelTarget",
            parent=del_root,
            status=models.EntityStatus.DELETED,
            status_operation_id="op-batch",
        )
        del_child_dir = models.Folder(
            id="del-child-dir",
            name="DelChildDir",
            parent=del_target,
            status=models.EntityStatus.DELETED,
            status_operation_id="op-batch",
        )
        del_old_dir = models.Folder(
            id="del-old-dir",
            name="DelOldDir",
            parent=del_target,
            status=models.EntityStatus.DELETED,
            status_operation_id="op-older",
        )
        del_child_doc = models.Document(
            id="del-child-doc",
            title="DelChildDoc",
            folder=del_child_dir,
            status=models.EntityStatus.DELETED,
            status_operation_id="op-batch",
        )
        session.add_all(
            [
                parent,
                locked_dir,
                locked_doc,
                del_root,
                del_sibling,
                del_target,
                del_child_dir,
                del_old_dir,
                del_child_doc,
            ]
        )

    with SessionLocal() as session:
        sd_folders, sd_docs = fetch_subtree_metadata_for_soft_delete(session, "p-tree")
        assert [row.id for row in sd_folders] == ["locked-sub"]
        assert [row.id for row in sd_docs] == ["locked-doc"]

        rs_folders, rs_docs = fetch_subtree_metadata_for_restore(
            session, "del-target", "op-batch"
        )
        assert [row.id for row in rs_folders] == ["del-child-dir"]
        assert [row.id for row in rs_docs] == ["del-child-doc"]
