from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateTable


@pytest.fixture(autouse=True)
def _run_from_src(monkeypatch, protected_test_config) -> None:
    monkeypatch.chdir(protected_test_config.src_dir)


def _create_schema(engine) -> None:
    import include.database.models  # noqa: F401
    from include.database.session import Base

    Base.metadata.create_all(engine)


def test_documents_and_folders_share_one_active_namespace() -> None:
    from include.database.models.documents import Document, Folder

    engine = create_engine("sqlite:///:memory:")
    _create_schema(engine)
    with Session(engine) as session:
        root = Folder(id="/", name="/")
        session.add_all(
            [
                root,
                Document(id="document", title="Report", folder=root),
                Folder(id="folder", name="Report", parent=root),
            ]
        )
        with pytest.raises(IntegrityError):
            session.commit()


def test_same_name_is_allowed_in_different_directories() -> None:
    from include.database.models.documents import Document, Folder

    engine = create_engine("sqlite:///:memory:")
    _create_schema(engine)
    with Session(engine) as session:
        root = Folder(id="/", name="/")
        first = Folder(id="first", name="First", parent=root)
        second = Folder(id="second", name="Second", parent=root)
        session.add_all(
            [
                root,
                first,
                second,
                Document(id="first-report", title="Report", folder=first),
                Document(id="second-report", title="Report", folder=second),
            ]
        )
        session.commit()


def test_deleted_nodes_release_names_but_locked_nodes_do_not() -> None:
    from include.database.models.documents import (
        Document,
        EntityStatus,
        Folder,
    )

    engine = create_engine("sqlite:///:memory:")
    _create_schema(engine)
    with Session(engine) as session:
        root = Folder(id="/", name="/")
        deleted_document = Document(
            id="deleted-document",
            title="Report",
            folder=root,
            status=EntityStatus.DELETED,
        )
        deleted_folder = Folder(
            id="deleted-folder",
            name="Report",
            parent=root,
            status=EntityStatus.DELETED,
        )
        session.add_all([root, deleted_document, deleted_folder])
        session.commit()

        deleted_document.status = EntityStatus.OK
        session.commit()
        deleted_folder.status = EntityStatus.LOCKED
        with pytest.raises(IntegrityError):
            session.commit()


def test_only_root_may_have_no_parent() -> None:
    from sqlalchemy import insert

    from include.database.models.documents import Folder, Node

    engine = create_engine("sqlite:///:memory:")
    _create_schema(engine)
    with Session(engine) as session:
        session.add(Folder(id="/", name="/"))
        session.commit()
        with pytest.raises(IntegrityError, match="ck_nodes_root_parent"):
            session.execute(
                insert(Node.__table__).values(
                    id="orphan",
                    type="node",
                    name="Orphan",
                    parent_id=None,
                    inherit=True,
                    status=0,
                )
            )


def test_concurrent_creates_have_one_winner(tmp_path) -> None:
    from include.database.models.documents import Folder

    engine = create_engine(
        f"sqlite:///{tmp_path / 'node-names.db'}",
        connect_args={"timeout": 10},
    )
    _create_schema(engine)
    with Session(engine) as session:
        session.add(Folder(id="/", name="/"))
        session.commit()

    barrier = Barrier(2)

    def create_sibling(index: int) -> bool:
        with Session(engine) as session:
            root = session.get(Folder, "/")
            session.add(Folder(id=f"folder-{index}", name="Concurrent", parent=root))
            barrier.wait()
            try:
                session.commit()
            except IntegrityError:
                session.rollback()
                return False
            return True

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(create_sibling, range(2)))

    assert sorted(results) == [False, True]


@pytest.mark.parametrize("dialect_name", ["sqlite", "mysql", "postgresql"])
def test_node_namespace_ddl_is_portable(dialect_name: str) -> None:
    from sqlalchemy.dialects import mysql, postgresql, sqlite

    from include.database.models.documents import Node

    dialects = {
        "sqlite": sqlite.dialect(),
        "mysql": mysql.dialect(),
        "postgresql": postgresql.dialect(),
    }
    ddl = str(CreateTable(Node.__table__).compile(dialect=dialects[dialect_name]))

    assert "GENERATED ALWAYS AS" in ddl
    assert "uq_nodes_active_parent_name" in ddl
    assert "ck_nodes_root_parent" in ddl
