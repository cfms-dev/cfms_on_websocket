from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from sqlalchemy.schema import CreateIndex, CreateTable


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


@pytest.mark.parametrize(
    ("first_type", "second_type"),
    [
        ("document", "document"),
        ("directory", "directory"),
        ("document", "directory"),
    ],
)
def test_concurrent_creates_have_one_winner(tmp_path, first_type, second_type) -> None:
    from include.database.models.documents import Document, Folder

    engine = create_engine(
        f"sqlite:///{tmp_path / f'{first_type}-{second_type}.db'}",
        connect_args={"timeout": 10},
    )
    _create_schema(engine)
    with Session(engine) as session:
        session.add(Folder(id="/", name="/"))
        session.commit()

    barrier = Barrier(2)

    node_types = (first_type, second_type)

    def create_sibling(index: int) -> bool:
        with Session(engine) as session:
            root = session.get(Folder, "/")
            if node_types[index] == "directory":
                node = Folder(id=f"node-{index}", name="Concurrent", parent=root)
            else:
                node = Document(id=f"node-{index}", title="Concurrent", folder=root)
            session.add(node)
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


@pytest.mark.parametrize(
    ("statement", "index_name"),
    [
        (
            "SELECT id FROM nodes WHERE parent_id = '/' AND status = 0 "
            "ORDER BY lower(name), id",
            "ix_nodes_parent_status_lower_name_id",
        ),
        (
            "SELECT id FROM nodes WHERE status = 0 ORDER BY lower(name), id",
            "ix_nodes_status_lower_name_id",
        ),
    ],
)
def test_name_pagination_queries_use_node_indexes(statement, index_name) -> None:
    engine = create_engine("sqlite:///:memory:")
    _create_schema(engine)

    with engine.connect() as connection:
        plan = connection.exec_driver_sql(f"EXPLAIN QUERY PLAN {statement}").all()

    assert any(index_name in row[-1] for row in plan)


@pytest.mark.parametrize("dialect_name", ["sqlite", "mysql", "postgresql"])
def test_node_namespace_ddl_is_portable(dialect_name: str) -> None:
    from sqlalchemy.dialects import mysql, postgresql, sqlite

    from include.config.constants import ROOT_DIRECTORY_ID
    from include.database.models.documents import EntityStatus, Node

    dialects = {
        "sqlite": sqlite.dialect(),
        "mysql": mysql.dialect(),
        "postgresql": postgresql.dialect(),
    }
    ddl = str(CreateTable(Node.__table__).compile(dialect=dialects[dialect_name]))

    assert "GENERATED ALWAYS AS" in ddl
    assert "uq_nodes_active_parent_name" in ddl
    assert "ck_nodes_root_parent" in ddl
    assert repr(ROOT_DIRECTORY_ID) in ddl
    assert f"status = {EntityStatus.DELETED.value}" in ddl

    index_ddl = {
        index.name: str(CreateIndex(index).compile(dialect=dialects[dialect_name]))
        for index in Node.__table__.indexes
    }
    assert "ix_nodes_parent_status_lower_name_id" in index_ddl
    assert "ix_nodes_status_lower_name_id" in index_ddl
    if dialect_name == "mysql":
        assert "(lower(name))" in index_ddl["ix_nodes_parent_status_lower_name_id"]
        assert "(lower(name))" in index_ddl["ix_nodes_status_lower_name_id"]
