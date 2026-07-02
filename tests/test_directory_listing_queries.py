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
        import include.database.models.access as blocking
        import include.database.models.keyrings as keyring
        from include.database.models.documents import (
            Document,
            DocumentRevision,
            EntityStatus,
            Folder,
        )
        from include.database.models.files import File
        from include.database.session import Base
        from include.domains.documents.queries.listing import (
            count_active_directory_children,
            directory_cursor_key,
            fetch_deleted_listing_items,
            fetch_directory_listing_items,
            fetch_latest_active_revisions_by_document,
            fetch_search_candidate_rows,
            search_cursor_key,
        )
    finally:
        os.chdir(original_cwd)

    _ = (blocking, keyring)

    return SimpleNamespace(
        Base=Base,
        Document=Document,
        DocumentRevision=DocumentRevision,
        EntityStatus=EntityStatus,
        File=File,
        Folder=Folder,
        count_active_directory_children=count_active_directory_children,
        directory_cursor_key=directory_cursor_key,
        fetch_deleted_listing_items=fetch_deleted_listing_items,
        fetch_latest_active_revisions=fetch_latest_active_revisions_by_document,
        fetch_directory_listing_items=fetch_directory_listing_items,
        fetch_search_candidate_rows=fetch_search_candidate_rows,
        search_cursor_key=search_cursor_key,
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


def _active_document(
    models,
    session,
    doc_id: str,
    *,
    title: str,
    created_time: float,
    revision_created_time: float,
    size: int = 1,
):
    document = models.Document(id=doc_id, title=title, created_time=created_time)
    session.add(document)
    session.flush()
    revision = _revision(
        models,
        session,
        f"{doc_id}-revision",
        document.id,
        _file(models, f"{doc_id}-file", active=True, size=size),
        created_time=revision_created_time,
    )
    document.current_revision_id = revision.id
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


def test_count_active_directory_children_uses_aggregate_queries(
    directory_models,
    directory_session,
):
    parent_id = "count-parent"
    parent = directory_models.Folder(id=parent_id, name="count-parent")
    directory_session.add(parent)
    directory_session.add_all(
        [
            directory_models.Folder(
                id="active-child",
                name="active-child",
                parent_id=parent_id,
                status=directory_models.EntityStatus.OK,
            ),
            directory_models.Folder(
                id="deleted-child",
                name="deleted-child",
                parent_id=parent_id,
                status=directory_models.EntityStatus.DELETED,
            ),
            directory_models.Folder(
                id="locked-child",
                name="locked-child",
                parent_id=parent_id,
                status=directory_models.EntityStatus.LOCKED,
            ),
            directory_models.Folder(
                id="grandchild",
                name="grandchild",
                parent_id="active-child",
                status=directory_models.EntityStatus.OK,
            ),
        ]
    )

    active_doc = _document(directory_models, directory_session, "active-doc", parent_id)
    active_revision = _revision(
        directory_models,
        directory_session,
        "active-doc-revision",
        active_doc.id,
        _file(directory_models, "active-doc-file", active=True),
        created_time=1,
    )
    active_doc.current_revision_id = active_revision.id

    deleted_doc = _document(
        directory_models, directory_session, "deleted-doc", parent_id
    )
    deleted_doc.status = directory_models.EntityStatus.DELETED
    deleted_revision = _revision(
        directory_models,
        directory_session,
        "deleted-doc-revision",
        deleted_doc.id,
        _file(directory_models, "deleted-doc-file", active=True),
        created_time=2,
    )
    deleted_doc.current_revision_id = deleted_revision.id

    locked_doc = _document(directory_models, directory_session, "locked-doc", parent_id)
    locked_doc.status = directory_models.EntityStatus.LOCKED
    locked_revision = _revision(
        directory_models,
        directory_session,
        "locked-doc-revision",
        locked_doc.id,
        _file(directory_models, "locked-doc-file", active=True),
        created_time=3,
    )
    locked_doc.current_revision_id = locked_revision.id

    inactive_doc = _document(
        directory_models, directory_session, "inactive-doc", parent_id
    )
    inactive_revision = _revision(
        directory_models,
        directory_session,
        "inactive-doc-revision",
        inactive_doc.id,
        _file(directory_models, "inactive-doc-file", active=False),
        created_time=4,
    )
    inactive_doc.current_revision_id = inactive_revision.id
    directory_session.commit()

    statements = []

    def collect_statement(_conn, _cursor, statement, *_args):
        statements.append(statement)

    event.listen(directory_session.bind, "before_cursor_execute", collect_statement)
    try:
        count = directory_models.count_active_directory_children(
            directory_session, parent_id
        )
    finally:
        event.remove(directory_session.bind, "before_cursor_execute", collect_statement)

    assert count == 2
    assert len(statements) == 2
    assert all("count" in statement.lower() for statement in statements)


def test_directory_listing_query_limits_candidates(
    directory_models,
    directory_session,
):
    parent = directory_models.Folder(id="parent", name="parent")
    directory_session.add(parent)
    for index in range(3):
        directory_session.add(
            directory_models.Folder(
                id=f"child-{index}",
                name=f"Child {index}",
                parent_id=parent.id,
            )
        )
    directory_session.commit()

    statements = []

    def collect_statement(_conn, _cursor, statement, *_args):
        statements.append(statement)

    event.listen(directory_session.bind, "before_cursor_execute", collect_statement)
    try:
        items = directory_models.fetch_directory_listing_items(
            directory_session, parent.id, None, 2
        )
    finally:
        event.remove(directory_session.bind, "before_cursor_execute", collect_statement)

    assert len(items) == 2
    folder_selects = [
        statement
        for statement in statements
        if "FROM folders" in statement
        and "parent_id" in statement
        and "ORDER BY lower" in statement
    ]
    assert folder_selects
    assert all("LIMIT" in statement.upper() for statement in folder_selects)

    second_page = directory_models.fetch_directory_listing_items(
        directory_session,
        parent.id,
        directory_models.directory_cursor_key(items[0]),
        1,
    )
    assert len(second_page) == 1
    assert second_page[0]["id"] != items[0]["id"]


def test_deleted_listing_query_limits_candidates(
    directory_models,
    directory_session,
):
    parent = directory_models.Folder(id="deleted-parent", name="deleted-parent")
    directory_session.add(parent)
    for index in range(3):
        directory_session.add(
            directory_models.Folder(
                id=f"deleted-child-{index}",
                name=f"Deleted Child {index}",
                parent_id=parent.id,
                status=directory_models.EntityStatus.DELETED,
            )
        )
    directory_session.commit()

    statements = []

    def collect_statement(_conn, _cursor, statement, *_args):
        statements.append(statement)

    event.listen(directory_session.bind, "before_cursor_execute", collect_statement)
    try:
        items = directory_models.fetch_deleted_listing_items(
            directory_session, parent.id, None, 2
        )
    finally:
        event.remove(directory_session.bind, "before_cursor_execute", collect_statement)

    assert len(items) == 2
    folder_selects = [
        statement
        for statement in statements
        if "FROM folders" in statement
        and "status" in statement
        and "ORDER BY lower" in statement
    ]
    assert folder_selects
    assert all("LIMIT" in statement.upper() for statement in folder_selects)

    second_page = directory_models.fetch_deleted_listing_items(
        directory_session,
        parent.id,
        directory_models.directory_cursor_key(items[0]),
        1,
    )
    assert len(second_page) == 1
    assert second_page[0]["id"] != items[0]["id"]


def test_search_candidate_query_limits_directory_candidates(
    directory_models,
    directory_session,
):
    for index in range(3):
        directory_session.add(
            directory_models.Folder(
                id=f"search-folder-{index}",
                name=f"Limited Search Folder {index}",
            )
        )
    directory_session.commit()

    statements = []

    def collect_statement(_conn, _cursor, statement, *_args):
        statements.append(statement)

    event.listen(directory_session.bind, "before_cursor_execute", collect_statement)
    try:
        rows = directory_models.fetch_search_candidate_rows(
            directory_session,
            query="Limited Search",
            sort_by="name",
            sort_order="asc",
            search_documents=False,
            search_directories=True,
            last_key=None,
            limit=2,
        )
    finally:
        event.remove(directory_session.bind, "before_cursor_execute", collect_statement)

    assert len(rows) == 2
    assert all(row["type"] == "directory" for row in rows)
    candidate_selects = [
        statement
        for statement in statements
        if "FROM folders" in statement and "lower" in statement.lower()
    ]
    assert candidate_selects
    assert all("LIMIT" in statement.upper() for statement in candidate_selects)


@pytest.mark.parametrize(
    ("sort_order", "expected_ids"),
    [
        (
            "asc",
            [
                "search-folder-old",
                "search-doc-mid",
                "search-folder-new",
                "search-doc-last",
            ],
        ),
        (
            "desc",
            [
                "search-doc-last",
                "search-folder-new",
                "search-doc-mid",
                "search-folder-old",
            ],
        ),
    ],
)
def test_search_last_modified_cursor_pages_mixed_candidates(
    directory_models,
    directory_session,
    sort_order,
    expected_ids,
):
    query = "LastModifiedCursor"
    directory_session.add_all(
        [
            directory_models.Folder(
                id="search-folder-old",
                name=f"{query} Folder Old",
                created_time=10,
            ),
            directory_models.Folder(
                id="search-folder-new",
                name=f"{query} Folder New",
                created_time=30,
            ),
        ]
    )
    _active_document(
        directory_models,
        directory_session,
        "search-doc-mid",
        title=f"{query} Document Mid",
        created_time=5,
        revision_created_time=20,
    )
    _active_document(
        directory_models,
        directory_session,
        "search-doc-last",
        title=f"{query} Document Last",
        created_time=5,
        revision_created_time=40,
    )
    directory_session.commit()

    last_key = None
    seen_ids = []
    while True:
        rows = directory_models.fetch_search_candidate_rows(
            directory_session,
            query=query,
            sort_by="last_modified",
            sort_order=sort_order,
            search_documents=True,
            search_directories=True,
            last_key=last_key,
            limit=1,
        )
        if not rows:
            break

        assert len(rows) == 1
        seen_ids.append(rows[0]["id"])
        last_key = directory_models.search_cursor_key(rows[0], "last_modified")

    assert seen_ids == expected_ids
    assert len(seen_ids) == len(set(seen_ids))


def test_search_name_cursor_uses_database_sort_key_for_unicode(
    directory_models,
    directory_session,
):
    query = "UnicodeCursor"
    for item_id, suffix in [
        ("unicode-folder-omega", "\u03a9"),
        ("unicode-folder-sigma", "\u03a3"),
        ("unicode-folder-dotted-i", "\u0130"),
        ("unicode-folder-sharp-s", "\u00df"),
        ("unicode-folder-z", "Z"),
        ("unicode-folder-i", "i"),
        ("unicode-folder-a-upper", "A"),
        ("unicode-folder-a-lower", "a"),
    ]:
        directory_session.add(
            directory_models.Folder(
                id=item_id,
                name=f"{query} {suffix}",
            )
        )
    directory_session.commit()

    last_key = None
    seen_ids = []
    while True:
        rows = directory_models.fetch_search_candidate_rows(
            directory_session,
            query=query,
            sort_by="name",
            sort_order="desc",
            search_documents=False,
            search_directories=True,
            last_key=last_key,
            limit=1,
        )
        if not rows:
            break

        assert len(rows) == 1
        seen_ids.append(rows[0]["id"])
        last_key = directory_models.search_cursor_key(rows[0], "name")

    assert seen_ids == [
        "unicode-folder-omega",
        "unicode-folder-sigma",
        "unicode-folder-dotted-i",
        "unicode-folder-sharp-s",
        "unicode-folder-z",
        "unicode-folder-i",
        "unicode-folder-a-lower",
        "unicode-folder-a-upper",
    ]
