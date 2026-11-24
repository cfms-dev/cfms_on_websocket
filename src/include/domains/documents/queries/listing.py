__all__ = [
    "count_active_directory_children",
    "directory_cursor_key",
    "fetch_deleted_listing_items",
    "fetch_directory_listing_items",
]

from typing import Any

from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from include.database.models.documents import (
    Document,
    EntityStatus,
    Folder,
)
from include.domains.documents.queries.active_revisions import (
    active_revision_exists_for,
    fetch_latest_active_revisions_by_document,
)

_CURSOR_KEY = "_cursor_key"


def directory_cursor_key(item: dict[str, Any]) -> list[Any]:
    if _CURSOR_KEY in item:
        return list(item[_CURSOR_KEY])
    type_rank = 0 if item["type"] == "directory" else 1
    return [type_rank, item["name"].lower(), item["id"]]


def _directory_item_cursor_key(
    type_rank: int, name_sort_key: str, item_id: str
) -> list[Any]:
    return [type_rank, name_sort_key, item_id]


def _name_id_after_filter(name_expression, id_column, last_name: str, last_id: str):
    return or_(
        name_expression > last_name,
        and_(name_expression == last_name, id_column > last_id),
    )


def count_active_directory_children(session: Session, folder_id: str) -> int:
    folder_count = (
        session.query(func.count(Folder.id))
        .filter(Folder.parent_id == folder_id, Folder.status == EntityStatus.OK)
        .scalar()
        or 0
    )
    document_count = (
        session.query(func.count(Document.id))
        .filter(
            Document.folder_id == folder_id,
            Document.status == EntityStatus.OK,
            active_revision_exists_for(Document.id),
        )
        .scalar()
        or 0
    )
    return int(folder_count) + int(document_count)


def _fetch_directory_rows(session: Session, folder_id: str, last_key, limit: int):
    if last_key is not None and last_key[0] > 0:
        return []

    name_expression = func.lower(Folder.name)
    query = session.query(
        Folder.id,
        Folder.name,
        Folder.created_time,
        name_expression.label("name_sort_key"),
    ).filter(Folder.parent_id == folder_id, Folder.status != EntityStatus.DELETED)
    if last_key is not None:
        _, last_name, last_id = last_key
        query = query.filter(
            _name_id_after_filter(name_expression, Folder.id, last_name, last_id)
        )

    return query.order_by(name_expression.asc(), Folder.id.asc()).limit(limit).all()


def _fetch_document_rows(
    session: Session,
    folder_id: str,
    last_key,
    limit: int,
    *,
    include_deleted: bool = False,
):
    if last_key is not None and last_key[0] > 1:
        return []

    name_expression = func.lower(Document.title)
    query = session.query(
        Document.id,
        Document.title,
        Document.created_time,
        Document.status_operation_id,
        name_expression.label("name_sort_key"),
    ).filter(Document.folder_id == folder_id)
    if include_deleted:
        query = query.execution_options(include_deleted=True).filter(
            Document.status == EntityStatus.DELETED
        )
    else:
        query = query.filter(
            Document.status != EntityStatus.DELETED,
            active_revision_exists_for(Document.id),
        )

    if last_key is not None and last_key[0] == 1:
        _, last_name, last_id = last_key
        query = query.filter(
            _name_id_after_filter(name_expression, Document.id, last_name, last_id)
        )

    return query.order_by(name_expression.asc(), Document.id.asc()).limit(limit).all()


def fetch_directory_listing_items(
    session: Session, folder_id: str, last_key: list[Any] | None, limit: int
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    folder_rows = _fetch_directory_rows(session, folder_id, last_key, limit)
    items.extend(
        {
            "type": "directory",
            "id": row.id,
            "name": row.name,
            "created_time": row.created_time,
            _CURSOR_KEY: _directory_item_cursor_key(0, row.name_sort_key, row.id),
        }
        for row in folder_rows
    )

    remaining = limit - len(items)
    if remaining <= 0:
        return items

    document_rows = _fetch_document_rows(session, folder_id, last_key, remaining)
    latest_revisions_by_document = fetch_latest_active_revisions_by_document(
        session, [row.id for row in document_rows]
    )
    items.extend(
        {
            "type": "document",
            "id": row.id,
            "title": row.title,
            "name": row.title,
            "created_time": row.created_time,
            "last_modified": latest_revision.created_time,
            "sha256": latest_revision.file.sha256,
            "size": latest_revision.file.size,
            _CURSOR_KEY: _directory_item_cursor_key(1, row.name_sort_key, row.id),
        }
        for row in document_rows
        if (latest_revision := latest_revisions_by_document.get(row.id))
    )
    return items


def fetch_deleted_listing_items(
    session: Session, folder_id: str, last_key: list[Any] | None, limit: int
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    name_expression = func.lower(Folder.name)
    folder_rows = (
        session.query(
            Folder.id,
            Folder.name,
            Folder.created_time,
            Folder.status_operation_id,
            name_expression.label("name_sort_key"),
        )
        .execution_options(include_deleted=True)
        .filter(Folder.parent_id == folder_id, Folder.status == EntityStatus.DELETED)
    )
    if last_key is not None and last_key[0] == 0:
        _, last_name, last_id = last_key
        folder_rows = folder_rows.filter(
            _name_id_after_filter(name_expression, Folder.id, last_name, last_id)
        )
    elif last_key is not None and last_key[0] > 0:
        folder_rows = None

    if folder_rows is not None:
        rows = (
            folder_rows.order_by(name_expression.asc(), Folder.id.asc())
            .limit(limit)
            .all()
        )
        items.extend(
            {
                "type": "directory",
                "id": row.id,
                "name": row.name,
                "created_time": row.created_time,
                "status_operation_id": row.status_operation_id,
                _CURSOR_KEY: _directory_item_cursor_key(0, row.name_sort_key, row.id),
            }
            for row in rows
        )

    remaining = limit - len(items)
    if remaining <= 0:
        return items

    document_rows = _fetch_document_rows(
        session,
        folder_id,
        last_key,
        remaining,
        include_deleted=True,
    )
    items.extend(
        {
            "type": "document",
            "id": row.id,
            "title": row.title,
            "name": row.title,
            "created_time": row.created_time,
            "status_operation_id": row.status_operation_id,
            _CURSOR_KEY: _directory_item_cursor_key(1, row.name_sort_key, row.id),
        }
        for row in document_rows
    )
    return items
