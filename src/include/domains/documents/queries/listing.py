__all__ = [
    "attach_listing_effective_masks",
    "count_active_directory_children",
    "directory_cursor_key",
    "fetch_deleted_listing_items",
    "fetch_directory_listing_items",
]

from collections.abc import Mapping, Sequence
from typing import Any

from cacl_compiler import ObjectType
from sqlalchemy import and_, func, or_
from sqlalchemy.orm import Session

from include.database.models.documents import (
    Document,
    EntityStatus,
    Folder,
)
from include.database.models.identity import User
from include.domains.access.authorization.engine import ObjectState
from include.domains.access.authorization.evaluation import (
    DirectoryAccessResult,
    ListingMaskTarget,
    compute_listing_item_effective_masks,
)
from include.domains.documents.queries.active_revisions import (
    active_revision_exists_for,
    fetch_latest_active_revisions_by_document,
)

_CURSOR_KEY = "_cursor_key"
_NODE_INHERIT_KEY = "_node_inherit"


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
        Folder.inherit,
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
        Document.inherit,
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
    session: Session,
    folder_id: str,
    last_key: list[Any] | None,
    limit: int,
    *,
    include_inherit_meta: bool = False,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    folder_rows = _fetch_directory_rows(session, folder_id, last_key, limit)
    for row in folder_rows:
        item: dict[str, Any] = {
            "type": "directory",
            "id": row.id,
            "name": row.name,
            "created_time": row.created_time,
            _CURSOR_KEY: _directory_item_cursor_key(0, row.name_sort_key, row.id),
        }
        if include_inherit_meta:
            item[_NODE_INHERIT_KEY] = bool(row.inherit)
        items.append(item)

    remaining = limit - len(items)
    if remaining <= 0:
        return items

    document_rows = _fetch_document_rows(session, folder_id, last_key, remaining)
    latest_revisions_by_document = fetch_latest_active_revisions_by_document(
        session, [row.id for row in document_rows]
    )
    for row in document_rows:
        latest_revision = latest_revisions_by_document.get(row.id)
        if not latest_revision:
            continue
        item = {
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
        if include_inherit_meta:
            item[_NODE_INHERIT_KEY] = bool(row.inherit)
        items.append(item)
    return items


def fetch_deleted_listing_items(
    session: Session,
    folder_id: str,
    last_key: list[Any] | None,
    limit: int,
    *,
    include_inherit_meta: bool = False,
) -> list[dict[str, Any]]:
    items: list[dict[str, Any]] = []
    name_expression = func.lower(Folder.name)
    folder_rows = (
        session.query(
            Folder.id,
            Folder.name,
            Folder.created_time,
            Folder.status_operation_id,
            Folder.inherit,
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
        for row in rows:
            item: dict[str, Any] = {
                "type": "directory",
                "id": row.id,
                "name": row.name,
                "created_time": row.created_time,
                "status_operation_id": row.status_operation_id,
                _CURSOR_KEY: _directory_item_cursor_key(0, row.name_sort_key, row.id),
            }
            if include_inherit_meta:
                item[_NODE_INHERIT_KEY] = bool(row.inherit)
            items.append(item)

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
    for row in document_rows:
        item = {
            "type": "document",
            "id": row.id,
            "title": row.title,
            "name": row.title,
            "created_time": row.created_time,
            "status_operation_id": row.status_operation_id,
            _CURSOR_KEY: _directory_item_cursor_key(1, row.name_sort_key, row.id),
        }
        if include_inherit_meta:
            item[_NODE_INHERIT_KEY] = bool(row.inherit)
        items.append(item)
    return items


def attach_listing_effective_masks(
    session: Session,
    user: User,
    parent_access: DirectoryAccessResult,
    page_items: Sequence[dict[str, Any]],
    *,
    inherit_by_id: Mapping[str, bool],
    state: ObjectState,
    include_deleted: bool = False,
) -> None:
    """Attach projected effective_mask onto each already-sliced listing item in place."""
    if not page_items:
        return
    targets = [
        ListingMaskTarget(
            node_id=item["id"],
            object_type=(
                ObjectType.DIRECTORY
                if item["type"] == "directory"
                else ObjectType.DOCUMENT
            ),
            state=state,
            inherit=inherit_by_id.get(item["id"], True),
        )
        for item in page_items
    ]
    masks = compute_listing_item_effective_masks(
        session,
        user,
        parent_access,
        targets,
        include_deleted=include_deleted,
    )
    for item in page_items:
        item["effective_mask"] = masks[item["id"]]
