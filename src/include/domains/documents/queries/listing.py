from __future__ import annotations

from collections.abc import Sequence
from functools import cmp_to_key
from itertools import batched
from typing import Any

from sqlalchemy import and_, exists, func, literal, or_, select, union_all
from sqlalchemy.orm import joinedload, raiseload

from include.config.constants import QUERY_CHUNK_SIZE
from include.database.models.documents import (
    Document,
    DocumentRevision,
    EntityStatus,
    Folder,
)
from include.database.models.files import File

_CURSOR_KEY = "_cursor_key"


def _lowered(value: str) -> str:
    return value.lower()


def directory_cursor_key(item: dict[str, Any]) -> list[Any]:
    if _CURSOR_KEY in item:
        return list(item[_CURSOR_KEY])
    type_rank = 0 if item["type"] == "directory" else 1
    return [type_rank, _lowered(item["name"]), item["id"]]


def search_cursor_key(item: dict[str, Any], sort_by: str) -> list[Any]:
    if _CURSOR_KEY in item:
        return list(item[_CURSOR_KEY])
    if sort_by == "name":
        primary = item.get("name_sort_key")
        if primary is None:
            primary = _lowered(item["name"])
    elif sort_by == "size":
        primary = item.get("size", 0) or 0
    elif sort_by == "last_modified":
        primary = item.get("last_modified")
        if primary is None:
            primary = item["created_time"]
    else:
        primary = item["created_time"]

    type_rank = 0 if item["type"] == "directory" else 1
    return [primary, type_rank, item["id"]]


def _directory_item_cursor_key(
    type_rank: int, name_sort_key: str, item_id: str
) -> list[Any]:
    return [type_rank, name_sort_key, item_id]


def _search_item_cursor_key(
    item: dict[str, Any],
    sort_by: str,
) -> list[Any]:
    if sort_by == "name":
        primary = item["name_sort_key"]
    elif sort_by == "size":
        primary = item.get("size", 0) or 0
    elif sort_by == "last_modified":
        primary = item.get("last_modified")
        if primary is None:
            primary = item["created_time"]
    else:
        primary = item["created_time"]

    return [primary, item["type_rank"], item["id"]]


def _name_id_after_filter(name_expression, id_column, last_name: str, last_id: str):
    return or_(
        name_expression > last_name,
        and_(name_expression == last_name, id_column > last_id),
    )


def _active_revision_exists():
    return exists(
        select(1)
        .select_from(DocumentRevision)
        .join(File, DocumentRevision.file_id == File.id)
        .where(DocumentRevision.document_id == Document.id, File.active.is_(True))
    )


def fetch_latest_active_revisions_by_document(
    session, document_ids: list[str]
) -> dict[str, DocumentRevision]:
    if not document_ids:
        return {}

    revision_ids_by_document: dict[str, str] = {}
    document_table = Document.__table__
    revision_table = DocumentRevision.__table__
    file_table = File.__table__

    for chunk in batched(document_ids, QUERY_CHUNK_SIZE):
        chunk_ids = list(chunk)
        current_chain_anchor = (
            select(
                document_table.c.id.label("document_id"),
                revision_table.c.id.label("revision_id"),
                revision_table.c.created_time.label("created_time"),
                revision_table.c.file_id.label("file_id"),
                revision_table.c.parent_revision_id.label("parent_revision_id"),
                file_table.c.active.label("file_active"),
                literal(0).label("depth"),
            )
            .select_from(
                document_table.join(
                    revision_table,
                    document_table.c.current_revision_id == revision_table.c.id,
                ).join(file_table, revision_table.c.file_id == file_table.c.id)
            )
            .where(document_table.c.id.in_(chunk_ids))
        )
        current_chain = current_chain_anchor.cte(
            "current_revision_chain", recursive=True
        )
        parent_revision = revision_table.alias("parent_revision")
        parent_file = file_table.alias("parent_file")
        current_chain = current_chain.union_all(
            select(
                current_chain.c.document_id,
                parent_revision.c.id,
                parent_revision.c.created_time,
                parent_revision.c.file_id,
                parent_revision.c.parent_revision_id,
                parent_file.c.active,
                (current_chain.c.depth + 1).label("depth"),
            ).select_from(
                current_chain.join(
                    parent_revision,
                    current_chain.c.parent_revision_id == parent_revision.c.id,
                ).join(parent_file, parent_revision.c.file_id == parent_file.c.id)
            )
        )
        active_current_chain = (
            select(
                current_chain.c.document_id,
                current_chain.c.revision_id,
                func.row_number()
                .over(
                    partition_by=current_chain.c.document_id,
                    order_by=current_chain.c.depth,
                )
                .label("row_number"),
            )
            .where(current_chain.c.file_active.is_(True))
            .subquery()
        )
        current_chain_rows = session.execute(
            select(
                active_current_chain.c.document_id,
                active_current_chain.c.revision_id,
            ).where(active_current_chain.c.row_number == 1)
        ).all()
        for document_id, revision_id in current_chain_rows:
            revision_ids_by_document[document_id] = revision_id

        fallback_document_ids = [
            document_id
            for document_id in chunk_ids
            if document_id not in revision_ids_by_document
        ]
        if not fallback_document_ids:
            continue

        active_revisions = (
            select(
                revision_table.c.document_id,
                revision_table.c.id.label("revision_id"),
                func.row_number()
                .over(
                    partition_by=revision_table.c.document_id,
                    order_by=revision_table.c.created_time.desc(),
                )
                .label("row_number"),
            )
            .select_from(
                revision_table.join(
                    file_table, revision_table.c.file_id == file_table.c.id
                )
            )
            .where(
                revision_table.c.document_id.in_(fallback_document_ids),
                file_table.c.active.is_(True),
            )
            .subquery()
        )
        fallback_rows = session.execute(
            select(
                active_revisions.c.document_id, active_revisions.c.revision_id
            ).where(active_revisions.c.row_number == 1)
        ).all()
        for document_id, revision_id in fallback_rows:
            revision_ids_by_document[document_id] = revision_id

    if not revision_ids_by_document:
        return {}

    revisions: list[DocumentRevision] = []
    revision_ids = list(revision_ids_by_document.values())
    for chunk in batched(revision_ids, QUERY_CHUNK_SIZE):
        revisions.extend(
            session.query(DocumentRevision)
            .options(joinedload(DocumentRevision.file), raiseload("*"))
            .filter(DocumentRevision.id.in_(list(chunk)))
            .all()
        )

    revisions_by_id = {revision.id: revision for revision in revisions}
    return {
        document_id: revisions_by_id[revision_id]
        for document_id, revision_id in revision_ids_by_document.items()
        if revision_id in revisions_by_id
    }


def _fetch_directory_rows(session, folder_id: str, last_key, limit: int):
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
    session,
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
            _active_revision_exists(),
        )

    if last_key is not None and last_key[0] == 1:
        _, last_name, last_id = last_key
        query = query.filter(
            _name_id_after_filter(name_expression, Document.id, last_name, last_id)
        )

    return query.order_by(name_expression.asc(), Document.id.asc()).limit(limit).all()


def fetch_directory_listing_items(
    session, folder_id: str, last_key: list[Any] | None, limit: int
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
    session, folder_id: str, last_key: list[Any] | None, limit: int
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


def _effective_active_revision_details_subquery(document_filters: Sequence[Any]):
    document_table = Document.__table__
    revision_table = DocumentRevision.__table__
    file_table = File.__table__

    matched_documents = (
        select(
            document_table.c.id,
            document_table.c.title,
            document_table.c.folder_id,
            document_table.c.created_time,
            document_table.c.current_revision_id,
        )
        .where(*document_filters)
        .cte("matched_documents")
    )

    current_chain_anchor = select(
        matched_documents.c.id.label("document_id"),
        revision_table.c.id.label("revision_id"),
        revision_table.c.created_time.label("revision_created_time"),
        revision_table.c.file_id.label("file_id"),
        revision_table.c.parent_revision_id.label("parent_revision_id"),
        file_table.c.active.label("file_active"),
        literal(0).label("depth"),
    ).select_from(
        matched_documents.join(
            revision_table,
            matched_documents.c.current_revision_id == revision_table.c.id,
        ).join(file_table, revision_table.c.file_id == file_table.c.id)
    )
    current_chain = current_chain_anchor.cte("search_current_chain", recursive=True)
    parent_revision = revision_table.alias("search_parent_revision")
    parent_file = file_table.alias("search_parent_file")
    current_chain = current_chain.union_all(
        select(
            current_chain.c.document_id,
            parent_revision.c.id,
            parent_revision.c.created_time,
            parent_revision.c.file_id,
            parent_revision.c.parent_revision_id,
            parent_file.c.active,
            (current_chain.c.depth + 1).label("depth"),
        ).select_from(
            current_chain.join(
                parent_revision,
                current_chain.c.parent_revision_id == parent_revision.c.id,
            ).join(parent_file, parent_revision.c.file_id == parent_file.c.id)
        )
    )

    current_ranked = (
        select(
            current_chain.c.document_id,
            current_chain.c.revision_id,
            current_chain.c.revision_created_time,
            current_chain.c.file_id,
            literal(0).label("source_rank"),
            func.row_number()
            .over(
                partition_by=current_chain.c.document_id,
                order_by=current_chain.c.depth.asc(),
            )
            .label("source_row_number"),
        )
        .where(current_chain.c.file_active.is_(True))
        .subquery()
    )
    current_first = select(
        current_ranked.c.document_id,
        current_ranked.c.revision_id,
        current_ranked.c.revision_created_time,
        current_ranked.c.file_id,
        current_ranked.c.source_rank,
    ).where(current_ranked.c.source_row_number == 1)

    fallback_ranked = (
        select(
            revision_table.c.document_id,
            revision_table.c.id.label("revision_id"),
            revision_table.c.created_time.label("revision_created_time"),
            revision_table.c.file_id,
            literal(1).label("source_rank"),
            func.row_number()
            .over(
                partition_by=revision_table.c.document_id,
                order_by=revision_table.c.created_time.desc(),
            )
            .label("source_row_number"),
        )
        .select_from(
            matched_documents.join(
                revision_table, matched_documents.c.id == revision_table.c.document_id
            ).join(file_table, revision_table.c.file_id == file_table.c.id)
        )
        .where(file_table.c.active.is_(True))
        .subquery()
    )
    fallback_first = select(
        fallback_ranked.c.document_id,
        fallback_ranked.c.revision_id,
        fallback_ranked.c.revision_created_time,
        fallback_ranked.c.file_id,
        fallback_ranked.c.source_rank,
    ).where(fallback_ranked.c.source_row_number == 1)

    active_choices = union_all(current_first, fallback_first).subquery()
    effective_ranked = select(
        active_choices.c.document_id,
        active_choices.c.revision_id,
        active_choices.c.revision_created_time,
        active_choices.c.file_id,
        func.row_number()
        .over(
            partition_by=active_choices.c.document_id,
            order_by=active_choices.c.source_rank.asc(),
        )
        .label("effective_row_number"),
    ).subquery()

    return (
        select(
            matched_documents.c.id.label("id"),
            matched_documents.c.title.label("name"),
            func.lower(matched_documents.c.title).label("name_sort_key"),
            matched_documents.c.folder_id.label("parent_id"),
            matched_documents.c.created_time.label("created_time"),
            effective_ranked.c.revision_created_time.label("last_modified"),
            file_table.c.size.label("size"),
            literal("document").label("type"),
            literal(1).label("type_rank"),
        )
        .select_from(
            matched_documents.join(
                effective_ranked,
                matched_documents.c.id == effective_ranked.c.document_id,
            ).join(file_table, effective_ranked.c.file_id == file_table.c.id)
        )
        .where(effective_ranked.c.effective_row_number == 1)
        .subquery()
    )


def _apply_search_cursor_filter(selectable, primary_column, last_key, sort_order: str):
    if last_key is None:
        return None

    last_primary, last_type_rank, last_id = last_key
    primary_comparison = (
        primary_column < last_primary
        if sort_order == "desc"
        else primary_column > last_primary
    )
    return or_(
        primary_comparison,
        and_(
            primary_column == last_primary,
            or_(
                selectable.c.type_rank > last_type_rank,
                and_(
                    selectable.c.type_rank == last_type_rank,
                    selectable.c.id > last_id,
                ),
            ),
        ),
    )


def _search_ordering(selectable, primary_column, sort_order: str):
    primary_order = (
        primary_column.desc() if sort_order == "desc" else primary_column.asc()
    )
    return [primary_order, selectable.c.type_rank.asc(), selectable.c.id.asc()]


def _search_primary_column(selectable, sort_by: str):
    if sort_by == "name":
        return selectable.c.name_sort_key
    if sort_by == "size":
        return func.coalesce(selectable.c.size, 0)
    if sort_by == "last_modified":
        return func.coalesce(selectable.c.last_modified, selectable.c.created_time)
    return selectable.c.created_time


def fetch_search_candidate_rows(
    session,
    *,
    query: str,
    sort_by: str,
    sort_order: str,
    search_documents: bool,
    search_directories: bool,
    last_key: list[Any] | None,
    limit: int,
) -> list[dict[str, Any]]:
    candidate_rows: list[dict[str, Any]] = []
    like_pattern = f"%{query}%"

    if search_directories:
        folder_selectable = (
            select(
                Folder.id.label("id"),
                Folder.name.label("name"),
                func.lower(Folder.name).label("name_sort_key"),
                Folder.parent_id.label("parent_id"),
                Folder.created_time.label("created_time"),
                literal(None).label("last_modified"),
                literal(0).label("size"),
                literal("directory").label("type"),
                literal(0).label("type_rank"),
            )
            .where(
                Folder.status != EntityStatus.DELETED,
                Folder.name.ilike(like_pattern),
            )
            .subquery()
        )
        primary_column = _search_primary_column(folder_selectable, sort_by)
        folder_query = select(folder_selectable)
        cursor_filter = _apply_search_cursor_filter(
            folder_selectable, primary_column, last_key, sort_order
        )
        if cursor_filter is not None:
            folder_query = folder_query.where(cursor_filter)
        folder_query = folder_query.order_by(
            *_search_ordering(folder_selectable, primary_column, sort_order)
        ).limit(limit)
        for row in session.execute(folder_query).mappings():
            item = dict(row)
            item[_CURSOR_KEY] = _search_item_cursor_key(item, sort_by)
            item.pop("name_sort_key", None)
            candidate_rows.append(item)

    if search_documents:
        document_details = _effective_active_revision_details_subquery(
            [
                Document.__table__.c.status != EntityStatus.DELETED,
                Document.__table__.c.title.ilike(like_pattern),
            ]
        )
        primary_column = _search_primary_column(document_details, sort_by)
        document_query = select(document_details)
        cursor_filter = _apply_search_cursor_filter(
            document_details, primary_column, last_key, sort_order
        )
        if cursor_filter is not None:
            document_query = document_query.where(cursor_filter)
        document_query = document_query.order_by(
            *_search_ordering(document_details, primary_column, sort_order)
        ).limit(limit)
        for row in session.execute(document_query).mappings():
            item = dict(row)
            item[_CURSOR_KEY] = _search_item_cursor_key(item, sort_by)
            item.pop("name_sort_key", None)
            candidate_rows.append(item)

    def compare_rows(left: dict[str, Any], right: dict[str, Any]) -> int:
        left_key = search_cursor_key(left, sort_by)
        right_key = search_cursor_key(right, sort_by)
        if left_key[0] != right_key[0]:
            if sort_order == "desc":
                return -1 if left_key[0] > right_key[0] else 1
            return -1 if left_key[0] < right_key[0] else 1
        if left_key[1] != right_key[1]:
            return -1 if left_key[1] < right_key[1] else 1
        if left_key[2] != right_key[2]:
            return -1 if left_key[2] < right_key[2] else 1
        return 0

    candidate_rows.sort(key=cmp_to_key(compare_rows))
    return candidate_rows[:limit]


_fetch_latest_active_revisions_by_document = fetch_latest_active_revisions_by_document
