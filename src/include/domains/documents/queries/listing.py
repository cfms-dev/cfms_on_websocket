import datetime
from contextlib import closing
from dataclasses import dataclass
from itertools import batched
from typing import Any
lazy from collections.abc import Mapping, Sequence

from cacl_compiler import ObjectType
from sqlalchemy import (
    and_,
    case,
    exists,
    func,
    literal,
    null,
    or_,
    select,
    union_all,
)
from sqlalchemy.orm import joinedload, raiseload

from include.config.constants import QUERY_CHUNK_SIZE
from include.database.cursors import KeysetBatchStrategy, default_keyset_batch_strategy
from include.database.models.documents import (
    Document,
    DocumentRevision,
    EntityStatus,
    Folder,
    Node,
    NodeType,
)
from include.database.models.files import File
from include.domains.access.authorization.evaluation import has_bypass_dacl
from include.domains.access.authorization.visibility import (
    BatchVisibilityEvaluator,
    VisibilityCandidate,
)
lazy from include.database.models.identity import User

_CURSOR_KEY = "_cursor_key"
_SEARCH_PROBE_MULTIPLIER = 2
_SEARCH_MIN_PROBE_LIMIT = 128


def _lowered(value: str) -> str:
    return value.lower()


def directory_cursor_key(item: dict[str, Any]) -> list[Any]:
    if _CURSOR_KEY in item:
        return list(item[_CURSOR_KEY])
    type_rank = 0 if item["type"] == "directory" else 1
    return [type_rank, _lowered(item["name"]), item["id"]]


def _search_cursor_primary_value(item: dict[str, Any], sort_by: str) -> Any:
    match sort_by:
        case "name":
            primary = item.get("name_sort_key")
            return _lowered(item["name"]) if primary is None else primary
        case "size":
            return item.get("size", 0) or 0
        case "last_modified":
            primary = item.get("last_modified")
            return item["created_time"] if primary is None else primary

    return item["created_time"]


def search_cursor_key(item: dict[str, Any], sort_by: str) -> list[Any]:
    if _CURSOR_KEY in item:
        return list(item[_CURSOR_KEY])
    type_rank = 0 if item["type"] == "directory" else 1
    return [_search_cursor_primary_value(item, sort_by), type_rank, item["id"]]


def _directory_item_cursor_key(
    type_rank: int, name_sort_key: str, item_id: str
) -> list[Any]:
    return [type_rank, name_sort_key, item_id]


def _search_item_cursor_key(
    item: dict[str, Any],
    sort_by: str,
) -> list[Any]:
    return [_search_cursor_primary_value(item, sort_by), item["type_rank"], item["id"]]


def _name_id_after_filter(name_expression, id_column, last_name: str, last_id: str):
    return or_(
        name_expression > last_name,
        and_(name_expression == last_name, id_column > last_id),
    )


def _active_revision_exists_for(document_id_column):
    revision_table = DocumentRevision.__table__
    file_table = File.__table__
    return exists(
        select(1)
        .select_from(
            revision_table.join(file_table, revision_table.c.file_id == file_table.c.id)
        )
        .where(
            revision_table.c.document_id == document_id_column,
            file_table.c.active.is_(True),
        )
    )


def _active_revision_exists():
    return _active_revision_exists_for(Document.id)


def count_active_directory_children(session, folder_id: str) -> int:
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
            _active_revision_exists(),
        )
        .scalar()
        or 0
    )
    return int(folder_count) + int(document_count)


def _build_active_revision_chain_cte(
    *,
    cte_name: str,
    rev_alias_name: str,
    file_alias_name: str,
    anchor_from: Any,
    passthrough_columns: Sequence[tuple[str, Any]],
    anchor_where: Sequence[Any] = (),
    include_revision_id: bool = False,
    include_details: bool = False,
):
    revision_table = DocumentRevision.__table__
    file_table = File.__table__

    anchor_cols: list[Any] = [col.label(name) for name, col in passthrough_columns]
    if include_revision_id:
        anchor_cols.append(revision_table.c.id.label("revision_id"))
    if include_details:
        anchor_cols.extend(
            (
                revision_table.c.created_time.label("revision_created_time"),
                file_table.c.size.label("file_size"),
            )
        )
    anchor_cols.extend(
        (
            revision_table.c.parent_revision_id.label("parent_revision_id"),
            file_table.c.active.label("file_active"),
        )
    )

    anchor = select(*anchor_cols).select_from(anchor_from)
    if anchor_where:
        anchor = anchor.where(*anchor_where)

    chain = anchor.cte(cte_name, recursive=True)
    parent_rev = revision_table.alias(rev_alias_name)
    parent_file = file_table.alias(file_alias_name)

    recursive_cols: list[Any] = [chain.c[name] for name, _ in passthrough_columns]
    if include_revision_id:
        recursive_cols.append(parent_rev.c.id)
    if include_details:
        recursive_cols.extend((parent_rev.c.created_time, parent_file.c.size))
    recursive_cols.extend((parent_rev.c.parent_revision_id, parent_file.c.active))

    return chain.union_all(
        select(*recursive_cols)
        .select_from(
            chain.join(
                parent_rev,
                chain.c.parent_revision_id == parent_rev.c.id,
            ).join(parent_file, parent_rev.c.file_id == parent_file.c.id)
        )
        .where(chain.c.file_active.is_(False))
    )


def _build_ranked_active_revisions_subquery(
    *,
    document_ids: Sequence[str] | None = None,
    matched_documents: Any = None,
    exclude_chain_cte: Any = None,
    include_revision_id: bool = False,
    include_details: bool = False,
    rev_alias_name: str | None = None,
    file_alias_name: str | None = None,
):
    revision_table = DocumentRevision.__table__
    file_table = File.__table__
    rev_src = (
        revision_table.alias(rev_alias_name)
        if rev_alias_name is not None
        else revision_table
    )
    file_src = (
        file_table.alias(file_alias_name) if file_alias_name is not None else file_table
    )

    cols: list[Any] = []
    where_clauses: list[Any] = [file_src.c.active.is_(True)]
    if matched_documents is not None:
        partition_col = matched_documents.c.id
        from_clause = matched_documents.join(
            rev_src, matched_documents.c.id == rev_src.c.document_id
        ).join(file_src, rev_src.c.file_id == file_src.c.id)
        cols.extend(
            (
                matched_documents.c.id.label("id"),
                matched_documents.c.name.label("name"),
                matched_documents.c.parent_id.label("parent_id"),
                matched_documents.c.created_time.label("created_time"),
                matched_documents.c.inherit.label("inherit"),
            )
        )
        if exclude_chain_cte is not None:
            where_clauses.append(
                ~exists(
                    select(1).where(
                        exclude_chain_cte.c.document_id == matched_documents.c.id,
                        exclude_chain_cte.c.file_active.is_(True),
                    )
                )
            )
    else:
        assert document_ids is not None
        partition_col = rev_src.c.document_id
        from_clause = rev_src.join(file_src, rev_src.c.file_id == file_src.c.id)
        cols.append(rev_src.c.document_id.label("document_id"))
        where_clauses.append(rev_src.c.document_id.in_(list(document_ids)))

    if include_revision_id:
        cols.append(rev_src.c.id.label("revision_id"))
    if include_details:
        cols.extend(
            (
                rev_src.c.created_time.label("last_modified"),
                file_src.c.size.label("size"),
            )
        )

    cols.append(
        func.row_number()
        .over(
            partition_by=partition_col,
            order_by=rev_src.c.created_time.desc(),
        )
        .label("row_number")
    )

    return select(*cols).select_from(from_clause).where(*where_clauses).subquery()


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
        current_chain = _build_active_revision_chain_cte(
            cte_name="current_revision_chain",
            rev_alias_name="parent_revision",
            file_alias_name="parent_file",
            anchor_from=document_table.join(
                revision_table,
                document_table.c.current_revision_id == revision_table.c.id,
            ).join(file_table, revision_table.c.file_id == file_table.c.id),
            passthrough_columns=(("document_id", document_table.c.id),),
            anchor_where=(document_table.c.id.in_(chunk_ids),),
            include_revision_id=True,
        )
        current_chain_rows = session.execute(
            select(
                current_chain.c.document_id,
                current_chain.c.revision_id,
            ).where(current_chain.c.file_active.is_(True))
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

        active_revisions = _build_ranked_active_revisions_subquery(
            document_ids=fallback_document_ids,
            include_revision_id=True,
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
    node_table = Node.__table__
    revision_table = DocumentRevision.__table__
    file_table = File.__table__

    matched_documents = (
        select(
            document_table.c.id,
            node_table.c.name,
            node_table.c.parent_id,
            document_table.c.created_time,
            document_table.c.current_revision_id,
            node_table.c.inherit,
        )
        .select_from(
            document_table.join(node_table, node_table.c.id == document_table.c.id)
        )
        .where(*document_filters)
        .cte("matched_documents")
    )

    current_chain = _build_active_revision_chain_cte(
        cte_name="search_current_chain",
        rev_alias_name="search_parent_rev",
        file_alias_name="search_parent_file",
        anchor_from=matched_documents.join(
            revision_table,
            matched_documents.c.current_revision_id == revision_table.c.id,
        ).join(file_table, revision_table.c.file_id == file_table.c.id),
        passthrough_columns=(
            ("document_id", matched_documents.c.id),
            ("name", matched_documents.c.name),
            ("parent_id", matched_documents.c.parent_id),
            ("created_time", matched_documents.c.created_time),
            ("inherit", matched_documents.c.inherit),
        ),
        include_details=True,
    )

    current_active = select(
        current_chain.c.document_id.label("id"),
        current_chain.c.name.label("name"),
        func.lower(current_chain.c.name).label("name_sort_key"),
        current_chain.c.parent_id.label("parent_id"),
        current_chain.c.created_time.label("created_time"),
        current_chain.c.inherit.label("inherit"),
        current_chain.c.revision_created_time.label("last_modified"),
        current_chain.c.file_size.label("size"),
        literal("document").label("type"),
        literal(1).label("type_rank"),
    ).where(current_chain.c.file_active.is_(True))

    fallback_ranked = _build_ranked_active_revisions_subquery(
        matched_documents=matched_documents,
        exclude_chain_cte=current_chain,
        include_details=True,
        rev_alias_name="search_fallback_rev",
        file_alias_name="search_fallback_file",
    )
    fallback_active = select(
        fallback_ranked.c.id,
        fallback_ranked.c.name,
        func.lower(fallback_ranked.c.name).label("name_sort_key"),
        fallback_ranked.c.parent_id,
        fallback_ranked.c.created_time,
        fallback_ranked.c.inherit,
        fallback_ranked.c.last_modified,
        fallback_ranked.c.size,
        literal("document").label("type"),
        literal(1).label("type_rank"),
    ).where(fallback_ranked.c.row_number == 1)

    return union_all(current_active, fallback_active).subquery()


def _fetch_active_revision_details_by_document(
    session,
    doc_current_rev_ids: Mapping[str, str | None],
) -> dict[str, tuple[float, int | None]]:
    """Resolve (last_modified, size) for active documents via current_revision_id fast path."""
    if not doc_current_rev_ids:
        return {}

    revision_table = DocumentRevision.__table__
    file_table = File.__table__
    details_by_doc: dict[str, tuple[float, int | None]] = {}
    inactive_parent_revs: dict[str, str] = {}

    current_rev_ids = list(
        dict.fromkeys(rid for rid in doc_current_rev_ids.values() if rid is not None)
    )
    for chunk in batched(current_rev_ids, QUERY_CHUNK_SIZE):
        rows = session.execute(
            select(
                revision_table.c.id,
                revision_table.c.document_id,
                revision_table.c.created_time,
                file_table.c.size,
                file_table.c.active,
                revision_table.c.parent_revision_id,
            )
            .select_from(
                revision_table.join(
                    file_table, revision_table.c.file_id == file_table.c.id
                )
            )
            .where(revision_table.c.id.in_(list(chunk)))
        ).all()
        for rev_id, doc_id, created_time, file_size, is_active, parent_rev_id in rows:
            if doc_current_rev_ids.get(doc_id) != rev_id:
                continue
            if is_active:
                details_by_doc[doc_id] = (created_time, file_size)
            elif parent_rev_id is not None:
                inactive_parent_revs[doc_id] = parent_rev_id

    if inactive_parent_revs:
        parent_rev_ids = list(dict.fromkeys(inactive_parent_revs.values()))
        for chunk in batched(parent_rev_ids, QUERY_CHUNK_SIZE):
            chain = _build_active_revision_chain_cte(
                cte_name="search_hydrate_rev_chain",
                rev_alias_name="search_hydrate_parent_rev",
                file_alias_name="search_hydrate_parent_file",
                anchor_from=revision_table.join(
                    file_table, revision_table.c.file_id == file_table.c.id
                ),
                passthrough_columns=(("document_id", revision_table.c.document_id),),
                anchor_where=(revision_table.c.id.in_(list(chunk)),),
                include_details=True,
            )
            chain_rows = session.execute(
                select(
                    chain.c.document_id,
                    chain.c.revision_created_time,
                    chain.c.file_size,
                ).where(chain.c.file_active.is_(True))
            ).all()
            for doc_id, created_time, file_size in chain_rows:
                if doc_id in inactive_parent_revs:
                    details_by_doc[doc_id] = (created_time, file_size)

    fallback_doc_ids = [
        doc_id for doc_id in doc_current_rev_ids if doc_id not in details_by_doc
    ]
    if fallback_doc_ids:
        for chunk in batched(fallback_doc_ids, QUERY_CHUNK_SIZE):
            ranked = _build_ranked_active_revisions_subquery(
                document_ids=list(chunk),
                include_details=True,
            )
            fallback_rows = session.execute(
                select(
                    ranked.c.document_id,
                    ranked.c.last_modified,
                    ranked.c.size,
                ).where(ranked.c.row_number == 1)
            ).all()
            for doc_id, created_time, file_size in fallback_rows:
                details_by_doc[doc_id] = (created_time, file_size)

    return details_by_doc


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


def _search_lightweight_candidate_selectable(
    *,
    query: str,
    search_documents: bool,
    search_directories: bool,
    require_active_document_revision: bool,
):
    node_table = Node.__table__
    folder_table = Folder.__table__
    document_table = Document.__table__
    name_expression = func.lower(node_table.c.name)

    if search_directories and search_documents:
        filters: list[Any] = [
            node_table.c.status != EntityStatus.DELETED,
            node_table.c.name.icontains(query, autoescape=True),
            node_table.c.type.in_((NodeType.DIRECTORY.value, NodeType.DOCUMENT.value)),
        ]
        if require_active_document_revision:
            filters.append(
                or_(
                    node_table.c.type == NodeType.DIRECTORY.value,
                    _active_revision_exists_for(document_table.c.id),
                )
            )
        return (
            select(
                node_table.c.id.label("id"),
                node_table.c.name.label("name"),
                name_expression.label("name_sort_key"),
                node_table.c.parent_id.label("parent_id"),
                func.coalesce(
                    folder_table.c.created_time, document_table.c.created_time
                ).label("created_time"),
                node_table.c.type.label("type"),
                case(
                    (node_table.c.type == NodeType.DIRECTORY.value, 0),
                    else_=1,
                ).label("type_rank"),
                node_table.c.inherit.label("inherit"),
                document_table.c.current_revision_id.label("current_revision_id"),
            )
            .select_from(
                node_table.outerjoin(
                    folder_table, folder_table.c.id == node_table.c.id
                ).outerjoin(document_table, document_table.c.id == node_table.c.id)
            )
            .where(*filters)
            .subquery("search_candidates")
        )

    if search_directories:
        return (
            select(
                node_table.c.id.label("id"),
                node_table.c.name.label("name"),
                name_expression.label("name_sort_key"),
                node_table.c.parent_id.label("parent_id"),
                folder_table.c.created_time.label("created_time"),
                literal("directory").label("type"),
                literal(0).label("type_rank"),
                node_table.c.inherit.label("inherit"),
                null().label("current_revision_id"),
            )
            .select_from(
                node_table.join(folder_table, folder_table.c.id == node_table.c.id)
            )
            .where(
                node_table.c.status != EntityStatus.DELETED,
                node_table.c.name.icontains(query, autoescape=True),
            )
            .subquery("search_candidates")
        )

    if search_documents:
        doc_filters: list[Any] = [
            node_table.c.status != EntityStatus.DELETED,
            node_table.c.name.icontains(query, autoescape=True),
        ]
        if require_active_document_revision:
            doc_filters.append(_active_revision_exists_for(document_table.c.id))
        return (
            select(
                node_table.c.id.label("id"),
                node_table.c.name.label("name"),
                name_expression.label("name_sort_key"),
                node_table.c.parent_id.label("parent_id"),
                document_table.c.created_time.label("created_time"),
                literal("document").label("type"),
                literal(1).label("type_rank"),
                node_table.c.inherit.label("inherit"),
                document_table.c.current_revision_id.label("current_revision_id"),
            )
            .select_from(
                node_table.join(document_table, document_table.c.id == node_table.c.id)
            )
            .where(*doc_filters)
            .subquery("search_candidates")
        )

    return None


def _search_candidate_selectable(
    *,
    query: str,
    search_documents: bool,
    search_directories: bool,
):
    selects = []

    if search_directories:
        name_expression = func.lower(Folder.name)
        selects.append(
            select(
                Folder.id.label("id"),
                Folder.name.label("name"),
                name_expression.label("name_sort_key"),
                Folder.parent_id.label("parent_id"),
                Folder.created_time.label("created_time"),
                null().label("last_modified"),
                literal(0).label("size"),
                literal("directory").label("type"),
                literal(0).label("type_rank"),
                Folder.inherit.label("inherit"),
            ).where(
                Folder.status != EntityStatus.DELETED,
                Folder.name.icontains(query, autoescape=True),
            )
        )

    if search_documents:
        document_details = _effective_active_revision_details_subquery(
            [
                Node.__table__.c.status != EntityStatus.DELETED,
                Node.__table__.c.name.icontains(query, autoescape=True),
            ]
        )
        selects.append(
            select(
                document_details.c.id,
                document_details.c.name,
                document_details.c.name_sort_key,
                document_details.c.parent_id,
                document_details.c.created_time,
                document_details.c.last_modified,
                document_details.c.size,
                document_details.c.type,
                document_details.c.type_rank,
                document_details.c.inherit,
            )
        )

    if not selects:
        return None
    if len(selects) == 1:
        return selects[0].subquery("search_candidates")
    return union_all(*selects).subquery("search_candidates")


def _build_search_select(
    candidates,
    primary_column,
    last_key: list[Any] | None,
    sort_order: str,
    *,
    include_revision_details: bool,
    limit: int | None = None,
):
    if include_revision_details:
        search_query = select(
            candidates.c.id,
            candidates.c.name,
            candidates.c.name_sort_key,
            candidates.c.parent_id,
            candidates.c.created_time,
            candidates.c.last_modified,
            candidates.c.size,
            candidates.c.type,
            candidates.c.type_rank,
            candidates.c.inherit,
        )
    else:
        search_query = select(
            candidates.c.id,
            candidates.c.name,
            candidates.c.name_sort_key,
            candidates.c.parent_id,
            candidates.c.created_time,
            candidates.c.type,
            candidates.c.type_rank,
            candidates.c.inherit,
            candidates.c.current_revision_id,
        )
    cursor_filter = _apply_search_cursor_filter(
        candidates, primary_column, last_key, sort_order
    )
    if cursor_filter is not None:
        search_query = search_query.where(cursor_filter)
    search_query = search_query.order_by(
        *_search_ordering(candidates, primary_column, sort_order)
    )
    if limit is not None:
        search_query = search_query.limit(limit)
    return search_query


def _execute_search_batch(
    session,
    candidates,
    primary_column,
    last_key: list[Any] | None,
    sort_order: str,
    limit: int,
    *,
    include_revision_details: bool,
) -> list[dict[str, Any]]:
    search_query = _build_search_select(
        candidates,
        primary_column,
        last_key,
        sort_order,
        include_revision_details=include_revision_details,
        limit=limit,
    )
    return [
        {str(key): value for key, value in row.items()}
        for row in session.execute(search_query).mappings()
    ]


def _finalize_search_item(raw_item: dict[str, Any], sort_by: str) -> dict[str, Any]:
    item = dict(raw_item)
    item[_CURSOR_KEY] = _search_item_cursor_key(raw_item, sort_by)
    item.pop("name_sort_key", None)
    item.pop("inherit", None)
    item.pop("current_revision_id", None)
    if item["type"] == "directory":
        item.pop("last_modified", None)
        item.pop("size", None)
    return item


def _hydrate_lightweight_search_rows(
    session,
    raw_rows: Sequence[dict[str, Any]],
    sort_by: str,
) -> list[dict[str, Any]]:
    doc_current_rev_ids = {
        row["id"]: row.get("current_revision_id")
        for row in raw_rows
        if row["type"] == "document"
    }
    rev_details = (
        _fetch_active_revision_details_by_document(session, doc_current_rev_ids)
        if doc_current_rev_ids
        else {}
    )
    hydrated: list[dict[str, Any]] = []
    for raw_item in raw_rows:
        if raw_item["type"] == "document":
            details = rev_details.get(raw_item["id"])
            if details is None:
                continue
            enriched = dict(raw_item)
            enriched["last_modified"], enriched["size"] = details
            hydrated.append(_finalize_search_item(enriched, sort_by))
        else:
            hydrated.append(_finalize_search_item(raw_item, sort_by))
    return hydrated


class _SearchPageCollector:
    """Filter candidate search rows for visibility and hydrate document revisions on demand."""

    def __init__(
        self,
        session,
        evaluator: BatchVisibilityEvaluator,
        *,
        sort_by: str,
        limit: int,
        lazy_hydrate_documents: bool,
    ) -> None:
        self._session = session
        self._evaluator = evaluator
        self._sort_by = sort_by
        self._limit = limit
        self._lazy_hydrate_documents = lazy_hydrate_documents
        self.visible_rows: list[dict[str, Any]] = []

    @property
    def is_full(self) -> bool:
        return len(self.visible_rows) >= self._limit

    def consume(self, raw_rows: Sequence[dict[str, Any]]) -> None:
        for sub_chunk in batched(raw_rows, QUERY_CHUNK_SIZE):
            if self.is_full:
                return
            chunk_list = list(sub_chunk)
            candidates = [
                VisibilityCandidate(
                    node_id=row["id"],
                    parent_id=row["parent_id"],
                    object_type=(
                        ObjectType.DIRECTORY
                        if row["type"] == "directory"
                        else ObjectType.DOCUMENT
                    ),
                    inherit=bool(row["inherit"]),
                )
                for row in chunk_list
            ]
            self._evaluator.preload(candidates)

            if not self._lazy_hydrate_documents:
                self._collect_eager(chunk_list, candidates)
            else:
                self._collect_with_lazy_hydration(chunk_list, candidates)

    def _collect_eager(
        self,
        chunk_list: Sequence[dict[str, Any]],
        candidates: Sequence[VisibilityCandidate],
    ) -> None:
        for raw_item, candidate in zip(chunk_list, candidates, strict=True):
            if self._evaluator.is_visible(candidate):
                self.visible_rows.append(_finalize_search_item(raw_item, self._sort_by))
                if self.is_full:
                    return

    def _collect_with_lazy_hydration(
        self,
        chunk_list: Sequence[dict[str, Any]],
        candidates: Sequence[VisibilityCandidate],
    ) -> None:
        pos = 0
        chunk_len = len(chunk_list)
        while pos < chunk_len and not self.is_full:
            needed = self._limit - len(self.visible_rows)
            pending_visible: list[dict[str, Any]] = []
            while pos < chunk_len and len(pending_visible) < needed:
                raw_item = chunk_list[pos]
                candidate = candidates[pos]
                pos += 1
                if self._evaluator.is_visible(candidate):
                    pending_visible.append(raw_item)
            if not pending_visible:
                break
            self.visible_rows.extend(
                _hydrate_lightweight_search_rows(
                    self._session, pending_visible, self._sort_by
                )
            )


@dataclass(frozen=True, slots=True)
class _SearchQuerySpec:
    query: str
    sort_by: str
    sort_order: str
    search_documents: bool
    search_directories: bool
    last_key: list[Any] | None
    limit: int

    @property
    def needs_revision_in_sort(self) -> bool:
        return self.sort_by in ("size", "last_modified")

    @property
    def lazy_hydrate_documents(self) -> bool:
        return not self.needs_revision_in_sort and self.search_documents


def _resolve_search_candidates(spec: _SearchQuerySpec, *, bypass_dacl: bool):
    if spec.needs_revision_in_sort:
        return _search_candidate_selectable(
            query=spec.query,
            search_documents=spec.search_documents,
            search_directories=spec.search_directories,
        )
    return _search_lightweight_candidate_selectable(
        query=spec.query,
        search_documents=spec.search_documents,
        search_directories=spec.search_directories,
        require_active_document_revision=bypass_dacl,
    )


def _fetch_bypass_search_rows(
    session,
    candidates,
    primary_column,
    spec: _SearchQuerySpec,
) -> list[dict[str, Any]]:
    raw_rows = _execute_search_batch(
        session,
        candidates,
        primary_column,
        spec.last_key,
        spec.sort_order,
        spec.limit,
        include_revision_details=spec.needs_revision_in_sort,
    )
    if spec.needs_revision_in_sort or not spec.search_documents:
        return [_finalize_search_item(row, spec.sort_by) for row in raw_rows]
    return _hydrate_lightweight_search_rows(session, raw_rows, spec.sort_by)


def _fetch_filtered_search_rows(
    session,
    candidates,
    primary_column,
    spec: _SearchQuerySpec,
    *,
    user: User,
    now_utc: datetime.datetime,
    batch_strategy: KeysetBatchStrategy | None,
) -> list[dict[str, Any]]:
    evaluator = BatchVisibilityEvaluator.for_user(session, user, now_utc)
    collector = _SearchPageCollector(
        session,
        evaluator,
        sort_by=spec.sort_by,
        limit=spec.limit,
        lazy_hydrate_documents=spec.lazy_hydrate_documents,
    )

    probe_limit = max(spec.limit * _SEARCH_PROBE_MULTIPLIER, _SEARCH_MIN_PROBE_LIMIT)
    probe_rows = _execute_search_batch(
        session,
        candidates,
        primary_column,
        spec.last_key,
        spec.sort_order,
        probe_limit,
        include_revision_details=spec.needs_revision_in_sort,
    )
    if not probe_rows:
        return []

    collector.consume(probe_rows)
    if collector.is_full or len(probe_rows) < probe_limit:
        return collector.visible_rows

    strategy = batch_strategy or default_keyset_batch_strategy(session)
    with closing(
        strategy.iter_batches(
            session,
            build_select=lambda batch_key, batch_limit: _build_search_select(
                candidates,
                primary_column,
                batch_key,
                spec.sort_order,
                include_revision_details=spec.needs_revision_in_sort,
                limit=batch_limit,
            ),
            cursor_key_of=lambda row: _search_item_cursor_key(row, spec.sort_by),
            initial_last_key=_search_item_cursor_key(probe_rows[-1], spec.sort_by),
        )
    ) as batches:
        for batch in batches:
            collector.consume(batch)
            if collector.is_full:
                break

    return collector.visible_rows


def fetch_visible_search_candidate_rows(
    session,
    *,
    user: User,
    now: datetime.datetime | float,
    query: str,
    sort_by: str,
    sort_order: str,
    search_documents: bool,
    search_directories: bool,
    last_key: list[Any] | None,
    limit: int,
    batch_strategy: KeysetBatchStrategy | None = None,
) -> list[dict[str, Any]]:
    if limit <= 0:
        return []

    spec = _SearchQuerySpec(
        query=query,
        sort_by=sort_by,
        sort_order=sort_order,
        search_documents=search_documents,
        search_directories=search_directories,
        last_key=last_key,
        limit=limit,
    )
    bypass_dacl = has_bypass_dacl(user)
    candidates = _resolve_search_candidates(spec, bypass_dacl=bypass_dacl)
    if candidates is None:
        return []

    primary_column = _search_primary_column(candidates, spec.sort_by)
    if bypass_dacl:
        return _fetch_bypass_search_rows(session, candidates, primary_column, spec)

    now_utc = (
        datetime.datetime.fromtimestamp(now, tz=datetime.UTC)
        if isinstance(now, int | float)
        else now.astimezone(datetime.UTC)
    )
    return _fetch_filtered_search_rows(
        session,
        candidates,
        primary_column,
        spec,
        user=user,
        now_utc=now_utc,
        batch_strategy=batch_strategy,
    )
