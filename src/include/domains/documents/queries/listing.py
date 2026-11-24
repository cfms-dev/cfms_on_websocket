import datetime
from itertools import batched
from typing import Any
lazy from collections.abc import Mapping, Sequence

from cacl_compiler import AtomicOp, CompiledPolicy, ObjectType
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
from include.database.models.access import (
    NodeDaclAtom,
    NodeDaclClause,
    NodeDaclRule,
)
from include.database.models.documents import (
    Document,
    DocumentRevision,
    EntityStatus,
    Folder,
    Node,
    NodeType,
)
from include.database.models.files import File
from include.domains.access.authorization.engine import (
    DIRECTORY_VISIBILITY_MASK,
    DOCUMENT_VISIBILITY_MASK,
    InheritedDaclState,
    Subject,
    step_node_dacl,
)
from include.domains.access.authorization.evaluation import (
    has_bypass_dacl,
    should_check_ancestor_traverse,
    user_to_subject,
)
from include.domains.access.authorization.storage import (
    assemble_rules_from_joined_rows,
    dacl_rule_validity_predicates,
    load_node_policies,
)
lazy from include.database.models.identity import User

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


_TRAVERSE_BIT = int(AtomicOp.TRAVERSE)
_EMPTY_INHERITED_STATE = InheritedDaclState()


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


def _build_combined_ancestors_and_policies_stmt(
    missing_ancestors: Sequence[str],
    candidate_ids: Sequence[str],
    active_ref: datetime.datetime,
):
    node_table = Node.__table__
    rule_table = NodeDaclRule.__table__
    clause_table = NodeDaclClause.__table__
    atom_table = NodeDaclAtom.__table__

    anchor = select(
        node_table.c.id.label("id"),
        node_table.c.parent_id.label("parent_id"),
        node_table.c.status.label("status"),
        node_table.c.inherit.label("inherit"),
        literal(0).label("depth"),
    ).where(node_table.c.id.in_(list(missing_ancestors)))
    ancestors = anchor.cte("search_anc_meta", recursive=True)
    parent_node = node_table.alias("search_anc_parent")
    ancestors = ancestors.union(
        select(
            parent_node.c.id,
            parent_node.c.parent_id,
            parent_node.c.status,
            parent_node.c.inherit,
            (ancestors.c.depth + 1).label("depth"),
        )
        .select_from(
            ancestors.join(parent_node, parent_node.c.id == ancestors.c.parent_id)
        )
        .where(ancestors.c.parent_id.is_not(None), ancestors.c.depth < 128)
    )
    distinct_ancestors = (
        select(
            ancestors.c.id,
            ancestors.c.parent_id,
            ancestors.c.status,
            ancestors.c.inherit,
        )
        .distinct()
        .cte("search_anc_distinct")
    )

    anc_rule_table = rule_table.alias("search_anc_rule")
    anc_clause_table = clause_table.alias("search_anc_clause")
    anc_atom_table = atom_table.alias("search_anc_atom")
    anc_validity = dacl_rule_validity_predicates(anc_rule_table, active_ref=active_ref)

    anc_branch = select(
        literal(0).label("row_kind"),
        distinct_ancestors.c.id.label("node_id"),
        distinct_ancestors.c.parent_id.label("parent_id"),
        distinct_ancestors.c.status.label("status"),
        distinct_ancestors.c.inherit.label("inherit"),
        anc_rule_table.c.id.label("rule_id"),
        anc_rule_table.c.effect.label("effect"),
        anc_rule_table.c.permission_mask.label("permission_mask"),
        anc_rule_table.c.scope.label("scope"),
        anc_rule_table.c.valid_from.label("valid_from"),
        anc_rule_table.c.valid_until.label("valid_until"),
        anc_rule_table.c.remark.label("remark"),
        anc_clause_table.c.id.label("clause_id"),
        anc_atom_table.c.id.label("atom_id"),
        anc_atom_table.c.predicate_kind.label("predicate_kind"),
        anc_atom_table.c.predicate_value.label("predicate_value"),
        anc_atom_table.c.is_negated.label("is_negated"),
    ).select_from(
        distinct_ancestors.outerjoin(
            anc_rule_table,
            and_(anc_rule_table.c.node_id == distinct_ancestors.c.id, *anc_validity),
        )
        .outerjoin(anc_clause_table, anc_clause_table.c.rule_id == anc_rule_table.c.id)
        .outerjoin(anc_atom_table, anc_atom_table.c.clause_id == anc_clause_table.c.id)
    )

    if not candidate_ids:
        return anc_branch

    cand_validity = dacl_rule_validity_predicates(rule_table, active_ref=active_ref)
    cand_branch = (
        select(
            literal(1).label("row_kind"),
            rule_table.c.node_id.label("node_id"),
            null().label("parent_id"),
            null().label("status"),
            null().label("inherit"),
            rule_table.c.id.label("rule_id"),
            rule_table.c.effect.label("effect"),
            rule_table.c.permission_mask.label("permission_mask"),
            rule_table.c.scope.label("scope"),
            rule_table.c.valid_from.label("valid_from"),
            rule_table.c.valid_until.label("valid_until"),
            rule_table.c.remark.label("remark"),
            clause_table.c.id.label("clause_id"),
            atom_table.c.id.label("atom_id"),
            atom_table.c.predicate_kind.label("predicate_kind"),
            atom_table.c.predicate_value.label("predicate_value"),
            atom_table.c.is_negated.label("is_negated"),
        )
        .select_from(
            rule_table.outerjoin(
                clause_table, clause_table.c.rule_id == rule_table.c.id
            ).outerjoin(atom_table, atom_table.c.clause_id == clause_table.c.id)
        )
        .where(
            rule_table.c.node_id.in_(list(candidate_ids)),
            *cand_validity,
            ~exists(select(1).where(distinct_ancestors.c.id == rule_table.c.node_id)),
        )
    )
    return union_all(anc_branch, cand_branch)


class _SearchVisibilityEvaluator:
    """Request-scoped memoized CACL evaluator for batched search candidates."""

    def __init__(
        self,
        session,
        subject: Subject,
        now_utc: datetime.datetime,
        *,
        check_traverse: bool,
    ) -> None:
        self._session = session
        self._subject = subject
        self._now_utc = now_utc
        self._check_traverse = check_traverse
        self._node_meta: dict[str, tuple[str | None, int, bool]] = {}
        self._node_policies: dict[str, CompiledPolicy] = {}
        self._dir_state_cache: dict[str, tuple[bool, InheritedDaclState]] = {}

    def ensure_loaded(self, batch_items: Sequence[dict[str, Any]]) -> None:
        for item in batch_items:
            nid: str = item["id"]
            if nid not in self._node_meta:
                self._node_meta[nid] = (
                    item["parent_id"],
                    EntityStatus.OK.value,
                    bool(item["inherit"]),
                )

        missing_ancestors: list[str] = []
        seen_missing: set[str] = set()
        new_candidate_ids: list[str] = []
        seen_candidate: set[str] = set()

        for item in batch_items:
            nid = item["id"]
            parent_id: str | None = item["parent_id"]
            if (
                parent_id is not None
                and parent_id not in self._node_meta
                and parent_id not in seen_missing
            ):
                seen_missing.add(parent_id)
                missing_ancestors.append(parent_id)

            if self._check_traverse and parent_id is not None:
                parent_state = self._dir_state_cache.get(parent_id)
                if parent_state is not None and not parent_state[0]:
                    continue

            if nid not in self._node_policies and nid not in seen_candidate:
                seen_candidate.add(nid)
                new_candidate_ids.append(nid)

        if not missing_ancestors and not new_candidate_ids:
            return

        remaining_candidates = new_candidate_ids
        cand_offset = 0

        if missing_ancestors:
            for anc_chunk in batched(missing_ancestors, QUERY_CHUNK_SIZE):
                anc_ids = list(anc_chunk)
                cand_budget = max(0, QUERY_CHUNK_SIZE - len(anc_ids))
                cand_slice = remaining_candidates[
                    cand_offset : cand_offset + cand_budget
                ]
                cand_offset += len(cand_slice)

                rows = self._session.execute(
                    _build_combined_ancestors_and_policies_stmt(
                        anc_ids, cand_slice, self._now_utc
                    )
                ).all()

                loaded_node_ids: set[str] = set(cand_slice)
                rule_rows: list[tuple[Any, ...]] = []
                for row in rows:
                    row_kind = row[0]
                    node_id = row[1]
                    if row_kind == 0:
                        loaded_node_ids.add(node_id)
                        if node_id not in self._node_meta:
                            self._node_meta[node_id] = (
                                row[2],
                                int(row[3]),
                                bool(row[4]),
                            )
                    rule_id = row[5]
                    if rule_id is not None:
                        rule_rows.append(
                            (
                                rule_id,
                                node_id,
                                row[6],
                                row[7],
                                row[8],
                                row[9],
                                row[10],
                                row[11],
                                row[12],
                                row[13],
                                row[14],
                                row[15],
                                row[16],
                            )
                        )

                rules_by_node = (
                    assemble_rules_from_joined_rows(rule_rows, canonicalize=False)
                    if rule_rows
                    else {}
                )
                for nid in loaded_node_ids:
                    if nid in self._node_policies:
                        continue
                    default_inherit = (
                        self._node_meta[nid][2] if nid in self._node_meta else True
                    )
                    self._node_policies[nid] = CompiledPolicy(
                        inherit=default_inherit,
                        rules=tuple(rules_by_node.get(nid, ())),
                    )

        leftover_candidates = [
            nid
            for nid in remaining_candidates[cand_offset:]
            if nid not in self._node_policies
        ]
        if leftover_candidates:
            preloaded_inherit = {
                nid: self._node_meta[nid][2]
                for nid in leftover_candidates
                if nid in self._node_meta
            }
            loaded = load_node_policies(
                self._session,
                leftover_candidates,
                include_deleted=True,
                preloaded_inherit=preloaded_inherit,
                active_at_utc=self._now_utc,
                canonicalize=False,
            )
            for nid in leftover_candidates:
                default_inherit = (
                    self._node_meta[nid][2] if nid in self._node_meta else True
                )
                self._node_policies[nid] = loaded.get(
                    nid, CompiledPolicy(inherit=default_inherit, rules=())
                )

    def _resolve_ancestor_dir(self, dir_id: str) -> tuple[bool, InheritedDaclState]:
        cached = self._dir_state_cache.get(dir_id)
        if cached is not None:
            return cached

        uncomputed: list[str] = []
        visited: set[str] = set()
        curr_id: str | None = dir_id
        while curr_id is not None and curr_id not in self._dir_state_cache:
            if curr_id in visited:
                raise RuntimeError(f"Cycle detected in folder hierarchy at {curr_id!r}")
            visited.add(curr_id)
            meta = self._node_meta.get(curr_id)
            if meta is None:
                break
            uncomputed.append(curr_id)
            curr_id = meta[0]

        if curr_id is not None and curr_id in self._dir_state_cache:
            traverse_ok, inherited = self._dir_state_cache[curr_id]
        else:
            traverse_ok, inherited = True, _EMPTY_INHERITED_STATE

        for nid in reversed(uncomputed):
            if self._check_traverse and not traverse_ok:
                self._dir_state_cache[nid] = (False, _EMPTY_INHERITED_STATE)
                continue
            _parent_id, status, inherit_flag = self._node_meta[nid]
            policy = self._node_policies.get(
                nid, CompiledPolicy(inherit=inherit_flag, rules=())
            )
            own_allow, own_deny, _, next_inherited = step_node_dacl(
                self._subject,
                policy,
                ObjectType.DIRECTORY,
                inherited,
                self._now_utc,
            )
            if self._check_traverse:
                eff_mask = own_allow & ~own_deny
                node_traverse_ok = (
                    traverse_ok
                    and status != EntityStatus.DELETED.value
                    and bool(eff_mask & _TRAVERSE_BIT)
                )
            else:
                node_traverse_ok = True
            self._dir_state_cache[nid] = (node_traverse_ok, next_inherited)
            traverse_ok, inherited = node_traverse_ok, next_inherited

        return self._dir_state_cache.get(dir_id, (False, _EMPTY_INHERITED_STATE))

    def is_visible(self, item: dict[str, Any]) -> bool:
        parent_id: str | None = item["parent_id"]
        if parent_id is not None:
            traverse_ok, parent_inherited = self._resolve_ancestor_dir(parent_id)
            if not traverse_ok:
                return False
        else:
            parent_inherited = _EMPTY_INHERITED_STATE

        nid: str = item["id"]
        is_dir = item["type"] == "directory"
        obj_type = ObjectType.DIRECTORY if is_dir else ObjectType.DOCUMENT
        policy = self._node_policies.get(
            nid, CompiledPolicy(inherit=bool(item["inherit"]), rules=())
        )
        own_allow, own_deny, _, _ = step_node_dacl(
            self._subject,
            policy,
            obj_type,
            parent_inherited,
            self._now_utc,
        )
        eff_mask = own_allow & ~own_deny
        required_mask = (
            DIRECTORY_VISIBILITY_MASK if is_dir else DOCUMENT_VISIBILITY_MASK
        )
        return bool(eff_mask & required_mask)


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
) -> list[dict[str, Any]]:
    if limit <= 0:
        return []

    needs_revision_in_sort = sort_by in ("size", "last_modified")
    bypass_dacl = has_bypass_dacl(user)

    if needs_revision_in_sort:
        candidates = _search_candidate_selectable(
            query=query,
            search_documents=search_documents,
            search_directories=search_directories,
        )
    else:
        candidates = _search_lightweight_candidate_selectable(
            query=query,
            search_documents=search_documents,
            search_directories=search_directories,
            require_active_document_revision=bypass_dacl,
        )
    if candidates is None:
        return []

    primary_column = _search_primary_column(candidates, sort_by)

    if bypass_dacl:
        raw_rows = _execute_search_batch(
            session,
            candidates,
            primary_column,
            last_key,
            sort_order,
            limit,
            include_revision_details=needs_revision_in_sort,
        )
        if needs_revision_in_sort or not search_documents:
            return [_finalize_search_item(row, sort_by) for row in raw_rows]
        return _hydrate_lightweight_search_rows(session, raw_rows, sort_by)

    now_utc = (
        datetime.datetime.fromtimestamp(now, tz=datetime.UTC)
        if isinstance(now, int | float)
        else now.astimezone(datetime.UTC)
    )
    evaluator = _SearchVisibilityEvaluator(
        session,
        user_to_subject(user),
        now_utc,
        check_traverse=should_check_ancestor_traverse(session, user),
    )

    visible_rows: list[dict[str, Any]] = []

    def _consume_rows(raw_rows: Sequence[dict[str, Any]]) -> None:
        for sub_chunk in batched(raw_rows, QUERY_CHUNK_SIZE):
            if len(visible_rows) >= limit:
                return
            chunk_list = list(sub_chunk)
            evaluator.ensure_loaded(chunk_list)

            if needs_revision_in_sort or not search_documents:
                for raw_item in chunk_list:
                    if evaluator.is_visible(raw_item):
                        visible_rows.append(_finalize_search_item(raw_item, sort_by))
                        if len(visible_rows) >= limit:
                            return
                continue

            pos = 0
            chunk_len = len(chunk_list)
            while pos < chunk_len and len(visible_rows) < limit:
                needed = limit - len(visible_rows)
                pending_visible: list[dict[str, Any]] = []
                while pos < chunk_len and len(pending_visible) < needed:
                    raw_item = chunk_list[pos]
                    pos += 1
                    if evaluator.is_visible(raw_item):
                        pending_visible.append(raw_item)
                if not pending_visible:
                    break
                visible_rows.extend(
                    _hydrate_lightweight_search_rows(session, pending_visible, sort_by)
                )

    probe_limit = max(limit * 2, 128)
    probe_rows = _execute_search_batch(
        session,
        candidates,
        primary_column,
        last_key,
        sort_order,
        probe_limit,
        include_revision_details=needs_revision_in_sort,
    )
    if not probe_rows:
        return []

    _consume_rows(probe_rows)
    if len(visible_rows) >= limit or len(probe_rows) < probe_limit:
        return visible_rows

    batch_last_key = _search_item_cursor_key(probe_rows[-1], sort_by)
    bind = session.get_bind()
    if bind is not None and bind.dialect.name == "sqlite":
        stream_query = _build_search_select(
            candidates,
            primary_column,
            batch_last_key,
            sort_order,
            include_revision_details=needs_revision_in_sort,
            limit=None,
        )
        result = session.execute(stream_query)
        try:
            mappings = result.mappings()
            while len(visible_rows) < limit:
                fetched = mappings.fetchmany(QUERY_CHUNK_SIZE)
                if not fetched:
                    break
                _consume_rows(
                    [{str(key): value for key, value in row.items()} for row in fetched]
                )
        finally:
            result.close()
        return visible_rows

    window_sizes = (2048, 8192)
    window_index = 0
    while len(visible_rows) < limit:
        window_limit = window_sizes[min(window_index, len(window_sizes) - 1)]
        window_index += 1
        raw_rows = _execute_search_batch(
            session,
            candidates,
            primary_column,
            batch_last_key,
            sort_order,
            window_limit,
            include_revision_details=needs_revision_in_sort,
        )
        if not raw_rows:
            break
        _consume_rows(raw_rows)
        if len(raw_rows) < window_limit:
            break
        batch_last_key = _search_item_cursor_key(raw_rows[-1], sort_by)

    return visible_rows
