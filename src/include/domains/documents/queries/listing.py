import datetime
from itertools import batched
from typing import Any
lazy from collections.abc import Sequence

from cacl_compiler import AtomicOp
from sqlalchemy import (
    and_,
    exists,
    false,
    func,
    literal,
    not_,
    or_,
    select,
    true,
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
)
from include.database.models.files import File
from include.domains.access.authorization.evaluation import (
    has_bypass_dacl,
    should_check_ancestor_traverse,
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


def _active_revision_exists():
    return exists(
        select(1)
        .select_from(DocumentRevision)
        .join(File, DocumentRevision.file_id == File.id)
        .where(DocumentRevision.document_id == Document.id, File.active.is_(True))
    )


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
            )
            .select_from(
                current_chain.join(
                    parent_revision,
                    current_chain.c.parent_revision_id == parent_revision.c.id,
                ).join(parent_file, parent_revision.c.file_id == parent_file.c.id)
            )
            .where(current_chain.c.file_active.is_(False))
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
        )
        .select_from(
            current_chain.join(
                parent_revision,
                current_chain.c.parent_revision_id == parent_revision.c.id,
            ).join(parent_file, parent_revision.c.file_id == parent_file.c.id)
        )
        .where(current_chain.c.file_active.is_(False))
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
            matched_documents.c.name.label("name"),
            func.lower(matched_documents.c.name).label("name_sort_key"),
            matched_documents.c.parent_id.label("parent_id"),
            matched_documents.c.created_time.label("created_time"),
            matched_documents.c.inherit.label("inherit"),
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


def _in_values(column, values: Sequence[str]):
    if not values:
        return false()
    return column.in_(list(values))


def _sql_rule_matches_subject(
    rule_table,
    user_id_str: str,
    user_groups: Sequence[str],
    user_perms: Sequence[str],
):
    atom_matches_positive = or_(
        and_(
            NodeDaclAtom.predicate_kind == "user",
            NodeDaclAtom.predicate_value == user_id_str,
        ),
        and_(
            NodeDaclAtom.predicate_kind == "group",
            _in_values(NodeDaclAtom.predicate_value, user_groups),
        ),
        and_(
            NodeDaclAtom.predicate_kind == "perm",
            _in_values(NodeDaclAtom.predicate_value, user_perms),
        ),
    )
    atom_fails = or_(
        and_(NodeDaclAtom.is_negated == False, not_(atom_matches_positive)),
        and_(NodeDaclAtom.is_negated == True, atom_matches_positive),
    )
    return exists(
        select(1).where(
            NodeDaclClause.rule_id == rule_table.c.id,
            not_(
                exists(
                    select(1).where(
                        NodeDaclAtom.clause_id == NodeDaclClause.id,
                        atom_fails,
                    )
                )
            ),
        )
    )


def _sql_chain_op_allowed(
    chain_cte,
    *,
    target_id_col,
    target_type_expr,
    op_bit: int,
    now_utc: datetime.datetime,
    user_id_str: str,
    user_groups: Sequence[str],
    user_perms: Sequence[str],
    match_target_type_on_chain: bool,
):
    def _effect_exists(effect: str):
        rule_tbl = NodeDaclRule.__table__.alias(f"cacl_r_{effect}_{op_bit}")
        chain_filters = [chain_cte.c.target_id == target_id_col]
        if match_target_type_on_chain:
            chain_filters.append(chain_cte.c.target_type == target_type_expr)
        scope_match = or_(
            rule_tbl.c.scope == "all",
            and_(rule_tbl.c.scope == "self", chain_cte.c.distance == 0),
            and_(rule_tbl.c.scope == "dirs", target_type_expr == "directory"),
            and_(rule_tbl.c.scope == "docs", target_type_expr == "document"),
        )
        return exists(
            select(1)
            .select_from(
                chain_cte.join(rule_tbl, rule_tbl.c.node_id == chain_cte.c.origin_id)
            )
            .where(
                *chain_filters,
                rule_tbl.c.effect == effect,
                rule_tbl.c.permission_mask.op("&")(op_bit) != 0,
                scope_match,
                or_(
                    rule_tbl.c.valid_from.is_(None),
                    rule_tbl.c.valid_from <= now_utc,
                ),
                or_(
                    rule_tbl.c.valid_until.is_(None),
                    rule_tbl.c.valid_until > now_utc,
                ),
                _sql_rule_matches_subject(
                    rule_tbl, user_id_str, user_groups, user_perms
                ),
            )
        )

    return and_(_effect_exists("allow"), not_(_effect_exists("deny")))


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
                literal(None).label("last_modified"),
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


def _search_effective_chain_cte(candidates):
    node_table = Node.__table__
    anchor = select(
        candidates.c.type.label("target_type"),
        candidates.c.id.label("target_id"),
        candidates.c.id.label("origin_id"),
        literal(0).label("distance"),
        candidates.c.parent_id.label("parent_id"),
        candidates.c.inherit.label("inherit"),
    )
    chain = anchor.cte("search_effective_chain", recursive=True)
    parent_node = node_table.alias("search_eff_parent")
    chain = chain.union_all(
        select(
            chain.c.target_type,
            chain.c.target_id,
            parent_node.c.id,
            (chain.c.distance + 1).label("distance"),
            parent_node.c.parent_id,
            parent_node.c.inherit,
        )
        .select_from(chain.join(parent_node, parent_node.c.id == chain.c.parent_id))
        .where(chain.c.inherit == True, chain.c.parent_id.is_not(None))
    )
    return chain


def _search_all_ancestors_cte(candidates):
    node_table = Node.__table__
    parent_anchor = node_table.alias("search_anc_seed")
    anchor = (
        select(
            candidates.c.type.label("target_type"),
            candidates.c.id.label("target_id"),
            parent_anchor.c.id.label("ancestor_id"),
            parent_anchor.c.parent_id.label("parent_id"),
            parent_anchor.c.status.label("ancestor_status"),
            parent_anchor.c.inherit.label("ancestor_inherit"),
        )
        .select_from(
            candidates.join(parent_anchor, parent_anchor.c.id == candidates.c.parent_id)
        )
        .where(candidates.c.parent_id.is_not(None))
    )
    ancestors = anchor.cte("search_all_ancestors", recursive=True)
    parent_step = node_table.alias("search_anc_step")
    ancestors = ancestors.union_all(
        select(
            ancestors.c.target_type,
            ancestors.c.target_id,
            parent_step.c.id,
            parent_step.c.parent_id,
            parent_step.c.status,
            parent_step.c.inherit,
        )
        .select_from(
            ancestors.join(parent_step, parent_step.c.id == ancestors.c.parent_id)
        )
        .where(ancestors.c.parent_id.is_not(None))
    )
    return ancestors


def _ancestor_effective_chain_cte(all_ancestors_cte):
    node_table = Node.__table__
    distinct_ancestors = select(
        all_ancestors_cte.c.ancestor_id.label("target_id"),
        all_ancestors_cte.c.ancestor_id.label("origin_id"),
        literal(0).label("distance"),
        all_ancestors_cte.c.parent_id.label("parent_id"),
        all_ancestors_cte.c.ancestor_inherit.label("inherit"),
    ).distinct()
    chain = distinct_ancestors.cte("search_anc_effective_chain", recursive=True)
    parent_node = node_table.alias("search_anc_eff_parent")
    chain = chain.union_all(
        select(
            chain.c.target_id,
            parent_node.c.id,
            (chain.c.distance + 1).label("distance"),
            parent_node.c.parent_id,
            parent_node.c.inherit,
        )
        .select_from(chain.join(parent_node, parent_node.c.id == chain.c.parent_id))
        .where(chain.c.inherit == True, chain.c.parent_id.is_not(None))
    )
    return chain


def _visible_search_filter(
    session,
    candidates,
    user: User,
    now_utc: datetime.datetime,
):
    if has_bypass_dacl(user):
        return true()

    user_id_str = str(user.id)
    user_groups = list(user.all_groups)
    user_perms = [str(permission) for permission in user.all_permissions]

    effective_chain = _search_effective_chain_cte(candidates)

    dir_visible = and_(
        candidates.c.type == "directory",
        or_(
            _sql_chain_op_allowed(
                effective_chain,
                target_id_col=candidates.c.id,
                target_type_expr=candidates.c.type,
                op_bit=int(AtomicOp.LIST_DIRECTORY),
                now_utc=now_utc,
                user_id_str=user_id_str,
                user_groups=user_groups,
                user_perms=user_perms,
                match_target_type_on_chain=True,
            ),
            _sql_chain_op_allowed(
                effective_chain,
                target_id_col=candidates.c.id,
                target_type_expr=candidates.c.type,
                op_bit=int(AtomicOp.READ_METADATA),
                now_utc=now_utc,
                user_id_str=user_id_str,
                user_groups=user_groups,
                user_perms=user_perms,
                match_target_type_on_chain=True,
            ),
        ),
    )
    doc_visible = and_(
        candidates.c.type == "document",
        or_(
            _sql_chain_op_allowed(
                effective_chain,
                target_id_col=candidates.c.id,
                target_type_expr=candidates.c.type,
                op_bit=int(AtomicOp.READ_CONTENT),
                now_utc=now_utc,
                user_id_str=user_id_str,
                user_groups=user_groups,
                user_perms=user_perms,
                match_target_type_on_chain=True,
            ),
            _sql_chain_op_allowed(
                effective_chain,
                target_id_col=candidates.c.id,
                target_type_expr=candidates.c.type,
                op_bit=int(AtomicOp.READ_METADATA),
                now_utc=now_utc,
                user_id_str=user_id_str,
                user_groups=user_groups,
                user_perms=user_perms,
                match_target_type_on_chain=True,
            ),
        ),
    )
    target_visible = or_(dir_visible, doc_visible)

    if not should_check_ancestor_traverse(session, user):
        return target_visible

    all_ancestors = _search_all_ancestors_cte(candidates)
    anc_eff_chain = _ancestor_effective_chain_cte(all_ancestors)
    blocked_ancestor = exists(
        select(1).where(
            all_ancestors.c.target_type == candidates.c.type,
            all_ancestors.c.target_id == candidates.c.id,
            or_(
                all_ancestors.c.ancestor_status == EntityStatus.DELETED.value,
                not_(
                    _sql_chain_op_allowed(
                        anc_eff_chain,
                        target_id_col=all_ancestors.c.ancestor_id,
                        target_type_expr=literal("directory"),
                        op_bit=int(AtomicOp.TRAVERSE),
                        now_utc=now_utc,
                        user_id_str=user_id_str,
                        user_groups=user_groups,
                        user_perms=user_perms,
                        match_target_type_on_chain=False,
                    )
                ),
            ),
        )
    )
    return and_(target_visible, not_(blocked_ancestor))


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
    candidates = _search_candidate_selectable(
        query=query,
        search_documents=search_documents,
        search_directories=search_directories,
    )
    if candidates is None:
        return []

    now_utc = (
        datetime.datetime.fromtimestamp(now, tz=datetime.UTC)
        if isinstance(now, int | float)
        else now.astimezone(datetime.UTC)
    )

    primary_column = _search_primary_column(candidates, sort_by)
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
    ).where(_visible_search_filter(session, candidates, user, now_utc))
    cursor_filter = _apply_search_cursor_filter(
        candidates, primary_column, last_key, sort_order
    )
    if cursor_filter is not None:
        search_query = search_query.where(cursor_filter)
    search_query = search_query.order_by(
        *_search_ordering(candidates, primary_column, sort_order)
    ).limit(limit)

    rows: list[dict[str, Any]] = []
    for row in session.execute(search_query).mappings():
        item = {str(key): value for key, value in row.items()}
        item[_CURSOR_KEY] = _search_item_cursor_key(item, sort_by)
        item.pop("name_sort_key", None)
        item.pop("inherit", None)
        if item["type"] == "directory":
            item.pop("last_modified", None)
            item.pop("size", None)
        rows.append(item)
    return rows
