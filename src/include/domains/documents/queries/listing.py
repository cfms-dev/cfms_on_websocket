import datetime
from itertools import batched
from typing import Any
lazy from collections.abc import Sequence

from cacl_compiler import AtomicOp, CompiledPolicy, ObjectType
from sqlalchemy import (
    and_,
    exists,
    func,
    literal,
    or_,
    select,
    union_all,
)
from sqlalchemy.orm import joinedload, raiseload

from include.config.constants import QUERY_CHUNK_SIZE
from include.database.models.documents import (
    Document,
    DocumentRevision,
    EntityStatus,
    Folder,
    Node,
)
from include.database.models.files import File
from include.domains.access.authorization.engine import (
    InheritedDaclState,
    Subject,
    step_node_dacl,
)
from include.domains.access.authorization.evaluation import (
    has_bypass_dacl,
    should_check_ancestor_traverse,
    user_to_subject,
)
from include.domains.access.authorization.storage import load_node_policies
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


_DIR_VISIBLE_MASK = int(AtomicOp.LIST_DIRECTORY | AtomicOp.READ_METADATA)
_DOC_VISIBLE_MASK = int(AtomicOp.READ_CONTENT | AtomicOp.READ_METADATA)
_TRAVERSE_BIT = int(AtomicOp.TRAVERSE)
_EMPTY_INHERITED_STATE = InheritedDaclState()


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
        missing_ancestors: list[str] = []
        seen_missing: set[str] = set()
        new_policy_ids: list[str] = []
        seen_policy: set[str] = set()

        for item in batch_items:
            nid: str = item["id"]
            parent_id: str | None = item["parent_id"]
            if nid not in self._node_meta:
                self._node_meta[nid] = (
                    parent_id,
                    EntityStatus.OK.value,
                    bool(item["inherit"]),
                )
            if nid not in self._node_policies and nid not in seen_policy:
                seen_policy.add(nid)
                new_policy_ids.append(nid)
            if (
                parent_id is not None
                and parent_id not in self._node_meta
                and parent_id not in seen_missing
            ):
                seen_missing.add(parent_id)
                missing_ancestors.append(parent_id)

        if missing_ancestors:
            node_table = Node.__table__
            for chunk in batched(missing_ancestors, QUERY_CHUNK_SIZE):
                chunk_ids = list(chunk)
                anchor = select(
                    node_table.c.id.label("id"),
                    node_table.c.parent_id.label("parent_id"),
                    node_table.c.status.label("status"),
                    node_table.c.inherit.label("inherit"),
                    literal(0).label("depth"),
                ).where(node_table.c.id.in_(chunk_ids))
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
                        ancestors.join(
                            parent_node, parent_node.c.id == ancestors.c.parent_id
                        )
                    )
                    .where(ancestors.c.parent_id.is_not(None), ancestors.c.depth < 128)
                )
                rows = self._session.execute(
                    select(
                        ancestors.c.id,
                        ancestors.c.parent_id,
                        ancestors.c.status,
                        ancestors.c.inherit,
                    ).distinct()
                ).all()
                for nid, parent_id, status, inherit_flag in rows:
                    if nid not in self._node_meta:
                        self._node_meta[nid] = (
                            parent_id,
                            int(status),
                            bool(inherit_flag),
                        )
                    if nid not in self._node_policies and nid not in seen_policy:
                        seen_policy.add(nid)
                        new_policy_ids.append(nid)

        if new_policy_ids:
            preloaded_inherit = {
                nid: self._node_meta[nid][2]
                for nid in new_policy_ids
                if nid in self._node_meta
            }
            loaded = load_node_policies(
                self._session,
                new_policy_ids,
                include_deleted=True,
                preloaded_inherit=preloaded_inherit,
                active_at_utc=self._now_utc,
                canonicalize=False,
            )
            for nid in new_policy_ids:
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
        required_mask = _DIR_VISIBLE_MASK if is_dir else _DOC_VISIBLE_MASK
        return bool(eff_mask & required_mask)


def _execute_search_batch(
    session,
    candidates,
    primary_column,
    last_key: list[Any] | None,
    sort_order: str,
    limit: int,
) -> list[dict[str, Any]]:
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
    cursor_filter = _apply_search_cursor_filter(
        candidates, primary_column, last_key, sort_order
    )
    if cursor_filter is not None:
        search_query = search_query.where(cursor_filter)
    search_query = search_query.order_by(
        *_search_ordering(candidates, primary_column, sort_order)
    ).limit(limit)
    return [
        {str(key): value for key, value in row.items()}
        for row in session.execute(search_query).mappings()
    ]


def _finalize_search_item(raw_item: dict[str, Any], sort_by: str) -> dict[str, Any]:
    item = dict(raw_item)
    item[_CURSOR_KEY] = _search_item_cursor_key(raw_item, sort_by)
    item.pop("name_sort_key", None)
    item.pop("inherit", None)
    if item["type"] == "directory":
        item.pop("last_modified", None)
        item.pop("size", None)
    return item


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

    candidates = _search_candidate_selectable(
        query=query,
        search_documents=search_documents,
        search_directories=search_directories,
    )
    if candidates is None:
        return []

    primary_column = _search_primary_column(candidates, sort_by)

    if has_bypass_dacl(user):
        raw_rows = _execute_search_batch(
            session, candidates, primary_column, last_key, sort_order, limit
        )
        return [_finalize_search_item(row, sort_by) for row in raw_rows]

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

    batch_sizes = (max(limit * 2, 128), 512, 2048, 4096)
    batch_index = 0
    batch_last_key = last_key
    visible_rows: list[dict[str, Any]] = []

    while len(visible_rows) < limit:
        batch_limit = batch_sizes[min(batch_index, len(batch_sizes) - 1)]
        batch_index += 1
        raw_rows = _execute_search_batch(
            session,
            candidates,
            primary_column,
            batch_last_key,
            sort_order,
            batch_limit,
        )
        if not raw_rows:
            break

        evaluator.ensure_loaded(raw_rows)
        for raw_item in raw_rows:
            if evaluator.is_visible(raw_item):
                visible_rows.append(_finalize_search_item(raw_item, sort_by))
                if len(visible_rows) >= limit:
                    break

        if len(raw_rows) < batch_limit:
            break
        batch_last_key = _search_item_cursor_key(raw_rows[-1], sort_by)

    return visible_rows
