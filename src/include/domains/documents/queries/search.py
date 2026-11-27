__all__ = [
    "SearchQuerySpec",
    "fetch_visible_search_candidate_rows",
    "search_cursor_key",
]

import datetime
from collections.abc import Sequence
from contextlib import closing
from dataclasses import dataclass
from itertools import batched
from typing import Any

from cacl_compiler import ObjectType
from sqlalchemy import (
    and_,
    case,
    func,
    literal,
    null,
    or_,
    select,
    union_all,
)
from sqlalchemy.orm import Session

from include.config.constants import QUERY_CHUNK_SIZE, ROOT_DIRECTORY_ID
from include.database.cursors import KeysetBatchStrategy, default_keyset_batch_strategy
from include.database.models.documents import (
    Document,
    EntityStatus,
    Folder,
    Node,
    NodeType,
)
from include.database.models.identity import User
from include.domains.access.authorization.engine import ObjectState
from include.domains.access.authorization.evaluation import (
    _ALL_OPS_MASK,
    global_gate_ops_mask,
    has_bypass_dacl,
    project_effective_mask,
)
from include.domains.access.authorization.visibility import (
    BatchVisibilityEvaluator,
    VisibilityCandidate,
)
from include.domains.documents.queries.active_revisions import (
    active_revision_exists_for,
    effective_active_revision_details_subquery,
    fetch_active_revision_details_by_document,
)

_CURSOR_KEY = "_cursor_key"
_SEARCH_PROBE_MULTIPLIER = 2
_SEARCH_MIN_PROBE_LIMIT = 128


@dataclass(frozen=True, slots=True)
class SearchQuerySpec:
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


def _search_cursor_primary_value(item: dict[str, Any], sort_by: str) -> Any:
    match sort_by:
        case "name":
            primary = item.get("name_sort_key")
            return item["name"].lower() if primary is None else primary
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


def _search_item_cursor_key(item: dict[str, Any], sort_by: str) -> list[Any]:
    return [_search_cursor_primary_value(item, sort_by), item["type_rank"], item["id"]]


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


def _build_combined_lightweight_candidates(
    *,
    query: str,
    require_active_document_revision: bool,
):
    node_table = Node.__table__
    folder_table = Folder.__table__
    document_table = Document.__table__
    filters: list[Any] = [
        node_table.c.status != EntityStatus.DELETED,
        node_table.c.name.icontains(query, autoescape=True),
        node_table.c.type.in_((NodeType.DIRECTORY.value, NodeType.DOCUMENT.value)),
    ]
    if require_active_document_revision:
        filters.append(
            or_(
                node_table.c.type == NodeType.DIRECTORY.value,
                active_revision_exists_for(document_table.c.id),
            )
        )
    return (
        select(
            node_table.c.id.label("id"),
            node_table.c.name.label("name"),
            func.lower(node_table.c.name).label("name_sort_key"),
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


def _build_directory_lightweight_candidates(*, query: str):
    node_table = Node.__table__
    folder_table = Folder.__table__
    return (
        select(
            node_table.c.id.label("id"),
            node_table.c.name.label("name"),
            func.lower(node_table.c.name).label("name_sort_key"),
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


def _build_document_lightweight_candidates(
    *,
    query: str,
    require_active_document_revision: bool,
):
    node_table = Node.__table__
    document_table = Document.__table__
    doc_filters: list[Any] = [
        node_table.c.status != EntityStatus.DELETED,
        node_table.c.name.icontains(query, autoescape=True),
    ]
    if require_active_document_revision:
        doc_filters.append(active_revision_exists_for(document_table.c.id))
    return (
        select(
            node_table.c.id.label("id"),
            node_table.c.name.label("name"),
            func.lower(node_table.c.name).label("name_sort_key"),
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


def _search_lightweight_candidate_selectable(
    *,
    query: str,
    search_documents: bool,
    search_directories: bool,
    require_active_document_revision: bool,
):
    if search_directories and search_documents:
        return _build_combined_lightweight_candidates(
            query=query,
            require_active_document_revision=require_active_document_revision,
        )
    if search_directories:
        return _build_directory_lightweight_candidates(query=query)
    if search_documents:
        return _build_document_lightweight_candidates(
            query=query,
            require_active_document_revision=require_active_document_revision,
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
        document_details = effective_active_revision_details_subquery(
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
    session: Session,
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
    item.pop("type_rank", None)
    item.pop("inherit", None)
    item.pop("current_revision_id", None)
    if item["type"] == "directory":
        item.pop("last_modified", None)
        item.pop("size", None)
    return item


def _hydrate_lightweight_search_rows(
    session: Session,
    raw_rows: Sequence[dict[str, Any]],
    sort_by: str,
) -> list[dict[str, Any]]:
    doc_current_rev_ids = {
        row["id"]: row.get("current_revision_id")
        for row in raw_rows
        if row["type"] == "document"
    }
    rev_details = (
        fetch_active_revision_details_by_document(session, doc_current_rev_ids)
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
        session: Session,
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
                    status=EntityStatus.OK.value,
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
            effective_mask = self._evaluator.evaluate_visible_effective_mask(candidate)
            if effective_mask is not None:
                raw_item["effective_mask"] = effective_mask
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
                effective_mask = self._evaluator.evaluate_visible_effective_mask(
                    candidate
                )
                if effective_mask is not None:
                    raw_item["effective_mask"] = effective_mask
                    pending_visible.append(raw_item)
            if not pending_visible:
                break
            self.visible_rows.extend(
                _hydrate_lightweight_search_rows(
                    self._session, pending_visible, self._sort_by
                )
            )


def _resolve_search_candidates(spec: SearchQuerySpec, *, bypass_dacl: bool):
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
    session: Session,
    candidates,
    primary_column,
    spec: SearchQuerySpec,
    *,
    user: User,
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
    global_mask = global_gate_ops_mask(user)
    dir_mask = project_effective_mask(
        _ALL_OPS_MASK,
        object_type=ObjectType.DIRECTORY,
        state=ObjectState.NORMAL,
        global_mask=global_mask,
    )
    root_mask = project_effective_mask(
        _ALL_OPS_MASK,
        object_type=ObjectType.DIRECTORY,
        state=ObjectState.NORMAL,
        global_mask=global_mask,
        is_root=True,
    )
    doc_mask = project_effective_mask(
        _ALL_OPS_MASK,
        object_type=ObjectType.DOCUMENT,
        state=ObjectState.NORMAL,
        global_mask=global_mask,
    )
    for row in raw_rows:
        if row["type"] == "directory":
            row["effective_mask"] = (
                root_mask if row["id"] == ROOT_DIRECTORY_ID else dir_mask
            )
        else:
            row["effective_mask"] = doc_mask
    if spec.needs_revision_in_sort or not spec.search_documents:
        return [_finalize_search_item(row, spec.sort_by) for row in raw_rows]
    return _hydrate_lightweight_search_rows(session, raw_rows, spec.sort_by)


def _fetch_filtered_search_rows(
    session: Session,
    candidates,
    primary_column,
    spec: SearchQuerySpec,
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
    session: Session,
    spec: SearchQuerySpec,
    *,
    user: User,
    now: datetime.datetime | float,
    batch_strategy: KeysetBatchStrategy | None = None,
) -> list[dict[str, Any]]:
    """Query search candidates matching spec and filter them by CACL visibility."""
    if spec.limit <= 0:
        return []

    bypass_dacl = has_bypass_dacl(user)
    candidates = _resolve_search_candidates(spec, bypass_dacl=bypass_dacl)
    if candidates is None:
        return []

    primary_column = _search_primary_column(candidates, spec.sort_by)
    if bypass_dacl:
        return _fetch_bypass_search_rows(
            session, candidates, primary_column, spec, user=user
        )

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
