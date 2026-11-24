__all__ = [
    "active_revision_exists_for",
    "effective_active_revision_details_subquery",
    "fetch_active_revision_details_by_document",
    "fetch_latest_active_revisions_by_document",
]

from collections.abc import Callable, Mapping, Sequence
from itertools import batched
from typing import Any

from sqlalchemy import exists, func, literal, select, union_all
from sqlalchemy.orm import Session, joinedload, raiseload

from include.config.constants import QUERY_CHUNK_SIZE
from include.database.models.documents import Document, DocumentRevision, Node
from include.database.models.files import File


def active_revision_exists_for(document_id_column):
    """Return a SQL EXISTS predicate matching documents with at least one active revision file."""
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


def _build_active_revision_chain_cte(
    *,
    cte_name: str,
    rev_alias_name: str,
    file_alias_name: str,
    anchor_from: Any,
    passthrough_columns: Sequence[tuple[str, Any]],
    extra_columns: Callable[[Any, Any], Sequence[tuple[str, Any]]],
    anchor_where: Sequence[Any] = (),
):
    revision_table = DocumentRevision.__table__
    file_table = File.__table__

    anchor_cols: list[Any] = [col.label(name) for name, col in passthrough_columns]
    anchor_cols.extend(
        col.label(name) for name, col in extra_columns(revision_table, file_table)
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
    recursive_cols.extend(col for _, col in extra_columns(parent_rev, parent_file))
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


def _build_ranked_active_revisions_for_ids(
    document_ids: Sequence[str],
    *,
    extra_columns: Callable[[Any, Any], Sequence[Any]],
):
    revision_table = DocumentRevision.__table__
    file_table = File.__table__
    return (
        select(
            revision_table.c.document_id.label("document_id"),
            *extra_columns(revision_table, file_table),
            func.row_number()
            .over(
                partition_by=revision_table.c.document_id,
                order_by=revision_table.c.created_time.desc(),
            )
            .label("row_number"),
        )
        .select_from(
            revision_table.join(file_table, revision_table.c.file_id == file_table.c.id)
        )
        .where(
            file_table.c.active.is_(True),
            revision_table.c.document_id.in_(list(document_ids)),
        )
        .subquery()
    )


def _build_ranked_active_revisions_for_matched(
    matched_documents: Any,
    exclude_chain_cte: Any,
):
    rev_src = DocumentRevision.__table__.alias("search_fallback_rev")
    file_src = File.__table__.alias("search_fallback_file")
    return (
        select(
            matched_documents.c.id.label("id"),
            matched_documents.c.name.label("name"),
            matched_documents.c.parent_id.label("parent_id"),
            matched_documents.c.created_time.label("created_time"),
            matched_documents.c.inherit.label("inherit"),
            rev_src.c.created_time.label("last_modified"),
            file_src.c.size.label("size"),
            func.row_number()
            .over(
                partition_by=matched_documents.c.id,
                order_by=rev_src.c.created_time.desc(),
            )
            .label("row_number"),
        )
        .select_from(
            matched_documents.join(
                rev_src, matched_documents.c.id == rev_src.c.document_id
            ).join(file_src, rev_src.c.file_id == file_src.c.id)
        )
        .where(
            file_src.c.active.is_(True),
            ~exists(
                select(1).where(
                    exclude_chain_cte.c.document_id == matched_documents.c.id,
                    exclude_chain_cte.c.file_active.is_(True),
                )
            ),
        )
        .subquery()
    )


def fetch_latest_active_revisions_by_document(
    session: Session, document_ids: list[str]
) -> dict[str, DocumentRevision]:
    """Batch-resolve each document's effective latest active DocumentRevision."""
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
            extra_columns=lambda rev, _file_tbl: (("revision_id", rev.c.id),),
            anchor_where=(document_table.c.id.in_(chunk_ids),),
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

        active_revisions = _build_ranked_active_revisions_for_ids(
            fallback_document_ids,
            extra_columns=lambda rev, _file_tbl: (rev.c.id.label("revision_id"),),
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


def effective_active_revision_details_subquery(document_filters: Sequence[Any]):
    """Build a subquery yielding active revision size/last_modified for matched documents."""
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
        extra_columns=lambda rev, file_tbl: (
            ("revision_created_time", rev.c.created_time),
            ("file_size", file_tbl.c.size),
        ),
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

    fallback_ranked = _build_ranked_active_revisions_for_matched(
        matched_documents,
        current_chain,
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


def _resolve_direct_current_revision_details(
    session: Session,
    doc_current_rev_ids: Mapping[str, str | None],
) -> tuple[dict[str, tuple[float, int | None]], dict[str, str]]:
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

    return details_by_doc, inactive_parent_revs


def _resolve_parent_chain_revision_details(
    session: Session,
    inactive_parent_revs: Mapping[str, str],
    details_by_doc: dict[str, tuple[float, int | None]],
) -> None:
    if not inactive_parent_revs:
        return
    revision_table = DocumentRevision.__table__
    file_table = File.__table__
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
            extra_columns=lambda rev, file_tbl: (
                ("revision_created_time", rev.c.created_time),
                ("file_size", file_tbl.c.size),
            ),
            anchor_where=(revision_table.c.id.in_(list(chunk)),),
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


def _resolve_fallback_revision_details(
    session: Session,
    fallback_doc_ids: Sequence[str],
    details_by_doc: dict[str, tuple[float, int | None]],
) -> None:
    if not fallback_doc_ids:
        return
    for chunk in batched(fallback_doc_ids, QUERY_CHUNK_SIZE):
        ranked = _build_ranked_active_revisions_for_ids(
            list(chunk),
            extra_columns=lambda rev, file_tbl: (
                rev.c.created_time.label("last_modified"),
                file_tbl.c.size.label("size"),
            ),
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


def fetch_active_revision_details_by_document(
    session: Session,
    doc_current_rev_ids: Mapping[str, str | None],
) -> dict[str, tuple[float, int | None]]:
    """Resolve (last_modified, size) for active documents via current_revision_id fast path."""
    if not doc_current_rev_ids:
        return {}

    details_by_doc, inactive_parent_revs = _resolve_direct_current_revision_details(
        session, doc_current_rev_ids
    )
    _resolve_parent_chain_revision_details(
        session, inactive_parent_revs, details_by_doc
    )
    fallback_doc_ids = [
        doc_id for doc_id in doc_current_rev_ids if doc_id not in details_by_doc
    ]
    _resolve_fallback_revision_details(session, fallback_doc_ids, details_by_doc)
    return details_by_doc
