from collections.abc import Iterable
from itertools import batched

from sqlalchemy import func
from sqlalchemy.orm import Session

from include.config.constants import MAX_PARAM_SIZE, QUERY_CHUNK_SIZE
from include.domains.documents.queries.file_references import count_file_references


def batch_count_other_revisions(
    session: Session,
    file_ids: Iterable[str],
    exclude_doc_ids: str | Iterable[str],
) -> dict[str, int]:
    """
    Return total references to each file EXCLUDING references from exclude_doc_ids.

    This centralizes counting via `count_file_references` so new FK references
    are automatically handled.

    Args:
        session: Database session.
        file_ids: File IDs to check.
        exclude_doc_ids: Document ID or IDs to exclude from count.

    Returns:
        Dict mapping file_id to reference count excluding specified documents.
    """
    # FIXME: Use lazy import when Python 3.15 is out
    from include.database.models.documents import DocumentRevision

    # Materialize iterables so they can be safely iterated multiple times.
    file_ids_list = list(file_ids)
    if not file_ids_list:
        return {}

    if isinstance(exclude_doc_ids, str):
        exclude_doc_ids_list = [exclude_doc_ids]
    else:
        exclude_doc_ids_list = list(exclude_doc_ids)

    # Get total references across all tables (uses reflected FKs).
    total_refs = count_file_references(session, file_ids_list)

    # Count references coming from the excluded documents (DocumentRevision only).
    # The query combines `file_id IN (...)` and `document_id IN (...)`, so both
    # dimensions must be chunked to keep total bind variables under MAX_PARAM_SIZE.
    exclude_chunk_size = max(1, MAX_PARAM_SIZE - QUERY_CHUNK_SIZE)
    excluded_counts: dict[str, int] = {}
    for f_chunk in batched(file_ids_list, QUERY_CHUNK_SIZE):
        for e_chunk in batched(exclude_doc_ids_list, exclude_chunk_size):
            rows = (
                session.query(DocumentRevision.file_id, func.count(DocumentRevision.id))
                .filter(DocumentRevision.file_id.in_(list(f_chunk)))
                .filter(DocumentRevision.document_id.in_(list(e_chunk)))
                .group_by(DocumentRevision.file_id)
                .all()
            )
            for file_id, count in rows:
                excluded_counts[file_id] = excluded_counts.get(file_id, 0) + count

    counts: dict[str, int] = {}
    for fid in file_ids_list:
        total = total_refs.get(fid, 0)
        excluded = excluded_counts.get(fid, 0)
        counts[fid] = max(0, total - excluded)

    return counts
