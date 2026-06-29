from itertools import batched
from typing import List

from sqlalchemy.orm import Session

from include.config.constants import QUERY_CHUNK_SIZE
from include.database.models.documents import (
    Document,
    DocumentAccessRule,
    DocumentRevision,
)
from include.database.models.files import (
    File,
    FileTask,
    _queue_deferred_file_deletion,
)
from include.domains.documents.queries.revisions import batch_count_other_revisions


def purge_documents_bulk(session: Session, document_ids: List[str]):
    """
    Purge many documents using batched deletes.

    This converts hundreds of per-document deletes into a small set of bulk
    operations across all target documents.
    """
    if not document_ids:
        return

    # 1. Fetch affected revision IDs and file IDs in chunks to avoid bind limits.
    revision_data = []
    for chunk in batched(document_ids, QUERY_CHUNK_SIZE):
        revision_data.extend(
            session.query(DocumentRevision.id, DocumentRevision.file_id)
            .filter(DocumentRevision.document_id.in_(list(chunk)))
            .all()
        )

    if not revision_data:
        # If none of these documents have revisions, delete document rows only.
        for chunk in batched(document_ids, QUERY_CHUNK_SIZE):
            session.query(DocumentAccessRule).filter(
                DocumentAccessRule.document_id.in_(chunk)
            ).delete(synchronize_session=False)
        for chunk in batched(document_ids, QUERY_CHUNK_SIZE):
            session.query(Document).filter(Document.id.in_(chunk)).delete(
                synchronize_session=False
            )
        return

    rev_ids = [r[0] for r in revision_data]
    file_ids = {r[1] for r in revision_data if r[1]}

    # 2. Count references in bulk. Files with no remaining external references
    # can be deleted.
    other_counts = batch_count_other_revisions(session, list(file_ids), document_ids)

    # Find files referenced only by this batch and eligible for physical delete.
    deletable_file_ids = [fid for fid in file_ids if other_counts.get(fid, 0) == 0]

    # 3. Delete in bulk using SQL-level deletes under no_autoflush.

    # 3a. Clear document-to-revision and revision-to-revision FK references.
    for chunk in batched(document_ids, QUERY_CHUNK_SIZE):
        session.query(Document).filter(Document.id.in_(chunk)).update(
            {Document.current_revision_id: None}, synchronize_session=False
        )

    for chunk in batched(rev_ids, QUERY_CHUNK_SIZE):
        session.query(DocumentRevision).filter(DocumentRevision.id.in_(chunk)).update(
            {DocumentRevision.parent_revision_id: None}, synchronize_session=False
        )

    # 3b. Clean up related tasks.
    if deletable_file_ids:
        for chunk in batched(deletable_file_ids, QUERY_CHUNK_SIZE):
            session.query(FileTask).filter(FileTask.file_id.in_(chunk)).delete(
                synchronize_session=False
            )

    # 3c. Collect file paths. File rows must be deleted after revisions.
    deletable_files = []
    if deletable_file_ids:
        for chunk in batched(deletable_file_ids, QUERY_CHUNK_SIZE):
            deletable_files.extend(session.query(File).filter(File.id.in_(chunk)).all())

    # 3d. Delete revisions, files, and documents in bulk.
    for chunk in batched(rev_ids, QUERY_CHUNK_SIZE):
        session.query(DocumentRevision).filter(DocumentRevision.id.in_(chunk)).delete(
            synchronize_session=False
        )

    if deletable_files:
        for f in deletable_files:
            _queue_deferred_file_deletion(session, f.path)

        deletable_file_ids = [f.id for f in deletable_files]
        for chunk in batched(deletable_file_ids, QUERY_CHUNK_SIZE):
            session.query(File).filter(File.id.in_(chunk)).delete(
                synchronize_session=False
            )

    for chunk in batched(document_ids, QUERY_CHUNK_SIZE):
        session.query(DocumentAccessRule).filter(
            DocumentAccessRule.document_id.in_(chunk)
        ).delete(synchronize_session=False)
        session.query(Document).filter(Document.id.in_(chunk)).delete(
            synchronize_session=False
        )
