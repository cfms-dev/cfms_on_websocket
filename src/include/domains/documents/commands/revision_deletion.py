from itertools import batched

from sqlalchemy import select
from sqlalchemy.orm import Session

from include.config.constants import QUERY_CHUNK_SIZE
from include.database.models.documents import Document, DocumentRevision
from include.database.models.files import (
    File,
    FileTask,
    _queue_deferred_file_deletion,
)
from include.domains.documents.queries.file_references import count_file_references
from include.domains.documents.queries.revisions import batch_count_other_revisions


def delete_revision_and_unreferenced_file(
    session: Session, revision: DocumentRevision
) -> None:
    if revision.file_id:
        total = count_file_references(session, [revision.file_id]).get(
            revision.file_id, 0
        )
        if max(0, total - 1) == 0:
            revision.file.delete()
            session.delete(revision.file)
    session.delete(revision)


def delete_all_document_revisions(session: Session, document: Document) -> None:
    revision_tuples = session.execute(
        select(DocumentRevision.id, DocumentRevision.file_id).where(
            DocumentRevision.document_id == document.id
        )
    ).all()
    if not revision_tuples:
        return

    revision_ids = [row[0] for row in revision_tuples]
    all_file_ids = {row[1] for row in revision_tuples if row[1]}
    other_counts = batch_count_other_revisions(session, all_file_ids, document.id)
    deletable_file_ids = {
        file_id for file_id in all_file_ids if other_counts.get(file_id, 0) == 0
    }

    files_to_delete: list[File] = []
    for chunk in batched(deletable_file_ids, QUERY_CHUNK_SIZE):
        files_to_delete.extend(
            session.scalars(select(File).where(File.id.in_(list(chunk)))).all()
        )

    document.current_revision_id = None
    document.current_revision = None

    with session.no_autoflush:
        upload_sessions_by_file: dict[str, list[str]] = {}
        for chunk in batched(deletable_file_ids, QUERY_CHUNK_SIZE):
            chunk_ids = list(chunk)
            for file_id, upload_session_id in session.execute(
                select(FileTask.file_id, FileTask.upload_session_id).where(
                    FileTask.file_id.in_(chunk_ids),
                    FileTask.upload_session_id.is_not(None),
                )
            ):
                if upload_session_id is not None:
                    upload_sessions_by_file.setdefault(file_id, []).append(
                        upload_session_id
                    )
            session.query(FileTask).filter(FileTask.file_id.in_(chunk_ids)).delete(
                synchronize_session=False
            )

        revisions: list[DocumentRevision] = []
        for chunk in batched(revision_ids, QUERY_CHUNK_SIZE):
            revisions.extend(
                session.scalars(
                    select(DocumentRevision).where(DocumentRevision.id.in_(list(chunk)))
                ).all()
            )

        for revision in revisions:
            session.delete(revision)
        for file_obj in files_to_delete:
            session.delete(file_obj)

    for file_obj in files_to_delete:
        _queue_deferred_file_deletion(
            session,
            file_obj.path,
            tuple(upload_sessions_by_file.get(file_obj.id, ())),
        )

    document.revisions = []
