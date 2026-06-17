from itertools import batched
from typing import List

from sqlalchemy.orm import Session

from include.constants import QUERY_CHUNK_SIZE
from include.database.models.entity import (
    Document,
    DocumentAccessRule,
    DocumentRevision,
)
from include.database.models.file import File, FileTask, _queue_deferred_file_deletion
from include.util.bulk.count import batch_count_other_revisions


def purge_documents_bulk(session: Session, document_ids: List[str]):
    """
    高度优化的批量粉碎函数。
    将原本 600+ 次的单个文档删除，转化为针对所有文档的一组批量删除。
    """
    if not document_ids:
        return

    # 1. 批量获取所有受影响的修订版本 ID 和文件 ID（分块查询以避免超出绑定变量限制）
    revision_data = []
    for chunk in batched(document_ids, QUERY_CHUNK_SIZE):
        revision_data.extend(
            session.query(DocumentRevision.id, DocumentRevision.file_id)
            .filter(DocumentRevision.document_id.in_(list(chunk)))
            .all()
        )

    if not revision_data:
        # 如果这些文档都没有修订版本，直接删除文档记录即可
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

    # 2. 批量引用计数检查
    # 使用集中计数，排除来自这批文档的引用后若为 0 则可删除
    other_counts = batch_count_other_revisions(session, list(file_ids), document_ids)

    # 找出仅被这批文档引用、可以物理删除的文件 ID
    deletable_file_ids = [fid for fid in file_ids if other_counts.get(fid, 0) == 0]

    # 3. 批量删除 (使用 SQL 级别的 delete)
    # 我们处于 no_autoflush 模式下运行此块

    # 3a. 先解除文档与修订版本、修订版本之间的外键引用
    for chunk in batched(document_ids, QUERY_CHUNK_SIZE):
        session.query(Document).filter(Document.id.in_(chunk)).update(
            {Document.current_revision_id: None}, synchronize_session=False
        )

    for chunk in batched(rev_ids, QUERY_CHUNK_SIZE):
        session.query(DocumentRevision).filter(DocumentRevision.id.in_(chunk)).update(
            {DocumentRevision.parent_revision_id: None}, synchronize_session=False
        )

    # 3b. 清理相关任务
    if deletable_file_ids:
        for chunk in batched(deletable_file_ids, QUERY_CHUNK_SIZE):
            session.query(FileTask).filter(FileTask.file_id.in_(chunk)).delete(
                synchronize_session=False
            )

    # 3c. 收集文件路径。File 记录必须等 DocumentRevision 删除后才能删除。
    deletable_files = []
    if deletable_file_ids:
        for chunk in batched(deletable_file_ids, QUERY_CHUNK_SIZE):
            deletable_files.extend(session.query(File).filter(File.id.in_(chunk)).all())

    # 3d. 批量删除修订版本、文件和文档
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
