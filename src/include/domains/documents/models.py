__all__ = [
    "Document",
    "DocumentRevision",
    "DocumentAccessRule",
    "Folder",
    "FolderAccessRule",
]

import secrets
import time
from enum import IntEnum
from itertools import batched
from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import JSON, VARCHAR, Boolean, Float, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.orm.session import object_session

from include.config.constants import QUERY_CHUNK_SIZE
from include.database.session import Base
from include.domains.access.authorization.access_rules import AccessRuleBase
from include.domains.documents.base import BaseObject, EntityStatus
from include.domains.documents.files import (
    File,
    FileTask,
    _queue_deferred_file_deletion,
)
from include.domains.documents.queries.file_references import count_file_references
from include.domains.documents.queries.revisions import batch_count_other_revisions
from include.exceptions.misc import NoActiveRevisionsError

if TYPE_CHECKING:
    from include.domains.documents.metadata import DocumentMetadata


class DocumentRevisionStatus(IntEnum):
    OK = 0
    DELETED = 1


class Folder(BaseObject):  # 文档文件夹
    __tablename__ = "folders"
    id: Mapped[str] = mapped_column(
        VARCHAR(255), primary_key=True, default=lambda: secrets.token_hex(32)
    )
    name: Mapped[str] = mapped_column(
        VARCHAR(255), nullable=False, index=True
    )  # 文件夹名称
    created_time: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time()
    )
    parent_id: Mapped[Optional[str]] = mapped_column(
        VARCHAR(255), ForeignKey("folders.id", ondelete="CASCADE")
    )  # 父文件夹ID
    parent: Mapped[Optional["Folder"]] = relationship(
        "Folder", back_populates="children", remote_side=[id]
    )
    children: Mapped[List["Folder"]] = relationship(
        "Folder", back_populates="parent", cascade="all, delete-orphan"
    )
    access_rules: Mapped[List["FolderAccessRule"]] = relationship(
        "FolderAccessRule", back_populates="folder", cascade="all, delete-orphan"
    )
    documents: Mapped[List["Document"]] = relationship(
        "Document", back_populates="folder", cascade="all, delete-orphan"
    )
    inherit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    @property
    def count_of_child(self):
        active_folders_count = sum(
            1 for f in self.children if f.status == EntityStatus.OK
        )
        active_docs_count = sum(
            1 for doc in self.documents if doc.status == EntityStatus.OK and doc.active
        )
        return active_folders_count + active_docs_count

    def is_descendant_of(self, potential_ancestor: "Folder") -> bool:
        """
        Check if this folder is a descendant of the given potential ancestor folder.

        Args:
            potential_ancestor: The folder to check if it's an ancestor

        Returns:
            True if this folder is a descendant of potential_ancestor, False otherwise
        """
        current = self.parent
        visited_ids = set()
        while current is not None:
            # Detect cycles in the parent chain to avoid infinite loops
            if current.id == potential_ancestor.id:
                return True
            if current.id in visited_ids:
                # Cycle detected; break to prevent an infinite loop
                break
            visited_ids.add(current.id)
            current = current.parent
        return False


class Document(BaseObject):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(
        VARCHAR(255), primary_key=True, default=lambda: secrets.token_hex(32)
    )
    title: Mapped[str] = mapped_column(
        VARCHAR(255), nullable=False, default="Untitled Document", index=True
    )  # 文档名称
    created_time: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time()
    )
    folder_id: Mapped[Optional[str]] = mapped_column(
        VARCHAR(255), ForeignKey("folders.id", ondelete="CASCADE"), nullable=True
    )  # 文档所属文件夹ID
    folder: Mapped[Optional["Folder"]] = relationship(
        "Folder", back_populates="documents"
    )

    # 每个文档有多个访问规则（AccessRule对象），以JSON格式存储规则数据
    access_rules: Mapped[List["DocumentAccessRule"]] = relationship(
        "DocumentAccessRule", back_populates="document", cascade="all, delete-orphan"
    )

    current_revision_id: Mapped[Optional[str]] = mapped_column(
        VARCHAR(64),
        ForeignKey(
            "document_revisions.id",
            name="fk_documents_current_revision_id",
            use_alter=True,
        ),
        nullable=True,
    )
    current_revision: Mapped[Optional["DocumentRevision"]] = relationship(
        "DocumentRevision",
        foreign_keys=[current_revision_id],
        post_update=True,
        uselist=False,
    )

    # 每个文档有多个修订版本
    revisions: Mapped[List["DocumentRevision"]] = relationship(
        "DocumentRevision",
        back_populates="document",
        foreign_keys="[DocumentRevision.document_id]",
        order_by="DocumentRevision.created_time",
        cascade="all, delete-orphan",
        overlaps="current_revision",  # 声明与 current_revision 的重叠
    )
    inherit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    metadata_record: Mapped[Optional["DocumentMetadata"]] = relationship(
        "DocumentMetadata",
        back_populates="document",
        cascade="all, delete-orphan",
        uselist=False,
    )

    @property
    def active(self):
        try:
            latest_revision = self.get_latest_revision()
        except (RuntimeError, NoActiveRevisionsError):
            return False
        return latest_revision is not None

    def get_latest_revision(self) -> "DocumentRevision":
        """
        获取最新的活跃修订版本。

        该函数的逻辑如下：

        - 如果 current_revision 不为空，则从指定的 current_revision 开始，寻找从修订版本树末端上溯遇到的第一个活跃修订版本。
        - 如果 current_revision 为空（这一般仅在从过去的版本升级时发生），则将全体修订版本按`created_time`降序排列，返回第一个`revision.active`为`True`的修订版本。
        """
        current_revision = self.current_revision
        if current_revision is not None:
            if current_revision.active:
                return current_revision

            # find active revisions
            latest_revision = current_revision.parent_revision
            while latest_revision is not None:
                if latest_revision.active:
                    return latest_revision
                latest_revision = latest_revision.parent_revision

            # if goes here, use backward compatibility method

        # for backward compatibility
        revisions = self.revisions
        if not revisions:
            raise RuntimeError("A document cannot have no revisions.")

        # 过滤出active为True的修订版本
        active_revisions = [rev for rev in revisions if rev.active]

        if not active_revisions:
            raise NoActiveRevisionsError("No active revisions found.")

        return max(active_revisions, key=lambda rev: rev.created_time)

    def delete_all_revisions(self, do_commit: bool = True):
        session = object_session(self)
        if not session:
            raise Exception("The object is not associated with a session")

        # Task 4: Lightweight tuple query — fetch only the IDs we need for logic.
        # Avoids loading the full ORM graph (revisions + files) just for reference counting.
        revision_tuples = (
            session.query(DocumentRevision.id, DocumentRevision.file_id)
            .filter(DocumentRevision.document_id == self.id)
            .all()
        )
        if not revision_tuples:
            return

        revision_ids = [row[0] for row in revision_tuples]
        all_file_ids = {row[1] for row in revision_tuples if row[1]}

        # Task 3: Chunked batch reference count queries to avoid variable limit.
        other_counts = batch_count_other_revisions(session, all_file_ids, self.id)

        # Determine which files are exclusively referenced by this document's revisions.
        deletable_file_ids = {
            fid for fid in all_file_ids if other_counts.get(fid, 0) == 0
        }

        # Load File ORM objects needed for deletion (chunked to stay within SQLite limits).
        # Task 4: Only loads files that are actually going to be deleted.
        files_to_delete: list = []
        if deletable_file_ids:
            for chunk in batched(deletable_file_ids, QUERY_CHUNK_SIZE):
                files_to_delete.extend(
                    session.query(File).filter(File.id.in_(list(chunk))).all()
                )

        self.current_revision_id = None
        self.current_revision = None

        with session.no_autoflush:
            # Task 2: Batch delete all FileTask rows for deletable files in one query per chunk.
            # Replaces N individual DELETE queries (one per file) with one per chunk.
            if deletable_file_ids:
                for chunk in batched(deletable_file_ids, QUERY_CHUNK_SIZE):
                    session.query(FileTask).filter(
                        FileTask.file_id.in_(list(chunk))
                    ).delete(synchronize_session=False)

            # Load DocumentRevision ORM objects for deletion (chunked).
            revisions: list = []
            for chunk in batched(revision_ids, QUERY_CHUNK_SIZE):
                revisions.extend(
                    session.query(DocumentRevision)
                    .filter(DocumentRevision.id.in_(list(chunk)))
                    .all()
                )

            # ORM-level delete so SQLAlchemy handles FK ordering correctly at flush time.
            for revision in revisions:
                session.delete(revision)
            for file_obj in files_to_delete:
                session.delete(file_obj)

        # Task 1: Queue physical file paths for deferred deletion.
        # Files are removed from disk ONLY after session.commit() succeeds.
        # If the transaction rolls back, the queued paths are discarded automatically.
        for file_obj in files_to_delete:
            _queue_deferred_file_deletion(session, file_obj.path)

        self.revisions = []
        if do_commit:
            session.commit()

    def __repr__(self) -> str:
        return f"Document(id={self.id!r}, created_time={self.created_time!r})"


class DocumentRevision(Base):
    """
    This class implemented a model for document revisions.

    A document revision is a historical version of the document,
    should only be written once and not changed.
    """

    __tablename__ = "document_revisions"
    id: Mapped[str] = mapped_column(
        VARCHAR(64), primary_key=True, default=lambda: secrets.token_hex(32)
    )
    document_id: Mapped[str] = mapped_column(
        VARCHAR(255), ForeignKey("documents.id"), nullable=False
    )
    file_id: Mapped[str] = mapped_column(ForeignKey("files.id"))
    created_time: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time()
    )

    document: Mapped["Document"] = relationship(
        "Document",
        back_populates="revisions",
        foreign_keys=[document_id],
        overlaps="current_revision",  # 声明重叠
    )
    file: Mapped["File"] = relationship(
        "File", primaryjoin="DocumentRevision.file_id == File.id"
    )

    parent_revision_id: Mapped[Optional[str]] = mapped_column(
        VARCHAR(64), ForeignKey("document_revisions.id"), nullable=True
    )
    parent_revision: Mapped[Optional["DocumentRevision"]] = relationship(
        "DocumentRevision",
        remote_side=[id],
        back_populates="child_revisions",
    )

    child_revisions: Mapped[List["DocumentRevision"]] = relationship(
        "DocumentRevision",
        back_populates="parent_revision",
        foreign_keys="[DocumentRevision.parent_revision_id]",
    )

    status: Mapped[DocumentRevisionStatus] = mapped_column(
        Integer, nullable=False, default=DocumentRevisionStatus.OK
    )

    @property
    def active(self):
        return self.file.active

    @property
    def writeable(self):
        return self.file.writeable

    def before_delete(self):
        session = object_session(self)
        if not session:
            raise Exception("The object is not associated with a session")
        if not self.file_id:
            return
        # Use centralized reference counting across all FK references.
        total = count_file_references(session, [self.file_id]).get(self.file_id, 0)
        # Subtract this revision's own reference.
        other_refs = max(0, total - 1)

        if other_refs == 0:
            self.file.delete()
            session.delete(self.file)

    def __repr__(self) -> str:
        return (
            f"DocumentRevision(id={self.id!r}, document_id={self.document_id!r}, "
            f"file={self.file!r}, created_time={self.created_time!r})"
        )


class DocumentAccessRule(Base, AccessRuleBase):
    __tablename__ = "document_access_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    access_type: Mapped[str] = mapped_column(
        VARCHAR(64),
        nullable=False,
        default="read",
        # comment="0: read, 1: write",  # rename is regarded as write
    )
    document_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("documents.id"), nullable=False
    )
    rule_data: Mapped[dict] = mapped_column(
        JSON, nullable=False
    )  # 存储单个Json格式的规则数据

    document: Mapped[Optional["Document"]] = relationship(
        "Document", back_populates="access_rules"
    )

    def __repr__(self) -> str:
        return f"DocumentAccessRule(id={self.id!r}, document_id={self.document_id!r}, rule_data={self.rule_data!r})"


class FolderAccessRule(Base, AccessRuleBase):
    __tablename__ = "folder_access_rules"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    access_type: Mapped[str] = mapped_column(
        VARCHAR(64),
        nullable=False,
        default="read",
    )
    folder_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("folders.id"), nullable=True
    )
    rule_data: Mapped[dict] = mapped_column(
        JSON, nullable=False
    )  # 存储单个Json格式的规则数据

    folder: Mapped[Optional["Folder"]] = relationship(
        "Folder", back_populates="access_rules"
    )

    def __repr__(self) -> str:
        return f"FolderAccessRule(id={self.id!r}, folder_id={self.folder_id!r}, rule_data={self.rule_data!r})"


from include.domains.documents import metadata as _metadata  # noqa: E402, F401
