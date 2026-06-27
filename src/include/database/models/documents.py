from __future__ import annotations

__all__ = [
    "BaseObject",
    "EntityStatus",
    "Document",
    "DocumentRevision",
    "DocumentRevisionStatus",
    "DocumentAccessRule",
    "DocumentMetadata",
    "DocumentMetadataTag",
    "Folder",
    "FolderAccessRule",
]

import secrets
import time
from enum import IntEnum
from itertools import batched
from typing import TYPE_CHECKING, List, Literal, Optional, cast

from sqlalchemy import JSON, VARCHAR, Boolean, Float, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.orm.session import object_session

from include.config.constants import AVAILABLE_ACCESS_TYPES, QUERY_CHUNK_SIZE
from include.config.settings import global_config
from include.database.models.files import (
    File,
    FileTask,
    _queue_deferred_file_deletion,
)
from include.database.session import Base
from include.domains.access.authorization.access_rules import AccessRuleBase
from include.domains.access.authorization.grants import (
    batch_prefetch_granted_ids,
    prefetch_user_blocks,
)
from include.domains.documents.queries.file_references import count_file_references
from include.domains.documents.queries.revisions import batch_count_other_revisions
from include.exceptions.misc import NoActiveRevisionsError

if TYPE_CHECKING:
    from include.database.models.identity import User


class EntityStatus(IntEnum):
    OK = 0
    DELETED = 1
    LOCKED = 2


class BaseObject(Base):
    __abstract__ = True

    id: Mapped[str]
    access_rules: Mapped[List]

    # Whether to inherit access rules from parent folders.
    # Useful when enabling recursion check.
    inherit: Mapped[bool]

    status: Mapped[EntityStatus] = mapped_column(
        Integer, nullable=False, default=EntityStatus.OK
    )
    status_operation_id: Mapped[Optional[str]] = mapped_column(
        VARCHAR(255), nullable=True, index=True
    )

    def check_access_requirements(
        self, user: User, access_type: str = "read", _no_recursive_check=False
    ) -> bool:
        """
        Checks if a given user meets the access requirements for a specific access type based on defined access rules.
        Args:
            user (User): The user object whose permissions and groups are to be checked.
            access_type (int, optional): The type of access to check for. Defaults to `"read"`.
            _no_recursive_check (bool, optional): Useful when performing batch queries. Defaults to False.
        Returns:
            bool: True if the user meets all access requirements for the specified access type, False otherwise.
        Raises:
            ValueError: If the "match" value in any rule is not "all" or "any".
        Access rules are evaluated as follows:
            - Each rule may specify required permissions ("rights") and/or groups ("groups").
            - Each requirement can specify a "match" mode: "all" (all required items must be present) or "any" (at least one must be present).
            - Rules are grouped and evaluated according to their match modes and requirements.
            - If no access rules are defined, access is granted by default.
        """

        _TARGET_TYPE_MAPPING = {"folders": "directory", "documents": "document"}

        def match_rights(sub_rights_group):
            if not sub_rights_group:
                return True

            sub_match_mode = sub_rights_group.get("match", "all")
            sub_rights_require = sub_rights_group.get("require", [])

            if not sub_rights_require:
                return True

            if sub_match_mode == "all":
                return set(sub_rights_require).issubset(user.all_permissions)

            elif sub_match_mode == "any":
                for right in sub_rights_require:
                    if right in user.all_permissions:
                        return True
                return False

            else:
                raise ValueError('the value of "match" must be "all" or "any"')

        def match_groups(sub_groups_group):
            if not sub_groups_group:
                return True

            sub_match_mode = sub_groups_group.get("match", "all")
            sub_groups_require = sub_groups_group.get("require", [])

            if not sub_groups_require:
                return True

            if sub_match_mode == "all":
                return set(sub_groups_require).issubset(user.all_groups)

            elif sub_match_mode == "any":
                for group in sub_groups_require:
                    if group in user.all_groups:
                        return True
                return False
            else:
                raise ValueError('the value of "match" must be "all" or "any"')

        def match_sub_group(sub_group):
            sub_match_mode = sub_group.get("match", "all")
            sub_rights_group = sub_group.get("rights", {})
            sub_groups_group = sub_group.get("groups", {})

            if not (sub_rights_group.get("require", [])) or (
                not sub_groups_group.get("require", [])
            ):
                sub_match_mode = "all"

            if sub_match_mode == "any":
                return match_rights(sub_rights_group) or match_groups(sub_groups_group)
            if sub_match_mode == "all":
                return match_rights(sub_rights_group) and match_groups(sub_groups_group)
            else:
                raise ValueError('the value of "match" must be "all" or "any"')

        def match_primary_sub_group(per_match_group):
            match_mode = per_match_group.get("match", "all")
            for sub_group in per_match_group["match_groups"]:
                if not sub_group:
                    continue

                state = match_sub_group(sub_group)

                if match_mode == "any":
                    if state:
                        return True
                elif match_mode == "all":
                    if not state:
                        return False

            if match_mode == "any":
                return False
            elif match_mode == "all":
                return True

        _session = object_session(user)
        if not _session:
            raise RuntimeError("No active session found for user")

        now = time.time()

        is_globally_blocked, blocked_ids = prefetch_user_blocks(
            _session, user, access_type, now
        )
        if is_globally_blocked or self.id in blocked_ids:
            return False

        self_type = cast(
            Literal["document", "directory"], _TARGET_TYPE_MAPPING[self.__tablename__]
        )
        explicitly_granted_ids = batch_prefetch_granted_ids(
            _session, user, [self.id], self_type, access_type, now
        )

        if self.id in explicitly_granted_ids:
            return True

        if (
            global_config["access"]["enable_access_recursive_check"]
            and self.inherit
            and not _no_recursive_check
        ):
            from include.database.models.documents import Document, Folder

            parent = None
            if isinstance(self, Document):
                parent = self.folder
            elif isinstance(self, Folder):
                parent = self.parent

            visited_folder_ids = set()
            while parent is not None:
                if parent.id in visited_folder_ids:
                    raise RuntimeError("Cycle detected in folder hierarchy")
                visited_folder_ids.add(parent.id)

                if not parent.check_access_requirements(user, access_type=access_type):
                    return False

                if not parent.inherit:
                    break

                parent = parent.parent

        if not self.access_rules:
            return True

        for each_rule in self.access_rules:
            if not each_rule:
                continue

            each_rule: AccessRuleBase

            if access_type not in AVAILABLE_ACCESS_TYPES:
                raise ValueError(
                    f"Invalid access type for {self.__tablename__}: {access_type}"
                )

            match access_type:
                case "read":
                    if each_rule.access_type != "read":
                        continue
                case "write":
                    if each_rule.access_type not in ["read", "write"]:
                        continue
                case "move":
                    if each_rule.access_type != "move":
                        continue
                case "manage":
                    if each_rule.access_type not in ["read", "manage"]:
                        continue
                case _:
                    raise NotImplementedError("Unsupported access type")

            if not each_rule.rule_data:
                continue

            if not match_primary_sub_group(each_rule.rule_data):
                return False

        return True


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


class DocumentMetadata(Base):
    __tablename__ = "document_metadata"

    document_id: Mapped[str] = mapped_column(
        VARCHAR(255), ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True
    )
    creator_username: Mapped[Optional[str]] = mapped_column(
        VARCHAR(64),
        ForeignKey("users.username", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    last_modified_by_username: Mapped[Optional[str]] = mapped_column(
        VARCHAR(64),
        ForeignKey("users.username", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    document: Mapped["Document"] = relationship(
        "Document",
        back_populates="metadata_record",
        foreign_keys=[document_id],
    )
    creator: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[creator_username]
    )
    last_modified_by: Mapped[Optional["User"]] = relationship(
        "User", foreign_keys=[last_modified_by_username]
    )
    tags: Mapped[List["DocumentMetadataTag"]] = relationship(
        "DocumentMetadataTag",
        back_populates="metadata_record",
        cascade="all, delete-orphan",
        order_by="DocumentMetadataTag.position",
    )


class DocumentMetadataTag(Base):
    __tablename__ = "document_metadata_tags"

    document_id: Mapped[str] = mapped_column(
        VARCHAR(255),
        ForeignKey("document_metadata.document_id", ondelete="CASCADE"),
        primary_key=True,
    )
    tag: Mapped[str] = mapped_column(VARCHAR(255), primary_key=True, index=True)
    position: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    metadata_record: Mapped["DocumentMetadata"] = relationship(
        "DocumentMetadata",
        back_populates="tags",
        foreign_keys=[document_id],
    )
