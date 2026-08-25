__all__ = [
    "Document",
    "DocumentMetadata",
    "DocumentMetadataTag",
    "DocumentRevision",
    "DocumentRevisionStatus",
    "EntityStatus",
    "Folder",
    "Node",
]

import secrets
import time
from enum import IntEnum, StrEnum
from itertools import batched
from typing import TYPE_CHECKING, ClassVar, Literal, cast
from warnings import deprecated

from sqlalchemy import (
    VARCHAR,
    Boolean,
    CheckConstraint,
    Computed,
    Float,
    ForeignKey,
    Index,
    Integer,
    UniqueConstraint,
    func,
    select,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym
from sqlalchemy.orm.session import object_session

from include.config.constants import (
    QUERY_CHUNK_SIZE,
    ROOT_DIRECTORY_ID,
    USERNAME_DATABASE_MAX_LENGTH,
)
from include.config.settings import global_config
from include.database.models.files import (
    File,
    FileTask,
    _queue_deferred_file_deletion,
)
from include.database.session import Base
from include.domains.access.authorization.grants import (
    batch_prefetch_granted_ids,
    prefetch_user_blocks,
)
from include.domains.documents.queries.file_references import count_file_references
from include.domains.documents.queries.revisions import batch_count_other_revisions
from include.exceptions.misc import NoActiveRevisionsError

if TYPE_CHECKING:
    from include.database.models.access import CompiledAccessRuleSet
    from include.database.models.identity import User


class NodeType(StrEnum):
    DOCUMENT = "document"
    DIRECTORY = "directory"


class EntityStatus(IntEnum):
    OK = 0
    DELETED = 1
    LOCKED = 2


def _default_node_parent_id(context) -> str | None:
    return (
        None
        if context.get_current_parameters().get("id") == ROOT_DIRECTORY_ID
        else ROOT_DIRECTORY_ID
    )


class Node(Base):
    __tablename__ = "nodes"

    id: Mapped[str] = mapped_column(
        VARCHAR(255), primary_key=True, default=lambda: secrets.token_hex(32)
    )
    type: Mapped[str] = mapped_column(VARCHAR(16), nullable=False, index=True)
    name: Mapped[str] = mapped_column(VARCHAR(255), nullable=False, index=True)
    parent_id: Mapped[str | None] = mapped_column(
        VARCHAR(255),
        ForeignKey(
            "folders.id",
            name="fk_nodes_parent_id_folders",
            ondelete="CASCADE",
            use_alter=True,
        ),
        nullable=True,
        default=_default_node_parent_id,
    )
    active_parent_id: Mapped[str | None] = mapped_column(
        VARCHAR(255),
        Computed(
            f"CASE WHEN status = {EntityStatus.DELETED.value} "
            "THEN NULL ELSE parent_id END",
            persisted=True,
        ),
        nullable=True,
    )
    __table_args__ = (
        CheckConstraint(
            (
                (id == ROOT_DIRECTORY_ID)
                & parent_id.is_(None)
                & (type == NodeType.DIRECTORY.value)
            )
            | ((id != ROOT_DIRECTORY_ID) & parent_id.is_not(None)),
            name="ck_nodes_root_parent",
        ),
        UniqueConstraint(
            "active_parent_id",
            "name",
            name="uq_nodes_active_parent_name",
        ),
        Index(
            "ix_nodes_parent_status_lower_name_id",
            "parent_id",
            "status",
            func.lower(name),
            "id",
        ),
        Index(
            "ix_nodes_status_lower_name_id",
            "status",
            func.lower(name),
            "id",
        ),
    )

    # Whether to inherit access rules from parent folders.
    # Useful when enabling recursion check.
    inherit: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)

    status: Mapped[EntityStatus] = mapped_column(
        Integer, nullable=False, default=EntityStatus.OK
    )
    status_operation_id: Mapped[str | None] = mapped_column(
        VARCHAR(255), nullable=True, index=True
    )
    access_rule_set_id: Mapped[str | None] = mapped_column(
        VARCHAR(32),
        ForeignKey(
            "compiled_access_rule_sets.id",
            name="fk_nodes_access_rule_set_id_compiled_access_rule_sets",
            use_alter=True,
        ),
        nullable=True,
        index=True,
    )
    access_rule_set: Mapped["CompiledAccessRuleSet | None"] = relationship(
        "CompiledAccessRuleSet",
        foreign_keys=[access_rule_set_id],
        post_update=True,
        uselist=False,
    )
    access_rule_sets: Mapped[list["CompiledAccessRuleSet"]] = relationship(
        "CompiledAccessRuleSet",
        back_populates="node",
        cascade="all, delete-orphan",
        foreign_keys="CompiledAccessRuleSet.node_id",
        order_by="CompiledAccessRuleSet.created_at",
    )

    __mapper_args__: ClassVar = {
        "polymorphic_on": type,
        "polymorphic_identity": "node",
    }

    def check_access_requirements(
        self, user: "User", access_type: str = "read", _no_recursive_check=False
    ) -> bool:
        """Checks if a given user meets the access requirements for a specific access type based on defined access rules.

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
        _TARGET_TYPE_MAPPING = {
            "folders": NodeType.DIRECTORY.value,
            "documents": NodeType.DOCUMENT.value,
        }

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

        # FIXME: Use lazy import when Python 3.15 comes out
        from include.domains.access.authorization.compiled_rules import (
            compiled_rules_allow,
        )

        return compiled_rules_allow(
            _session,
            target_type=self_type,
            target_id=self.id,
            user=user,
            access_type=access_type,
        )


class DocumentRevisionStatus(IntEnum):
    OK = 0
    DELETED = 1


class Folder(Node):  # Document folder.
    __tablename__ = "folders"
    id: Mapped[str] = mapped_column(
        VARCHAR(255),
        ForeignKey("nodes.id", ondelete="CASCADE"),
        primary_key=True,
    )
    created_time: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time()
    )
    parent: Mapped[Folder | None] = relationship(
        "Folder",
        back_populates="children",
        remote_side=[id],
        foreign_keys=[Node.parent_id],
    )
    children: Mapped[list[Folder]] = relationship(
        "Folder",
        back_populates="parent",
        cascade="all, delete-orphan",
        foreign_keys=[Node.parent_id],
    )
    documents: Mapped[list[Document]] = relationship(
        "Document",
        back_populates="folder",
        cascade="all, delete-orphan",
        foreign_keys="[Node.parent_id]",
    )

    __mapper_args__: ClassVar[dict[str, object]] = {
        "polymorphic_identity": NodeType.DIRECTORY.value,
        "inherit_condition": id == Node.id,
    }

    @property
    @deprecated("Use count_active_directory_children instead.")
    def count_of_child(self):
        active_folders_count = sum(
            1 for f in self.children if f.status == EntityStatus.OK
        )
        active_docs_count = sum(
            1 for doc in self.documents if doc.status == EntityStatus.OK and doc.active
        )
        return active_folders_count + active_docs_count

    def is_descendant_of(self, potential_ancestor: Folder, /) -> bool:
        """Check if this folder is a descendant of the given potential ancestor folder.

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


class Document(Node):
    __tablename__ = "documents"
    id: Mapped[str] = mapped_column(
        VARCHAR(255),
        ForeignKey("nodes.id", ondelete="CASCADE"),
        primary_key=True,
    )
    title = synonym("name")
    folder_id = synonym("parent_id")
    created_time: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time()
    )
    folder: Mapped[Folder | None] = relationship(
        "Folder",
        back_populates="documents",
        foreign_keys=[Node.parent_id],
    )

    current_revision_id: Mapped[str | None] = mapped_column(
        VARCHAR(64),
        ForeignKey(
            "document_revisions.id",
            ondelete="SET NULL",
            use_alter=True,
        ),
        nullable=True,
    )
    current_revision: Mapped[DocumentRevision | None] = relationship(
        "DocumentRevision",
        foreign_keys=[current_revision_id],
        post_update=True,
        uselist=False,
    )

    # Each document has multiple revisions.
    revisions: Mapped[list[DocumentRevision]] = relationship(
        "DocumentRevision",
        back_populates="document",
        foreign_keys="[DocumentRevision.document_id]",
        order_by="DocumentRevision.created_time",
        cascade="all, delete-orphan",
        overlaps="current_revision",  # Declares overlap with current_revision.
    )
    metadata_record: Mapped[DocumentMetadata | None] = relationship(
        "DocumentMetadata",
        back_populates="document",
        cascade="all, delete-orphan",
        uselist=False,
    )

    @property
    def active(self):
        try:
            latest_revision = self.get_latest_revision()
        except RuntimeError, NoActiveRevisionsError:
            return False
        return latest_revision is not None

    __mapper_args__: ClassVar[dict[str, str]] = {
        "polymorphic_identity": NodeType.DOCUMENT.value
    }

    def get_latest_revision(self) -> DocumentRevision:
        """Return the latest active revision.

        If current_revision is set, walk upward from it and return the first
        active revision found in that branch. If current_revision is not set,
        which generally only occurs after upgrading from an older version,
        sort all revisions by created_time descending and return the first
        revision whose active property is True.
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

        # Keep only revisions whose active property is True.
        active_revisions = [rev for rev in revisions if rev.active]

        if not active_revisions:
            raise NoActiveRevisionsError("No active revisions found.")

        return max(active_revisions, key=lambda rev: rev.created_time)

    def delete_all_revisions(self, do_commit: bool = True):
        session = object_session(self)
        if not session:
            raise RuntimeError("The object is not associated with a session")

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
            upload_sessions_by_file: dict[str, list[str]] = {}
            if deletable_file_ids:
                for chunk in batched(deletable_file_ids, QUERY_CHUNK_SIZE):
                    for file_id, upload_session_id in session.execute(
                        select(FileTask.file_id, FileTask.upload_session_id).where(
                            FileTask.file_id.in_(list(chunk)),
                            FileTask.upload_session_id.is_not(None),
                        )
                    ):
                        if upload_session_id is not None:
                            upload_sessions_by_file.setdefault(file_id, []).append(
                                upload_session_id
                            )
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
            _queue_deferred_file_deletion(
                session,
                file_obj.path,
                tuple(upload_sessions_by_file.get(file_obj.id, ())),
            )

        self.revisions = []
        if do_commit:
            session.commit()

    def __repr__(self) -> str:
        return f"Document(id={self.id!r}, created_time={self.created_time!r})"


class DocumentRevision(Base):
    """This class implemented a model for document revisions.

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
    file_id: Mapped[str] = mapped_column(ForeignKey("files.id"), index=True)
    created_time: Mapped[float] = mapped_column(
        Float, nullable=False, default=lambda: time.time()
    )

    document: Mapped[Document] = relationship(
        "Document",
        back_populates="revisions",
        foreign_keys=[document_id],
        overlaps="current_revision",  # Declares overlap.
    )
    file: Mapped[File] = relationship(
        "File", primaryjoin="DocumentRevision.file_id == File.id"
    )

    parent_revision_id: Mapped[str | None] = mapped_column(
        VARCHAR(64),
        ForeignKey("document_revisions.id", ondelete="SET NULL"),
        nullable=True,
    )
    parent_revision: Mapped[DocumentRevision | None] = relationship(
        "DocumentRevision",
        remote_side=[id],
        back_populates="child_revisions",
    )

    child_revisions: Mapped[list[DocumentRevision]] = relationship(
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
            raise RuntimeError("The object is not associated with a session")
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


class DocumentMetadata(Base):
    __tablename__ = "document_metadata"

    document_id: Mapped[str] = mapped_column(
        VARCHAR(255), ForeignKey("documents.id", ondelete="CASCADE"), primary_key=True
    )
    creator_username: Mapped[str | None] = mapped_column(
        VARCHAR(USERNAME_DATABASE_MAX_LENGTH),
        ForeignKey("users.username", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )
    last_modified_by_username: Mapped[str | None] = mapped_column(
        VARCHAR(USERNAME_DATABASE_MAX_LENGTH),
        ForeignKey("users.username", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    document: Mapped[Document] = relationship(
        "Document",
        back_populates="metadata_record",
        foreign_keys=[document_id],
    )
    creator: Mapped["User | None"] = relationship(
        "User", foreign_keys=[creator_username]
    )
    last_modified_by: Mapped["User | None"] = relationship(
        "User", foreign_keys=[last_modified_by_username]
    )
    tags: Mapped[list[DocumentMetadataTag]] = relationship(
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

    metadata_record: Mapped[DocumentMetadata] = relationship(
        "DocumentMetadata",
        back_populates="tags",
        foreign_keys=[document_id],
    )
