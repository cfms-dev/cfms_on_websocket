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
from typing import TYPE_CHECKING, ClassVar
from warnings import deprecated

from sqlalchemy import (
    VARCHAR,
    Boolean,
    CheckConstraint,
    Computed,
    Double,
    ForeignKey,
    Index,
    Integer,
    UniqueConstraint,
    func,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship, synonym

from include.config.constants import (
    ROOT_DIRECTORY_ID,
    USERNAME_DATABASE_MAX_LENGTH,
)
from include.database.models.files import File
from include.database.session import Base
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
    active_name: Mapped[str | None] = mapped_column(
        VARCHAR(255),
        Computed(
            f"CASE WHEN status = {EntityStatus.DELETED.value} THEN NULL ELSE name END",
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
            "parent_id",
            "active_name",
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
        Double, nullable=False, default=lambda: time.time()
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
        Double, nullable=False, default=lambda: time.time()
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
        Double, nullable=False, default=lambda: time.time()
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
