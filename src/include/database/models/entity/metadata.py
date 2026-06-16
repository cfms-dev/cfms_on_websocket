__all__ = ["DocumentMetadata", "DocumentMetadataTag"]

from typing import TYPE_CHECKING, List, Optional

from sqlalchemy import VARCHAR, ForeignKey, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship

from include.database.handler import Base

if TYPE_CHECKING:
    from include.database.models.classic import User
    from include.database.models.entity.obj import Document


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
