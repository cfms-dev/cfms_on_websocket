__all__ = ["DocumentMetadata"]

from sqlalchemy import VARCHAR, ForeignKey
from sqlalchemy.orm import Mapped, mapped_column

from include.database.handler import Base


class DocumentMetadata(Base):
    __tablename__ = "document_metadata"

    document_id: Mapped[str] = mapped_column(
        VARCHAR(64), ForeignKey("document.id", ondelete="CASCADE"), primary_key=True
    )
    # TODO: Add more metadata fields as needed, e.g. author, creation date, etc.
