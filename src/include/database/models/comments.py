from typing import Any

from sqlalchemy import JSON, BigInteger, Index, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from include.database.session import Base


class Comment(Base):
    __tablename__ = "comments"
    __table_args__ = (Index("ix_comments_comment_hash", "comment_hash"),)

    comment_id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    comment_hash: Mapped[int] = mapped_column(Integer, nullable=False)
    comment_text: Mapped[str] = mapped_column(Text, nullable=False)
    comment_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
