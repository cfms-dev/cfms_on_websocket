from typing import Any

from sqlalchemy import (
    JSON,
    BigInteger,
    Integer,
    SmallInteger,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column

from include.database.session import Base


class Comment(Base):
    __tablename__ = "comments"
    __table_args__ = (
        UniqueConstraint(
            "digest_version",
            "content_digest",
            name="uq_comments_content_digest",
        ),
    )

    comment_id: Mapped[int] = mapped_column(
        BigInteger().with_variant(Integer, "sqlite"),
        primary_key=True,
        autoincrement=True,
    )
    digest_version: Mapped[int] = mapped_column(SmallInteger, nullable=False)
    content_digest: Mapped[str] = mapped_column(String(64), nullable=False)
    comment_text: Mapped[str] = mapped_column(Text, nullable=False)
    comment_data: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
