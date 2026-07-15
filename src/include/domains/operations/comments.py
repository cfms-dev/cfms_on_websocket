import hashlib
from typing import Any

import orjson
from sqlalchemy import select
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.orm import Session

from include.database.models.comments import Comment


class CommentDigestCollisionError(RuntimeError):
    pass


class CommentStore:
    """Store reusable short operation reasons and summaries."""

    DIGEST_VERSION = 1

    @classmethod
    def _serialize(cls, text: str, data: dict[str, Any] | None) -> bytes:
        return orjson.dumps({"data": data, "text": text}, option=orjson.OPT_SORT_KEYS)

    @classmethod
    def _digest(cls, text: str, data: dict[str, Any] | None) -> str:
        serialized = cls._serialize(text, data)
        namespace = f"cfms-comment:v{cls.DIGEST_VERSION}\0".encode()
        return hashlib.sha256(namespace + serialized).hexdigest()

    @classmethod
    def _insert_if_missing(
        cls,
        session: Session,
        values: dict[str, Any],
    ) -> None:
        dialect_name = session.get_bind().dialect.name

        if dialect_name == "sqlite":
            statement = sqlite_insert(Comment).values(**values)
            statement = statement.on_conflict_do_nothing(
                index_elements=[Comment.digest_version, Comment.content_digest]
            )
        elif dialect_name == "postgresql":
            statement = postgresql_insert(Comment).values(**values)
            statement = statement.on_conflict_do_nothing(
                index_elements=[Comment.digest_version, Comment.content_digest]
            )
        elif dialect_name == "mysql":
            statement = mysql_insert(Comment).values(**values)
            statement = statement.on_duplicate_key_update(
                digest_version=statement.inserted.digest_version,
                content_digest=statement.inserted.content_digest,
            )
        else:
            raise ValueError(f"Unsupported database dialect: {dialect_name}")

        session.execute(statement)

    @classmethod
    def get_or_create(
        cls,
        session: Session,
        text: str,
        data: dict[str, Any] | None = None,
    ) -> Comment:
        """Atomically return an equal comment or create one."""
        serialized = cls._serialize(text, data)
        content_digest = cls._digest(text, data)
        values = {
            "digest_version": cls.DIGEST_VERSION,
            "content_digest": content_digest,
            "comment_text": text,
            "comment_data": data,
        }

        cls._insert_if_missing(session, values)
        comment = session.scalar(
            select(Comment)
            .where(
                Comment.digest_version == cls.DIGEST_VERSION,
                Comment.content_digest == content_digest,
            )
            .with_for_update()
        )
        if comment is None:
            raise RuntimeError("Comment upsert did not produce a stored row")
        if cls._serialize(comment.comment_text, comment.comment_data) != serialized:
            raise CommentDigestCollisionError(
                "Comment content digest matched different stored content"
            )

        return comment
