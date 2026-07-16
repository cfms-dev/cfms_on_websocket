import hashlib
from typing import Any, cast

import orjson
from sqlalchemy import func, select
from sqlalchemy.dialects.mysql import insert as mysql_insert
from sqlalchemy.dialects.postgresql import insert as postgresql_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
from sqlalchemy.engine import CursorResult
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
    def _digest(cls, serialized: bytes) -> bytes:
        namespace = f"cfms-comment:v{cls.DIGEST_VERSION}\0".encode()
        return hashlib.sha256(namespace + serialized).digest()

    @classmethod
    def _build_insert_statement(
        cls,
        dialect_name: str,
        values: dict[str, Any],
    ):
        if dialect_name == "sqlite":
            statement = sqlite_insert(Comment).values(**values)
            return statement.on_conflict_do_nothing(
                index_elements=[Comment.digest_version, Comment.content_digest]
            )
        if dialect_name == "postgresql":
            statement = postgresql_insert(Comment).values(**values)
            return statement.on_conflict_do_nothing(
                index_elements=[Comment.digest_version, Comment.content_digest]
            ).returning(Comment.comment_id)
        if dialect_name == "mysql":
            statement = mysql_insert(Comment).values(**values)
            return statement.on_duplicate_key_update(
                comment_id=func.last_insert_id(Comment.comment_id),
            )
        raise ValueError(f"Unsupported database dialect: {dialect_name}")

    @classmethod
    def _load_and_validate(
        cls,
        session: Session,
        serialized: bytes,
        content_digest: bytes,
        *,
        comment_id: int | None = None,
    ) -> Comment:
        if comment_id is None:
            statement = select(Comment).where(
                Comment.digest_version == cls.DIGEST_VERSION,
                Comment.content_digest == content_digest,
            )
        else:
            statement = select(Comment).where(Comment.comment_id == comment_id)

        comment = session.scalar(statement)
        if comment is None:
            raise RuntimeError("Comment upsert did not produce a stored row")
        if cls._serialize(comment.comment_text, comment.comment_data) != serialized:
            raise CommentDigestCollisionError(
                "Comment content digest matched different stored content"
            )
        return comment

    @classmethod
    def get_or_create_id(
        cls,
        session: Session,
        text: str,
        data: dict[str, Any] | None = None,
    ) -> int:
        """Atomically return the ID of an equal comment or create one."""
        serialized = cls._serialize(text, data)
        content_digest = cls._digest(serialized)
        values = {
            "digest_version": cls.DIGEST_VERSION,
            "content_digest": content_digest,
            "comment_text": text,
            "comment_data": data,
        }
        dialect_name = session.get_bind().dialect.name
        statement = cls._build_insert_statement(dialect_name, values)

        if dialect_name == "postgresql":
            inserted_id = session.scalar(statement)
            if inserted_id is not None:
                return inserted_id
        else:
            result = cast(CursorResult[Any], session.execute(statement))
            if dialect_name == "sqlite" and result.rowcount == 1:
                primary_key = result.inserted_primary_key
                if not primary_key or primary_key[0] is None:
                    raise RuntimeError("Comment insert did not return a primary key")
                return primary_key[0]
            if dialect_name == "mysql":
                comment_id = result.lastrowid
                if not comment_id:
                    raise RuntimeError("Comment upsert did not return a primary key")
                return cls._load_and_validate(
                    session,
                    serialized,
                    content_digest,
                    comment_id=comment_id,
                ).comment_id

        return cls._load_and_validate(
            session,
            serialized,
            content_digest,
        ).comment_id

    @classmethod
    def get_or_create(
        cls,
        session: Session,
        text: str,
        data: dict[str, Any] | None = None,
    ) -> Comment:
        """Atomically return an equal comment or create one."""
        comment_id = cls.get_or_create_id(session, text, data)
        comment = session.get(Comment, comment_id)
        if comment is None:
            raise RuntimeError("Comment upsert did not produce a stored row")
        return comment
