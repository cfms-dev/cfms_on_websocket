import zlib
from typing import Any

import orjson
from sqlalchemy import select
from sqlalchemy.orm import Session

from include.database.models.comments import Comment


class CommentStore:
    """Store reusable short operation reasons and summaries."""

    @staticmethod
    def _hash(text: str, data: dict[str, Any] | None) -> int:
        serialized = orjson.dumps(
            {"data": data, "text": text}, option=orjson.OPT_SORT_KEYS
        )
        unsigned_hash = zlib.crc32(serialized)
        return unsigned_hash if unsigned_hash < 2**31 else unsigned_hash - 2**32

    @classmethod
    def get_or_create(
        cls,
        session: Session,
        text: str,
        data: dict[str, Any] | None = None,
    ) -> Comment:
        """Return an equal comment when found, otherwise create one.

        De-duplication is deliberately best-effort. The hash is not unique, and
        concurrent transactions may both insert the same comment.
        """
        comment_hash = cls._hash(text, data)
        candidates = session.scalars(
            select(Comment).where(Comment.comment_hash == comment_hash)
        )
        for candidate in candidates:
            if candidate.comment_text == text and candidate.comment_data == data:
                return candidate

        comment = Comment(
            comment_hash=comment_hash,
            comment_text=text,
            comment_data=data,
        )
        session.add(comment)
        session.flush()
        return comment
