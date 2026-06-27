__all__ = ["count_file_references", "_clear_file_references_cache"]

from itertools import islice
from typing import Any, Sequence, cast

from sqlalchemy import MetaData, Table, func, select, union_all
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from include.config.constants import QUERY_CHUNK_SIZE

# Cache keyed by engine URL so that different engines (e.g. in tests) each
# get their own reflected FK list.  Call ``_clear_file_references_cache()``
# to force a re-reflection.
_CACHED_REFS: dict[str, list[tuple[Table, str]]] = {}


def _clear_file_references_cache() -> None:
    """Reset the cached FK reflection data.

    Useful in test fixtures or after schema migrations.
    """
    _CACHED_REFS.clear()


def _get_file_references(engine: Engine) -> list[tuple[Table, str]]:
    """Return ``(table, column_name)`` pairs for every FK that points to the
    ``files`` table, **excluding** cascade-dependent relationships.

    Foreign keys declared with ``ondelete="CASCADE"`` represent operational
    metadata (e.g. ``file_tasks``) that is automatically removed when the
    parent file row is deleted — they are not independent "usage" references
    and must not block file deletion.
    """
    cache_key = str(engine.url)
    if cache_key in _CACHED_REFS:
        return _CACHED_REFS[cache_key]

    meta = MetaData()
    meta.reflect(bind=engine)

    refs: list[tuple[Table, str]] = []
    files_table_name = "files"
    for table in meta.tables.values():
        for col in table.columns:
            for fk in col.foreign_keys:
                if fk.column.table.name != files_table_name:
                    continue
                # Skip FK relationships with CASCADE delete — those rows are
                # dependent metadata, not independent references.
                ondelete = (fk.ondelete or "").upper()
                if ondelete == "CASCADE":
                    continue
                refs.append((table, col.name))

    _CACHED_REFS[cache_key] = refs
    return refs


def count_file_references(
    session: Session,
    file_ids: Sequence[Any] | None = None,
) -> dict[Any, int]:
    """Count independent usage references to files across the database.

    Uses SQLAlchemy metadata reflection to discover every foreign key that
    points to the ``files`` table (excluding cascade-dependent tables like
    ``file_tasks``), then aggregates the reference counts.

    Args:
        session: The SQLAlchemy session to use for the query.
        file_ids: An optional sequence of file IDs to filter by.  If *None*,
            counts references for **all** files.

    Returns:
        A mapping of ``{file_id: total_reference_count}``.  File IDs with
        zero references are omitted.
    """
    if file_ids is not None and len(file_ids) == 0:
        return {}

    engine = cast(Engine, session.get_bind())
    refs = _get_file_references(engine)

    if not refs:
        return {}

    def _execute_query(chunk_ids: Sequence[Any] | None) -> dict[Any, int]:
        subqueries = []
        for table, colname in refs:
            col = table.c[colname]
            stmt = select(col.label("file_id"), func.count().label("cnt")).where(
                col.isnot(None)
            )

            if chunk_ids is not None:
                stmt = stmt.where(col.in_(list(chunk_ids)))

            stmt = stmt.group_by(col)
            subqueries.append(stmt)

        union = union_all(*subqueries).alias("u")
        final = select(union.c.file_id, func.sum(union.c.cnt).label("total")).group_by(
            union.c.file_id
        )

        rows = session.execute(final).all()
        return {row.file_id: int(row.total) for row in rows}

    if file_ids is None:
        return _execute_query(None)

    result: dict[Any, int] = {}
    iterator = iter(file_ids)
    while chunk := tuple(islice(iterator, QUERY_CHUNK_SIZE)):
        chunk_result = _execute_query(chunk)
        for k, v in chunk_result.items():
            result[k] = result.get(k, 0) + v

    return result
