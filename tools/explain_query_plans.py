from __future__ import annotations

import argparse
import statistics
import time
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import SQLAlchemyError

EXPECTED_INDEXES = {
    "folders": {
        "ix_folders_parent_status_lower_name_id",
        "ix_folders_status_lower_name_id",
        "ix_folders_status_created_time_id",
    },
    "documents": {
        "ix_documents_folder_status_lower_title_id",
        "ix_documents_status_lower_title_id",
        "ix_documents_status_created_time_id",
        "ix_documents_current_revision_id",
    },
    "document_revisions": {
        "ix_document_revisions_document_created_id",
        "ix_document_revisions_parent_revision_id",
    },
    "files": {"ix_files_active_size_id"},
}

QUERIES = {
    "search_directory_candidates": """
        SELECT id, name, lower(name) AS name_sort_key
        FROM folders
        WHERE status != 1 AND name LIKE :pattern
        ORDER BY lower(name), id
        LIMIT :limit
    """,
    "effective_active_revision_chain": """
        WITH RECURSIVE current_chain(
            document_id, revision_id, revision_created_time, file_id,
            parent_revision_id, file_active, depth
        ) AS (
            SELECT d.id, dr.id, dr.created_time, dr.file_id,
                   dr.parent_revision_id, f.active, 0
            FROM documents d
            JOIN document_revisions dr ON d.current_revision_id = dr.id
            JOIN files f ON dr.file_id = f.id
            WHERE d.status != 1 AND d.title LIKE :pattern

            UNION ALL

            SELECT current_chain.document_id, parent_revision.id,
                   parent_revision.created_time, parent_revision.file_id,
                   parent_revision.parent_revision_id, parent_file.active,
                   current_chain.depth + 1
            FROM current_chain
            JOIN document_revisions parent_revision
                ON current_chain.parent_revision_id = parent_revision.id
            JOIN files parent_file ON parent_revision.file_id = parent_file.id
        )
        SELECT document_id, revision_id, revision_created_time, depth
        FROM current_chain
        WHERE file_active = 1
        ORDER BY document_id, depth
        LIMIT :limit
    """,
    "access_ancestor_tree": """
        WITH RECURSIVE anc(id, parent_id, inherit) AS (
            SELECT id, parent_id, inherit
            FROM folders
            WHERE id = :folder_id

            UNION

            SELECT f.id, f.parent_id, f.inherit
            FROM folders f
            INNER JOIN anc ON f.id = anc.parent_id
        )
        SELECT DISTINCT id FROM anc
    """,
    "deletion_subtree": """
        WITH RECURSIVE subtree(id, parent_id, status) AS (
            SELECT id, parent_id, status
            FROM folders
            WHERE id = :folder_id

            UNION ALL

            SELECT f.id, f.parent_id, f.status
            FROM folders f
            INNER JOIN subtree s ON f.parent_id = s.id
            WHERE f.status = 0
        )
        SELECT id FROM subtree WHERE id != :folder_id
    """,
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Explain and time recursive CTE and listing/search query plans."
    )
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--sqlite", type=Path, help="Path to a SQLite database file.")
    target.add_argument(
        "--url",
        help=(
            "SQLAlchemy database URL, for example "
            "mysql+mysqlconnector://user:pass@localhost:3306/app_db"
        ),
    )
    parser.add_argument("--query", default="%", help="LIKE pattern or search term.")
    parser.add_argument("--folder-id", help="Folder ID for recursive tree queries.")
    parser.add_argument("--limit", type=int, default=64)
    parser.add_argument("--runs", type=int, default=5)
    return parser.parse_args()


def make_engine(args: argparse.Namespace) -> Engine:
    if args.sqlite:
        return create_engine(f"sqlite:///{args.sqlite}")
    return create_engine(args.url)


def scalar_or_none(
    engine: Engine, sql: str, params: dict[str, Any] | None = None
) -> Any:
    with engine.connect() as conn:
        return conn.execute(text(sql), params or {}).scalar()


def first_folder_id(engine: Engine) -> str | None:
    return scalar_or_none(engine, "SELECT id FROM folders ORDER BY id LIMIT 1")


def table_count(engine: Engine, table_name: str) -> int | None:
    try:
        return scalar_or_none(engine, f"SELECT COUNT(*) FROM {table_name}")
    except SQLAlchemyError:
        return None


def sqlite_indexes(engine: Engine, table_name: str) -> set[str]:
    with engine.connect() as conn:
        rows = conn.exec_driver_sql(f"PRAGMA index_list({table_name})").fetchall()
    return {row[1] for row in rows}


def mysql_indexes(engine: Engine, table_name: str) -> set[str]:
    with engine.connect() as conn:
        rows = conn.execute(text(f"SHOW INDEX FROM {table_name}")).mappings()
        return {row["Key_name"] for row in rows}


def table_indexes(engine: Engine, table_name: str) -> set[str]:
    dialect = engine.dialect.name
    if dialect == "sqlite":
        return sqlite_indexes(engine, table_name)
    if dialect == "mysql":
        return mysql_indexes(engine, table_name)
    raise RuntimeError(f"Index inspection is not implemented for {dialect!r}.")


def explain_prefix(engine: Engine) -> str:
    if engine.dialect.name == "sqlite":
        return "EXPLAIN QUERY PLAN "
    if engine.dialect.name == "mysql":
        return "EXPLAIN FORMAT=JSON "
    return "EXPLAIN "


def explain(engine: Engine, sql: str, params: dict[str, Any]) -> list[Any]:
    with engine.connect() as conn:
        try:
            rows = conn.execute(text(explain_prefix(engine) + sql), params).fetchall()
        except SQLAlchemyError:
            rows = conn.execute(text("EXPLAIN " + sql), params).fetchall()
    return [tuple(row) for row in rows]


def time_query(
    engine: Engine, sql: str, params: dict[str, Any], runs: int
) -> tuple[int, float, float]:
    durations = []
    row_count = 0
    for _ in range(runs):
        started = time.perf_counter()
        with engine.connect() as conn:
            rows = conn.execute(text(sql), params).fetchall()
        durations.append((time.perf_counter() - started) * 1000)
        row_count = len(rows)
    return row_count, statistics.mean(durations), max(durations)


def print_lines(lines: Iterable[str]) -> None:
    for line in lines:
        print(line)


def main() -> None:
    args = parse_args()
    engine = make_engine(args)
    folder_id = args.folder_id or first_folder_id(engine)
    if folder_id is None:
        raise SystemExit("No folder row found; pass --folder-id or seed the database.")

    pattern = args.query if "%" in args.query else f"%{args.query}%"
    params = {"pattern": pattern, "limit": args.limit, "folder_id": folder_id}

    print(f"Dialect: {engine.dialect.name}")
    print(f"Folder seed: {folder_id}")
    print("Table counts:")
    for table in ("folders", "documents", "document_revisions", "files"):
        print(f"  {table}: {table_count(engine, table)}")

    print("\nExpected index check:")
    for table, expected in EXPECTED_INDEXES.items():
        try:
            existing = table_indexes(engine, table)
        except SQLAlchemyError as exc:
            print(f"  {table}: unable to inspect indexes ({exc})")
            continue
        missing = sorted(expected - existing)
        state = "ok" if not missing else f"missing {missing}"
        print(f"  {table}: {state}")

    for name, sql in QUERIES.items():
        normalized_sql = "\n".join(line.rstrip() for line in sql.strip().splitlines())
        print(f"\n=== {name} ===")
        print("SQL:")
        print(normalized_sql)
        print("EXPLAIN:")
        for row in explain(engine, normalized_sql, params):
            print(f"  {row}")
        row_count, mean_ms, max_ms = time_query(
            engine, normalized_sql, params, args.runs
        )
        print(f"Rows: {row_count}")
        print(f"Timing: mean={mean_ms:.3f}ms max={max_ms:.3f}ms runs={args.runs}")


if __name__ == "__main__":
    main()
