from sqlalchemy import create_engine

from include.database.models.documents import Document, DocumentRevision
from tools.explain_query_plans import EXPECTED_INDEXES, QUERIES, explain, time_query


def test_expected_indexes_match_document_models():
    assert EXPECTED_INDEXES["documents"] <= {
        index.name for index in Document.__table__.indexes
    }
    assert EXPECTED_INDEXES["document_revisions"] <= {
        index.name for index in DocumentRevision.__table__.indexes
    }


def test_queries_match_current_node_schema(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'query-plans.db'}")
    schema = """
        CREATE TABLE nodes (
            id TEXT PRIMARY KEY,
            type TEXT NOT NULL,
            name TEXT NOT NULL,
            parent_id TEXT,
            inherit INTEGER NOT NULL,
            status INTEGER NOT NULL
        );
        CREATE TABLE folders (id TEXT PRIMARY KEY);
        CREATE TABLE documents (id TEXT PRIMARY KEY, current_revision_id TEXT);
        CREATE TABLE files (id TEXT PRIMARY KEY, active INTEGER NOT NULL);
        CREATE TABLE document_revisions (
            id TEXT PRIMARY KEY,
            document_id TEXT NOT NULL,
            file_id TEXT NOT NULL,
            created_time REAL NOT NULL,
            parent_revision_id TEXT
        );
    """
    with engine.begin() as conn:
        for statement in schema.split(";"):
            if statement.strip():
                conn.exec_driver_sql(statement)
        conn.exec_driver_sql(
            "INSERT INTO nodes VALUES ('/', 'directory', 'root', NULL, 1, 0)"
        )
        conn.exec_driver_sql("INSERT INTO folders VALUES ('/')")

    params = {
        "pattern": "%",
        "limit": 64,
        "folder_id": "/",
        "document_id": "",
        "revision_id": "",
    }
    for sql in QUERIES.values():
        normalized_sql = "\n".join(line.rstrip() for line in sql.strip().splitlines())
        assert explain(engine, normalized_sql, params)
        row_count, mean_ms, max_ms = time_query(engine, normalized_sql, params, runs=1)
        assert row_count >= 0
        assert 0 <= mean_ms <= max_ms
