from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine

from include.database.models.documents import Document, DocumentRevision
from tools import explain_query_plans
from tools.explain_query_plans import EXPECTED_INDEXES, QUERIES, explain, time_query


@pytest.mark.unit
def test_expected_indexes_match_document_models():
    assert EXPECTED_INDEXES["documents"] <= {
        index.name for index in Document.__table__.indexes
    }
    assert EXPECTED_INDEXES["document_revisions"] <= {
        index.name for index in DocumentRevision.__table__.indexes
    }


@pytest.fixture
def query_engine():
    engine = create_engine("sqlite:///:memory:")
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
    try:
        with engine.begin() as conn:
            for statement in schema.split(";"):
                if statement.strip():
                    conn.exec_driver_sql(statement)
            conn.exec_driver_sql(
                "INSERT INTO nodes VALUES ('/', 'directory', 'root', NULL, 1, 0)"
            )
            conn.exec_driver_sql("INSERT INTO folders VALUES ('/')")
        yield engine
    finally:
        engine.dispose()


@pytest.mark.component
@pytest.mark.parametrize("query_name", QUERIES)
def test_query_can_be_explained_against_node_schema(query_engine, query_name):
    params = {
        "pattern": "%",
        "limit": 64,
        "folder_id": "/",
        "document_id": "",
        "revision_id": "",
    }

    plan = explain(query_engine, QUERIES[query_name], params)

    assert plan


@pytest.mark.component
@pytest.mark.parametrize(
    ("query_name", "expected_rows"),
    [
        ("search_directory_candidates", 1),
        ("effective_active_revision_chain", 0),
        ("access_ancestor_tree", 1),
        ("deletion_subtree", 0),
        ("revisions_by_document", 0),
        ("child_revisions", 0),
        ("documents_by_current_revision", 0),
    ],
    ids=lambda value: value if isinstance(value, str) else None,
)
def test_time_query_reports_rows_from_seeded_node_schema(
    query_engine, monkeypatch, query_name, expected_rows
):
    params = {
        "pattern": "%",
        "limit": 64,
        "folder_id": "/",
        "document_id": "",
        "revision_id": "",
    }
    clock = iter((10.0, 10.125))
    monkeypatch.setattr(
        explain_query_plans, "time", SimpleNamespace(perf_counter=lambda: next(clock))
    )

    row_count, mean_ms, max_ms = time_query(
        query_engine, QUERIES[query_name], params, runs=1
    )

    assert row_count == expected_rows
    assert mean_ms == 125.0
    assert max_ms == 125.0


@pytest.mark.component
def test_time_query_reports_mean_and_max_across_runs(query_engine, monkeypatch):
    clock = iter((10.0, 10.125, 11.0, 11.25, 12.0, 12.375))
    monkeypatch.setattr(
        explain_query_plans, "time", SimpleNamespace(perf_counter=lambda: next(clock))
    )

    result = time_query(query_engine, "SELECT id FROM nodes", {}, runs=3)

    assert result == (1, 250.0, 375.0)
