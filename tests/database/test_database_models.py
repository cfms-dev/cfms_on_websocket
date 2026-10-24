import pytest

pytestmark = pytest.mark.unit


def test_database_models_register_core_tables():

    import include.database.models  # noqa: F401
    from include.database.session import Base

    expected_tables = {
        "audit_entries",
        "banned_subnets",
        "comments",
        "document_revisions",
        "documents",
        "files",
        "keyrings",
        "nodes",
        "schedule_executions",
        "schedules",
        "scheduling_runtime_state",
        "users",
    }
    assert expected_tables <= set(Base.metadata.tables)
