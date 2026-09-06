def test_database_models_register_core_tables(monkeypatch, protected_test_config):
    monkeypatch.chdir(protected_test_config.src_dir)

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


def test_database_models_export_node_only(monkeypatch, protected_test_config):
    monkeypatch.chdir(protected_test_config.src_dir)

    import include.database.models as models
    from include.database.models import documents

    legacy_name = "Base" + "Object"

    assert models.Node is documents.Node
    assert "Node" in models.__all__
    assert "Node" in documents.__all__
    assert not hasattr(models, legacy_name)
    assert not hasattr(documents, legacy_name)
    assert legacy_name not in models.__all__
    assert legacy_name not in documents.__all__
