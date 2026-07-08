def test_database_models_register_core_tables(monkeypatch, protected_test_config):
    monkeypatch.chdir(protected_test_config.src_dir)

    import include.database.models  # noqa: F401
    from include.database.session import Base

    expected_tables = {
        "audit_entries",
        "banned_subnets",
        "document_revisions",
        "documents",
        "files",
        "keyrings",
        "nodes",
        "users",
    }
    assert expected_tables <= set(Base.metadata.tables)
