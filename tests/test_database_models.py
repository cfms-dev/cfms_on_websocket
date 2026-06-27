import importlib

import pytest


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
        "users",
    }
    assert expected_tables <= set(Base.metadata.tables)


@pytest.mark.parametrize(
    "module_name",
    [
        "include.domains.access.models",
        "include.domains.documents.base",
        "include.domains.documents.files",
        "include.domains.documents.metadata",
        "include.domains.documents.models",
        "include.domains.identity.models",
        "include.domains.keyrings.models",
        "include.domains.operations.models",
        "include.domains.security.models",
    ],
)
def test_legacy_model_paths_are_removed(module_name):
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(module_name)
