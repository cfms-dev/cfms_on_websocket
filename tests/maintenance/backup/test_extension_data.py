import pytest
from sqlalchemy import inspect, select

from include.config import paths
from include.extensions.data import extension_metadata, load_extension_data
from tests.maintenance.backup.support import _RootedStorage
from tests.support.extension_data import example_data

__all__ = ["example_data"]
pytestmark = pytest.mark.component


def test_generic_extension_data_roundtrip(
    backup_context, example_data, database_factory, tmp_path
):
    base = backup_context.Base
    declarations = load_extension_data(base.metadata)
    metadata = extension_metadata(base.metadata, declarations)
    source, sessions = database_factory(base, tmp_path / "source.db")
    target, target_sessions = database_factory(base, tmp_path / "target.db")
    metadata.create_all(source)
    with source.begin() as connection:
        connection.execute(metadata.tables["example_parent"].insert(), {"id": 1})
        connection.execute(
            metadata.tables["example_child"].insert(),
            {
                "id": 2,
                "parent_id": 1,
                "value": b"extension bytes",
            },
        )
    storage = _RootedStorage(tmp_path / "storage")
    backup = tmp_path / "archive.conf"
    key = backup_context.export_backup(
        backup,
        session_factory=sessions,
        storage_provider=storage,
        config=backup_context.source_config,
        selection=backup_context.BackupExportSelection.from_component_values(
            ["accounts"]
        ),
    )
    backup_context.import_backup(
        backup,
        key,
        session_factory=target_sessions,
        db_engine=target,
        storage_provider=storage,
        config_path=tmp_path / "config.toml",
        init_path=tmp_path / "init",
    )
    with target.connect() as connection:
        assert connection.execute(select(metadata.tables["example_child"])).all() == [
            (2, 1, b"extension bytes")
        ]
    assert not set(declarations) & set(base.metadata.tables)


def test_export_does_not_create_absent_extension_tables(
    backup_context, database_factory, tmp_path
):
    source, sessions = database_factory(backup_context.Base, tmp_path / "source.db")
    backup_context.export_backup(
        tmp_path / "archive.conf",
        session_factory=sessions,
        storage_provider=_RootedStorage(tmp_path / "storage"),
        config=backup_context.source_config,
    )
    assert "user_oidc_credentials" not in inspect(source).get_table_names()


def test_missing_extension_cannot_silently_drop_data(
    backup_context,
    example_data,
    database_factory,
    tmp_path,
    monkeypatch,
):
    base = backup_context.Base
    metadata = extension_metadata(base.metadata, load_extension_data(base.metadata))
    source, sessions = database_factory(base, tmp_path / "source.db")
    target, target_sessions = database_factory(base, tmp_path / "target.db")
    metadata.create_all(source)
    with source.begin() as connection:
        connection.execute(metadata.tables["example_parent"].insert(), {"id": 1})
    backup = tmp_path / "archive.conf"
    storage = _RootedStorage(tmp_path / "storage")
    key = backup_context.export_backup(
        backup,
        session_factory=sessions,
        storage_provider=storage,
        config=backup_context.source_config,
    )
    empty = tmp_path / "no-extensions"
    empty.mkdir()
    monkeypatch.setattr(paths, "EXTENSION_ROOT", empty)
    with pytest.raises(backup_context.BackupFormatError, match="unsupported tables"):
        backup_context.import_backup(
            backup,
            key,
            session_factory=target_sessions,
            db_engine=target,
            storage_provider=storage,
            config_path=tmp_path / "config.toml",
            init_path=tmp_path / "init",
        )
    with pytest.raises(backup_context.BackupIntegrityError, match="Unregistered"):
        backup_context.export_backup(
            tmp_path / "second.conf",
            session_factory=sessions,
            storage_provider=storage,
            config=backup_context.source_config,
        )
    assert not {"example_parent", "example_child"} & set(
        inspect(target).get_table_names()
    )
