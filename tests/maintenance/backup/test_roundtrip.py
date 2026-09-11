import logging

import tomlkit
from sqlalchemy import select

from .roundtrip_support import _seed_source
from .support import (
    _dump_backup_tables,
    _new_database,
    _RootedStorage,
    _test_progress,
    _write_config,
)


def test_backup_header_and_roundtrip_restore(backup_context, tmp_path, caplog):
    base = backup_context.Base
    source_engine, source_session = _new_database(base, tmp_path / "source.db")
    target_engine, target_session = _new_database(base, tmp_path / "target.db")
    source_storage = tmp_path / "source-storage"
    target_storage = tmp_path / "target-storage"
    source_storage.mkdir()
    target_storage.mkdir()
    _seed_source(base, source_engine, source_storage)

    backup_path = tmp_path / "backup.conf"
    caplog.set_level(logging.DEBUG, logger="maintenance.backup")
    with _test_progress() as export_progress:
        key_text = backup_context.export_backup(
            backup_path,
            session_factory=source_session,
            storage_provider=_RootedStorage(source_storage),
            config=backup_context.source_config,
            progress=export_progress,
            show_progress_details=True,
        )

    assert backup_path.read_bytes().startswith(b"CONF")
    header = backup_context.read_backup_header(backup_path)
    assert header.created_at
    assert header.encryption == "AES-256-GCM"
    export_tasks = list(export_progress.tasks)
    assert any(
        task.description.startswith("Backup export completed")
        and task.completed == task.total
        for task in export_tasks
    )
    assert any(task.description.startswith("Exporting table") for task in export_tasks)
    assert any(
        task.description.startswith("Copying storage file") for task in export_tasks
    )
    assert any(
        task.description.startswith("Adding archive member") for task in export_tasks
    )
    archive_logs = [
        record.getMessage()
        for record in caplog.records
        if "Adding archive member" in record.getMessage()
    ]
    assert any("manifest.json" in message for message in archive_logs)
    assert any("tables/files.jsonl" in message for message in archive_logs)
    assert any("files/00000000.bin" in message for message in archive_logs)

    target_config = tmp_path / "target-config.toml"
    _write_config(target_config, secret_key="target-secret", pepper="target-pepper")
    init_path = tmp_path / "target-init"
    with _test_progress() as import_progress:
        result = backup_context.import_backup(
            backup_path,
            key_text,
            session_factory=target_session,
            db_engine=target_engine,
            storage_provider=_RootedStorage(target_storage),
            config_path=target_config,
            init_path=init_path,
            progress=import_progress,
            show_progress_details=True,
        )

    assert result["created_at"] == header.created_at
    assert "compiled_access_rule_sets" in result["tables"]
    assert "compiled_access_rules" in result["tables"]
    assert "schedules" in result["tables"]
    assert "document_access_rules" not in result["tables"]
    assert "folder_access_rules" not in result["tables"]
    assert "system_states" not in result["tables"]
    assert init_path.exists()
    import_tasks = list(import_progress.tasks)
    assert any(
        task.description.startswith("Backup import completed")
        and task.completed == task.total
        for task in import_tasks
    )
    assert any(
        task.description.startswith("Restoring storage file") for task in import_tasks
    )
    assert any(task.description.startswith("Restoring table") for task in import_tasks)
    assert _dump_backup_tables(base, source_engine) == _dump_backup_tables(
        base, target_engine
    )
    assert (target_storage / "content" / "files" / "doc.bin").read_bytes() == (
        source_storage / "content" / "files" / "doc.bin"
    ).read_bytes()
    assert (target_storage / "content" / "files" / "avatar.bin").read_bytes() == (
        source_storage / "content" / "files" / "avatar.bin"
    ).read_bytes()

    restored_config = tomlkit.parse(target_config.read_text(encoding="utf-8"))
    assert restored_config["security"]["pepper"] == "source-pepper"
    assert restored_config["server"]["secret_key"] == "source-secret-key"

    with target_engine.connect() as connection:
        compiled_rules = connection.execute(
            select(base.metadata.tables["compiled_access_rules"])
        ).all()
        file_tasks = connection.execute(
            select(base.metadata.tables["file_tasks"])
        ).all()
        account_throttles = connection.execute(
            select(base.metadata.tables["account_throttles"])
        ).all()
        rate_limit_buckets = connection.execute(
            select(base.metadata.tables["rate_limit_buckets"])
        ).all()
        risk_ip_accounts = connection.execute(
            select(base.metadata.tables["risk_ip_accounts"])
        ).all()
        login_throttles = connection.execute(
            select(base.metadata.tables["login_throttles"])
        ).all()
        traffic_throttles = connection.execute(
            select(base.metadata.tables["traffic_throttles"])
        ).all()
        system_states = connection.execute(
            select(base.metadata.tables["system_states"])
        ).all()
        assert len(compiled_rules) == 2
        rule_sets = connection.execute(
            select(base.metadata.tables["compiled_access_rule_sets"])
        ).all()
        assert len(rule_sets) == 2
        assert file_tasks == []
        assert account_throttles == []
        assert rate_limit_buckets == []
        assert risk_ip_accounts == []
        assert login_throttles == []
        assert system_states == []
        assert traffic_throttles == []

    from include.database.models.identity import User
    from include.domains.documents.queries.listing import (
        fetch_visible_search_candidate_rows,
    )

    with target_session() as session:
        user = User(
            username="bob",
            pass_hash="hash",
            passwd_last_modified=0.0,
            nickname="Bob",
            avatar_id=None,
            last_login=None,
            created_time=0.0,
            status=0,
            secret_key="bob-secret",
            totp_secret=None,
            totp_enabled=False,
            totp_backup_codes=None,
            preference_dek_id=None,
        )
        session.add(user)
        session.flush()

        visible_rows = fetch_visible_search_candidate_rows(
            session,
            user=user,
            now=1_700_000_001.0,
            query="Folder",
            sort_by="name",
            sort_order="asc",
            search_documents=False,
            search_directories=True,
            last_key=None,
            limit=10,
        )

        assert visible_rows == []
