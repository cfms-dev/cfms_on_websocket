import logging

import pytest
import tomlkit
from sqlalchemy import insert, select, update

from tests.maintenance.test_backup_format_compatibility import (
    _dump_backup_tables,
    _new_database,
    _read_jsonl,
    _RootedStorage,
    _seed_source,
    _test_progress,
    _write_config,
    _write_jsonl,
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
    caplog.set_level(logging.DEBUG, logger="maintenance.backup.core")
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
    assert "document_access_rules" not in result["tables"]
    assert "folder_access_rules" not in result["tables"]
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


def test_legacy_access_rule_backup_rows_restore_as_compiled_rules(
    backup_context, tmp_path
):
    from maintenance.backup.core import (
        BACKUP_FORMAT_VERSION,
        _restore_database,
        _validate_manifest,
    )

    base = backup_context.Base
    target_engine, target_session = _new_database(base, tmp_path / "target.db")
    extract_dir = tmp_path / "legacy-payload"
    tables_dir = extract_dir / "tables"

    folder_rows = [
        {
            "id": "folder-legacy",
            "name": "Legacy Folder",
            "created_time": 1_700_000_000.0,
            "parent_id": None,
            "status": 0,
            "status_operation_id": None,
            "inherit": True,
        }
    ]
    document_rows = [
        {
            "id": "doc-legacy",
            "title": "Legacy Document",
            "created_time": 1_700_000_001.0,
            "folder_id": "folder-legacy",
            "current_revision_id": None,
            "status": 0,
            "status_operation_id": None,
            "inherit": True,
        }
    ]
    folder_rule_rows = [
        {
            "id": 1,
            "folder_id": "folder-legacy",
            "access_type": "read",
            "rule_data": {
                "match": "all",
                "match_groups": [{"groups": {"match": "all", "require": ["sysop"]}}],
            },
        }
    ]
    document_rule_rows = [
        {
            "id": 2,
            "document_id": "doc-legacy",
            "access_type": "manage",
            "rule_data": {
                "match": "all",
                "match_groups": [
                    {"rights": {"match": "all", "require": ["list_users"]}}
                ],
            },
        }
    ]

    _write_jsonl(tables_dir / "folders.jsonl", folder_rows)
    _write_jsonl(tables_dir / "documents.jsonl", document_rows)
    _write_jsonl(tables_dir / "folder_access_rules.jsonl", folder_rule_rows)
    _write_jsonl(tables_dir / "document_access_rules.jsonl", document_rule_rows)

    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["documents"],
        "tables": {
            "folders": {"rows": len(folder_rows)},
            "documents": {"rows": len(document_rows)},
            "folder_access_rules": {"rows": len(folder_rule_rows)},
            "document_access_rules": {"rows": len(document_rule_rows)},
        },
        "files": [],
        "configuration": {},
    }

    _validate_manifest(manifest)
    _restore_database(extract_dir, manifest, target_session)

    with target_engine.connect() as connection:
        tables = base.metadata.tables
        compiled_rules_table = tables["compiled_access_rules"]
        rule_sets_table = tables["compiled_access_rule_sets"]
        compiled_rules = (
            connection.execute(
                select(
                    compiled_rules_table,
                    rule_sets_table.c.node_id.label("node_id"),
                )
                .join(
                    rule_sets_table,
                    compiled_rules_table.c.rule_set_id == rule_sets_table.c.id,
                )
                .order_by(rule_sets_table.c.node_id)
            )
            .mappings()
            .all()
        )
        memberships = (
            connection.execute(select(tables["compiled_access_rule_memberships"]))
            .mappings()
            .all()
        )
        rights = (
            connection.execute(select(tables["compiled_access_rule_rights"]))
            .mappings()
            .all()
        )
        rule_sets = (
            connection.execute(
                select(rule_sets_table).order_by(rule_sets_table.c.node_id)
            )
            .mappings()
            .all()
        )
        nodes = (
            connection.execute(select(tables["nodes"]).order_by(tables["nodes"].c.id))
            .mappings()
            .all()
        )

    assert [(row["node_id"], row["access_type"]) for row in compiled_rules] == [
        ("doc-legacy", "manage"),
        ("folder-legacy", "read"),
    ]
    assert [row["node_id"] for row in rule_sets] == ["doc-legacy", "folder-legacy"]
    assert {
        row["id"]: row["access_rule_set_id"] for row in nodes if row["id"] != "/"
    } == {row["node_id"]: row["id"] for row in rule_sets}
    assert [row["group_name"] for row in memberships] == ["sysop"]
    assert [row["permission"] for row in rights] == ["list_users"]


def test_current_access_rule_backup_manifest_uses_compiled_tables(
    backup_context, tmp_path
):
    from maintenance.backup.core import _stage_backup_payload

    base = backup_context.Base
    source_engine, source_session = _new_database(base, tmp_path / "source.db")
    source_storage = tmp_path / "source-storage"
    staging_dir = tmp_path / "staging"
    source_storage.mkdir()
    staging_dir.mkdir()
    _seed_source(base, source_engine, source_storage)
    tables = base.metadata.tables

    with source_engine.begin() as connection:
        connection.execute(
            insert(tables["nodes"]),
            [
                {
                    "id": "backup-empty-rules",
                    "type": "directory",
                    "name": "Backup Empty Rules",
                    "parent_id": "/",
                    "inherit": True,
                    "status": 0,
                    "status_operation_id": None,
                    "access_rule_set_id": None,
                },
                {
                    "id": "backup-inactive-rules",
                    "type": "directory",
                    "name": "Backup Inactive Rules",
                    "parent_id": "/",
                    "inherit": True,
                    "status": 0,
                    "status_operation_id": None,
                    "access_rule_set_id": None,
                },
            ],
        )
        connection.execute(
            insert(tables["folders"]),
            [
                {
                    "id": "backup-empty-rules",
                    "created_time": 1_700_000_010.0,
                },
                {
                    "id": "backup-inactive-rules",
                    "created_time": 1_700_000_011.0,
                },
            ],
        )
        connection.execute(
            insert(tables["compiled_access_rule_sets"]),
            [
                {
                    "id": "rule-set-empty",
                    "node_id": "backup-empty-rules",
                    "created_at": 1_700_000_010.0,
                },
                {
                    "id": "rule-set-inactive",
                    "node_id": "backup-inactive-rules",
                    "created_at": 1_700_000_011.0,
                },
            ],
        )
        connection.execute(
            update(tables["nodes"])
            .where(tables["nodes"].c.id == "backup-empty-rules")
            .values(access_rule_set_id="rule-set-empty")
        )
        connection.execute(
            insert(tables["compiled_access_rules"]),
            {
                "rule_set_id": "rule-set-inactive",
                "access_type": "read",
                "match_mode": "all",
            },
        )

    manifest = _stage_backup_payload(
        staging_dir,
        session_factory=source_session,
        storage_provider=_RootedStorage(source_storage),
        config=backup_context.source_config,
    )

    assert "compiled_access_rules" in manifest["tables"]
    assert "compiled_access_rule_sets" in manifest["tables"]
    assert "compiled_access_rule_groups" in manifest["tables"]
    assert "compiled_access_rule_memberships" in manifest["tables"]
    assert "compiled_access_rule_rights" in manifest["tables"]
    assert "document_access_rules" not in manifest["tables"]
    assert "folder_access_rules" not in manifest["tables"]

    exported_rule_sets = _read_jsonl(
        staging_dir / "tables" / "compiled_access_rule_sets.jsonl"
    )
    exported_nodes = _read_jsonl(staging_dir / "tables" / "nodes.jsonl")
    assert all("active_parent_id" not in row for row in exported_nodes)
    assert {row["id"] for row in exported_rule_sets} == {
        "rule-set-doc-1",
        "rule-set-folder-1",
    }
    assert {
        row["id"]: row["access_rule_set_id"]
        for row in exported_nodes
        if row["id"] in {"backup-empty-rules", "backup-inactive-rules"}
    } == {
        "backup-empty-rules": None,
        "backup-inactive-rules": None,
    }


def test_backup_with_nodes_and_legacy_subtype_names_is_upgraded(
    backup_context, tmp_path
):
    from maintenance.backup.core import (
        BACKUP_FORMAT_VERSION,
        _restore_database,
        _validate_manifest,
    )

    base = backup_context.Base
    target_engine, target_session = _new_database(base, tmp_path / "target.db")
    extract_dir = tmp_path / "legacy-node-payload"
    tables_dir = extract_dir / "tables"
    tables_dir.mkdir(parents=True)

    rows_by_table = {
        "nodes": [
            {"id": "/", "type": "directory", "inherit": True, "status": 0},
            {"id": "folder-old", "type": "directory", "inherit": True, "status": 0},
            {"id": "doc-old", "type": "document", "inherit": True, "status": 0},
        ],
        "folders": [
            {"id": "/", "name": "/", "parent_id": None, "created_time": 1.0},
            {
                "id": "folder-old",
                "name": "Archive",
                "parent_id": "/",
                "created_time": 2.0,
            },
        ],
        "documents": [
            {
                "id": "doc-old",
                "title": "Report",
                "folder_id": "folder-old",
                "created_time": 3.0,
                "current_revision_id": None,
            }
        ],
    }
    for table_name, rows in rows_by_table.items():
        _write_jsonl(tables_dir / f"{table_name}.jsonl", rows)
    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["documents"],
        "tables": {
            table_name: {"columns": list(rows[0]), "rows": len(rows)}
            for table_name, rows in rows_by_table.items()
        },
        "files": [],
        "configuration": {},
    }

    _validate_manifest(manifest)
    _restore_database(extract_dir, manifest, target_session)

    nodes = base.metadata.tables["nodes"]
    with target_engine.connect() as connection:
        restored = {
            row["id"]: (row["name"], row["parent_id"])
            for row in connection.execute(select(nodes)).mappings()
        }
    assert restored == {
        "/": ("/", None),
        "folder-old": ("Archive", "/"),
        "doc-old": ("Report", "folder-old"),
    }


def test_legacy_backup_rejects_active_cross_type_duplicate(backup_context, tmp_path):
    from maintenance.backup.core import (
        BACKUP_FORMAT_VERSION,
        _restore_database,
        _validate_manifest,
    )

    base = backup_context.Base
    _, target_session = _new_database(base, tmp_path / "target.db")
    extract_dir = tmp_path / "duplicate-payload"
    tables_dir = extract_dir / "tables"
    tables_dir.mkdir(parents=True)
    rows_by_table = {
        "folders": [
            {"id": "/", "name": "/", "parent_id": None, "created_time": 1.0},
            {"id": "folder", "name": "Same", "parent_id": "/", "created_time": 2.0},
        ],
        "documents": [
            {
                "id": "document",
                "title": "Same",
                "folder_id": "/",
                "created_time": 3.0,
                "current_revision_id": None,
            }
        ],
    }
    for table_name, rows in rows_by_table.items():
        _write_jsonl(tables_dir / f"{table_name}.jsonl", rows)
    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["documents"],
        "tables": {
            table_name: {"columns": list(rows[0]), "rows": len(rows)}
            for table_name, rows in rows_by_table.items()
        },
        "files": [],
        "configuration": {},
    }

    _validate_manifest(manifest)
    with pytest.raises(
        backup_context.BackupFormatError,
        match="document:document.*parent '/'.*name 'Same'",
    ):
        _restore_database(extract_dir, manifest, target_session)
