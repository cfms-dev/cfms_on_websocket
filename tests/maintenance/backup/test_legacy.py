import uuid

import pytest
from sqlalchemy import select

from .support import (
    _write_jsonl,
)

pytestmark = pytest.mark.component


@pytest.mark.parametrize("has_policy_table", [False, True])
def test_auth_restore_converts_only_legacy_archives(
    database_factory, backup_context, tmp_path, has_policy_table
):
    from include.database.models.auth import (
        UserAuthPolicy,
        UserPasswordCredential,
        UserTotpCredential,
    )
    from maintenance.backup.archive import _validate_manifest
    from maintenance.backup.format import BACKUP_FORMAT_VERSION
    from maintenance.backup.restore import _restore_database

    _, sessions = database_factory(backup_context.Base, tmp_path / "target.db")
    root = tmp_path / "payload"
    (root / "tables").mkdir(parents=True)
    user_id = uuid.uuid4()
    rows = {
        "users": [
            {
                "id": str(user_id),
                "username": "legacy",
                "nickname": None,
                "avatar_id": None,
                "last_login": None,
                "created_time": 1.0,
                "status": 0,
                "status_comment_id": None,
                "secret_key": "secret",
                "preference_dek_id": None,
            }
        ],
        "user_passwords": [
            {"user_id": str(user_id), "pass_hash": "hash", "passwd_last_modified": 0.0}
        ],
        "user_totp_credentials": [
            {
                "user_id": str(user_id),
                "secret": "secret",
                "enabled": True,
                "backup_codes": "[]",
                "created_time": 1.0,
            }
        ],
    }
    if has_policy_table:
        rows["user_auth_policies"] = []
        rows["user_passwords"][0]["credential_id"] = "a" * 32
        rows["user_totp_credentials"][0]["credential_id"] = "b" * 32
    for name, values in rows.items():
        _write_jsonl(root / "tables" / f"{name}.jsonl", values)
    manifest = {
        "format_version": BACKUP_FORMAT_VERSION,
        "components": ["accounts"],
        "tables": {
            name: {"columns": list(values[0]) if values else [], "rows": len(values)}
            for name, values in rows.items()
        },
        "files": [],
        "configuration": {},
    }
    _validate_manifest(manifest)
    _restore_database(root, manifest, sessions)
    with sessions() as session:
        password = session.get(UserPasswordCredential, user_id)
        totp = session.get(UserTotpCredential, user_id)
        assert len(password.credential_id) == len(totp.credential_id) == 32
        policy = session.get(UserAuthPolicy, (user_id, "login"))
        if has_policy_table:
            assert policy is None
        else:
            assert policy.chains == [
                [{"method": "password", "credential_ids": [password.credential_id]}]
            ]
            assert session.get(UserAuthPolicy, (user_id, "mfa")).chains == [
                [{"method": "totp", "credential_ids": [totp.credential_id]}]
            ]


def test_backup_with_nodes_and_legacy_subtype_names_is_upgraded(
    database_factory, backup_context, tmp_path
):
    from maintenance.backup.archive import _validate_manifest
    from maintenance.backup.format import BACKUP_FORMAT_VERSION
    from maintenance.backup.restore import _restore_database

    base = backup_context.Base
    target_engine, target_session = database_factory(base, tmp_path / "target.db")
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


def test_legacy_backup_rejects_active_cross_type_duplicate(
    backup_context, tmp_path, database_factory
):
    from maintenance.backup.archive import _validate_manifest
    from maintenance.backup.format import BACKUP_FORMAT_VERSION
    from maintenance.backup.restore import _restore_database

    base = backup_context.Base
    _, target_session = database_factory(base, tmp_path / "target.db")
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
