import uuid
from pathlib import Path

from sqlalchemy import insert, update

from .support import _insert_compiled_rule, _RootedStorage

ALICE_ID = uuid.UUID("12345678-1234-4234-9234-123456789abc")


def _seed_source(base, db_engine, storage_root: Path) -> None:
    storage = _RootedStorage(storage_root)
    with storage.fopen("content/files/doc.bin", "wb") as f:
        f.write(b"document payload")
    with storage.fopen("content/files/avatar.bin", "wb") as f:
        f.write(b"avatar payload")

    tables = base.metadata.tables
    now = 1_700_000_000.0
    created_at = now

    with db_engine.begin() as connection:
        connection.execute(
            insert(tables["comments"]),
            [
                {
                    "comment_id": 1,
                    "digest_version": 1,
                    "content_digest": bytes.fromhex(
                        "e28bca6fb18bcde822a03cfa87a802b94136c6367f1952229382517c9f6d64cc"
                    ),
                    "comment_text": "Repeated policy violations",
                    "comment_data": None,
                },
                {
                    "comment_id": 2,
                    "digest_version": 1,
                    "content_digest": bytes.fromhex(
                        "f2a01247ea2f1c75120f51d5514e9d562002bc363d3b93a15a11ca63912018bd"
                    ),
                    "comment_text": "manual incident",
                    "comment_data": None,
                },
                {
                    "comment_id": 3,
                    "digest_version": 1,
                    "content_digest": bytes.fromhex(
                        "52e5e2272062cc620938aabd097dc450e046b5e1ea7fb9b1da75f0bc51c4e710"
                    ),
                    "comment_text": "Original block reason",
                    "comment_data": None,
                },
            ],
        )
        connection.execute(
            insert(tables["files"]),
            [
                {
                    "id": "file-doc",
                    "sha256": None,
                    "path": "content/files/doc.bin",
                    "size": len(b"document payload"),
                    "created_time": now,
                    "active": True,
                },
                {
                    "id": "file-avatar",
                    "sha256": None,
                    "path": "content/files/avatar.bin",
                    "size": len(b"avatar payload"),
                    "created_time": now,
                    "active": True,
                },
            ],
        )
        connection.execute(
            insert(tables["users"]),
            {
                "id": ALICE_ID,
                "username": "alice",
                "nickname": "Alice",
                "avatar_id": "file-avatar",
                "last_login": None,
                "created_time": now,
                "status": 1,
                "status_comment_id": 1,
                "secret_key": "alice-secret",
                "preference_dek_id": None,
            },
        )
        connection.execute(
            insert(tables["user_passwords"]),
            {
                "user_id": ALICE_ID,
                "pass_hash": "preserved-password-hash",
                "passwd_last_modified": now,
            },
        )
        connection.execute(
            insert(tables["user_totp_credentials"]),
            {
                "user_id": ALICE_ID,
                "secret": "JBSWY3DPEHPK3PXP",
                "enabled": True,
                "backup_codes": "[]",
                "created_time": now,
            },
        )
        connection.execute(
            insert(tables["user_auth_public_keys"]),
            {
                "id": "auth-key",
                "user_id": ALICE_ID,
                "public_key_der": b"\x30\x00",
                "fingerprint": b"f" * 32,
                "created_time": now,
            },
        )
        connection.execute(
            insert(tables["schedules"]),
            {
                "id": "schedule-1",
                "task_name": "test.record",
                "task_contract_version": 1,
                "payload": {"value": 7},
                "trigger_type": "interval",
                "trigger_data": {
                    "seconds": 3600,
                    "start_at": "2023-11-14T22:13:20+00:00",
                },
                "timezone": "UTC",
                "system_managed": False,
                "enabled": True,
                "status": "active",
                "revision": 1,
                "next_run_at": now + 3600,
                "active_execution_id": None,
                "pending_scheduled_for": None,
                "created_by": ALICE_ID,
                "created_at": now,
                "updated_by": ALICE_ID,
                "updated_at": now,
                "deleted_at": None,
            },
        )
        connection.execute(
            insert(tables["user_groups"]),
            {
                "group_name": "sysop",
                "group_display_name": "Sysop",
            },
        )
        connection.execute(
            insert(tables["group_permissions"]),
            {
                "group_name": "sysop",
                "permission": "manage_system",
                "granted": True,
                "start_time": 0.0,
                "end_time": None,
            },
        )
        connection.execute(
            insert(tables["user_memberships"]),
            {
                "user_id": ALICE_ID,
                "group_name": "sysop",
                "start_time": 0.0,
                "end_time": None,
            },
        )
        connection.execute(
            insert(tables["user_permissions"]),
            {
                "user_id": ALICE_ID,
                "permission": "list_users",
                "granted": True,
                "start_time": 0.0,
                "end_time": None,
            },
        )
        connection.execute(
            insert(tables["keyrings"]),
            {
                "id": "key-1",
                "user_id": ALICE_ID,
                "content": "encrypted-dek",
                "label": "main",
                "created_time": now,
            },
        )
        connection.execute(
            update(tables["users"])
            .where(tables["users"].c.username == "alice")
            .values(preference_dek_id="key-1")
        )
        connection.execute(
            insert(tables["nodes"]),
            {
                "id": "/",
                "type": "directory",
                "name": "/",
                "parent_id": None,
                "inherit": True,
                "status": 0,
                "status_operation_id": None,
            },
        )
        connection.execute(
            insert(tables["folders"]),
            {"id": "/", "created_time": now},
        )
        connection.execute(
            insert(tables["nodes"]),
            {
                "id": "folder-1",
                "type": "directory",
                "name": "Folder",
                "parent_id": "/",
                "inherit": True,
                "status": 0,
                "status_operation_id": None,
            },
        )
        connection.execute(
            insert(tables["folders"]),
            {"id": "folder-1", "created_time": now},
        )
        connection.execute(
            insert(tables["nodes"]),
            {
                "id": "doc-1",
                "type": "document",
                "name": "Document",
                "parent_id": "folder-1",
                "inherit": True,
                "status": 1,
                "status_operation_id": "soft-delete-op",
            },
        )
        _insert_compiled_rule(
            connection,
            tables,
            target_id="folder-1",
            access_type="read",
            rule_data={
                "match": "all",
                "match_groups": [{"groups": {"match": "all", "require": ["sysop"]}}],
            },
        )
        connection.execute(
            insert(tables["documents"]),
            {
                "id": "doc-1",
                "created_time": now,
                "current_revision_id": None,
            },
        )
        connection.execute(
            insert(tables["document_revisions"]),
            {
                "id": "rev-1",
                "document_id": "doc-1",
                "file_id": "file-doc",
                "created_time": now,
                "parent_revision_id": None,
                "status": 0,
            },
        )
        connection.execute(
            update(tables["documents"])
            .where(tables["documents"].c.id == "doc-1")
            .values(current_revision_id="rev-1")
        )
        _insert_compiled_rule(
            connection,
            tables,
            target_id="doc-1",
            access_type="read",
            rule_data={
                "match": "all",
                "match_groups": [{"groups": {"match": "all", "require": ["sysop"]}}],
            },
        )
        connection.execute(
            insert(tables["document_metadata"]),
            {
                "document_id": "doc-1",
                "creator_id": ALICE_ID,
                "last_modified_by_id": ALICE_ID,
            },
        )
        connection.execute(
            insert(tables["document_metadata_tags"]),
            {
                "document_id": "doc-1",
                "tag": "important",
                "position": 1,
            },
        )
        connection.execute(
            insert(tables["object_access_entries"]),
            {
                "entity_type": "user",
                "entity_identifier": "alice",
                "target_type": "document",
                "target_identifier": "doc-1",
                "access_type": "read",
                "start_time": 0.0,
                "end_time": None,
            },
        )
        connection.execute(
            insert(tables["audit_entries"]),
            {
                "id": "audit-1",
                "action": "create_document",
                "user_id": ALICE_ID,
                "target": "doc-1",
                "data": {"ok": True},
                "result": 200,
                "remote_address": "127.0.0.1",
                "logged_time": now,
            },
        )
        connection.execute(
            insert(tables["userblock_entries"]),
            {
                "block_id": "block-1",
                "user_id": ALICE_ID,
                "timestamp": now,
                "not_before": 0.0,
                "not_after": -1.0,
                "target_type": "document",
                "target_id": "doc-1",
                "reason_comment_id": 3,
            },
        )
        connection.execute(
            insert(tables["userblock_sub_entries"]),
            {
                "parent_id": "block-1",
                "block_type": "read",
            },
        )
        connection.execute(
            insert(tables["banned_subnets"]),
            {
                "subnet": "192.0.2.0/24",
                "reason_comment_id": 2,
                "created_at": created_at,
                "starts_at": created_at,
                "expires_at": None,
            },
        )
        connection.execute(
            insert(tables["file_tasks"]),
            {
                "id": "task-1",
                "file_id": "file-doc",
                "status": 0,
                "mode": 0,
                "start_time": now,
                "end_time": now + 60,
                "encryption_key": "transient",
            },
        )
        connection.execute(
            insert(tables["login_throttles"]),
            {
                "username": "alice",
                "ip_address": "198.51.100.10",
                "failed_attempts": 3,
                "window_started_at": created_at,
                "last_attempt": created_at,
                "locked_until": created_at,
            },
        )
        connection.execute(
            insert(tables["traffic_throttles"]),
            {
                "ip_address": "198.51.100.11",
                "failed_attempts": 4,
                "window_started_at": created_at,
                "last_attempt": created_at,
                "locked_until": created_at,
            },
        )
        connection.execute(
            insert(tables["system_states"]),
            {
                "owner": "core",
                "state_key": "lockdown",
                "schema_version": 1,
                "revision": 1,
                "payload": {
                    "enabled": True,
                    "reason": "Maintenance",
                    "last_disabled_at": 0.0,
                },
                "updated_at": created_at,
            },
        )
