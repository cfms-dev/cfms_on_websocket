import sqlite3
from contextlib import closing

import pytest

from include.domains.identity.default_groups import DEFAULT_GROUP_PERMISSIONS


@pytest.mark.unit
def test_default_group_permissions_preserve_the_explicit_seed_contract():
    assert {
        group: set(values) for group, values in DEFAULT_GROUP_PERMISSIONS.items()
    } == {
        "user": {"configure_auth_methods", "search"},
        "sysop": {
            "move",
            "shutdown",
            "super_create_document",
            "super_create_directory",
            "super_list_directory",
            "create_document",
            "create_directory",
            "delete_document",
            "rename_document",
            "delete_directory",
            "rename_directory",
            "manage_system",
            "diagnostics",
            "view_schedules",
            "manage_schedules",
            "create_user",
            "delete_user",
            "rename_user",
            "manage_user_status",
            "get_user_info",
            "set_user_permissions",
            "get_group_info",
            "change_user_groups",
            "super_configure_auth_methods",
            "view_access_rules",
            "set_access_rules",
            "view_metadata",
            "set_metadata_tags",
            "list_users",
            "list_groups",
            "create_group",
            "delete_group",
            "rename_group",
            "set_group_permissions",
            "bypass_lockdown",
            "bypass_document_creation_rate_limit",
            "bypass_document_download_rate_limit",
            "bypass_request_rate_limit",
            "apply_lockdown",
            "view_audit_logs",
            "manage_access",
            "view_access_entries",
            "block",
            "unblock",
            "super_set_user_avatar",
            "debugging",
            "super_list_user_auth_methods",
            "list_revisions",
            "view_revision",
            "set_current_revision",
            "delete_revision",
            "manage_keyrings",
            "list_user_blocks",
            "list_banned_subnets",
            "manage_banned_subnets",
            "list_auth_lockouts",
            "unlock_auth_lockouts",
            "purge",
            "restore",
            "list_deleted_items",
            "super_rename_user",
            "set_user_avatar",
        },
    }
    assert len(DEFAULT_GROUP_PERMISSIONS["user"]) == 2
    assert len(DEFAULT_GROUP_PERMISSIONS["sysop"]) == 62


@pytest.mark.integration
def test_fresh_server_seeds_default_groups_with_original_time_defaults(
    server_process, test_server_settings
):
    with closing(
        sqlite3.connect(
            f"{(test_server_settings.src_dir / 'app.db').as_uri()}?mode=ro", uri=True
        )
    ) as connection:
        rows = connection.execute(
            "SELECT group_name, permission, granted, start_time, end_time "
            "FROM group_permissions WHERE group_name IN ('user', 'sysop')"
        ).fetchall()

    assert {(row[0], row[1]) for row in rows} == {
        (group, permission)
        for group, values in DEFAULT_GROUP_PERMISSIONS.items()
        for permission in values
    }
    assert len(rows) == 64
    assert all(
        granted == 1 and start > 0.0 and end is None
        for _, _, granted, start, end in rows
    )
