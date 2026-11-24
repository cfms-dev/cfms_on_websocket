__all__ = ["Permissions"]

from enum import StrEnum


class Permissions(StrEnum):
    # Global file/tree gates (operations not purely delegated to CACL)
    PURGE = "purge"
    """Global gate to permanently destroy soft-deleted documents/directories."""
    DELETE_REVISION = "delete_revision"
    """Global gate to permanently destroy historical document revisions."""
    SEARCH = "search"
    """Global gate to search for documents/directories."""

    # CACL global capability bypasses (CEP-0002)
    BYPASS_DACL = "bypass_dacl"
    """Super-administrator recovery capability bypassing per-node CACL DACL checks and anti-lockout."""
    BYPASS_TRAVERSE_CHECKING = "bypass_traverse_checking"
    """Subject-level bypass for ancestor directory TRAVERSE checks."""

    # System and management
    SHUTDOWN = "shutdown"
    DEBUGGING = "debugging"
    VIEW_SETTINGS = "view_settings"
    MANAGE_SETTINGS = "manage_settings"
    DIAGNOSTICS = "diagnostics"
    VIEW_SCHEDULES = "view_schedules"
    MANAGE_SCHEDULES = "manage_schedules"

    # User management
    CREATE_USER = "create_user"
    DELETE_USER = "delete_user"
    SET_NICKNAME = "set_nickname"
    SET_USERNAME = "set_username"
    MANAGE_USER_STATUS = "manage_user_status"
    GET_USER_INFO = "get_user_info"
    LIST_USERS = "list_users"
    CONFIGURE_AUTH_METHODS = "configure_auth_methods"
    SUPER_CONFIGURE_AUTH_METHODS = "super_configure_auth_methods"
    SUPER_LIST_USER_AUTH_METHODS = "super_list_user_auth_methods"
    SET_USER_PERMISSIONS = "set_user_permissions"
    SET_USER_AVATAR = "set_user_avatar"
    SUPER_SET_USER_AVATAR = "super_set_user_avatar"
    SUPER_SET_NICKNAME = "super_set_nickname"
    SUPER_SET_USERNAME = "super_set_username"

    # Group management
    CREATE_GROUP = "create_group"
    DELETE_GROUP = "delete_group"
    RENAME_GROUP = "rename_group"
    GET_GROUP_INFO = "get_group_info"
    LIST_GROUPS = "list_groups"
    CHANGE_USER_GROUPS = "change_user_groups"
    SET_GROUP_PERMISSIONS = "set_group_permissions"

    # Lockdown, rate limits, and network/auth security
    APPLY_LOCKDOWN = "apply_lockdown"
    BYPASS_LOCKDOWN = "bypass_lockdown"
    BYPASS_DOCUMENT_CREATION_RATE_LIMIT = "bypass_document_creation_rate_limit"
    BYPASS_DOCUMENT_DOWNLOAD_RATE_LIMIT = "bypass_document_download_rate_limit"
    BYPASS_REQUEST_RATE_LIMIT = "bypass_request_rate_limit"
    LIST_BANNED_SUBNETS = "list_banned_subnets"
    MANAGE_BANNED_SUBNETS = "manage_banned_subnets"
    LIST_AUTH_LOCKOUTS = "list_auth_lockouts"
    UNLOCK_AUTH_LOCKOUTS = "unlock_auth_lockouts"

    # Audit logs
    VIEW_AUDIT_LOGS = "view_audit_logs"

    # Key management
    MANAGE_KEYRINGS = "manage_keyrings"
