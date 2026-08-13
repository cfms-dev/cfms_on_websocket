__all__ = ["Permissions"]

from enum import StrEnum


class Permissions(StrEnum):
    # File and directory operations
    MOVE = "move"
    CREATE_DOCUMENT = "create_document"
    DELETE_DOCUMENT = "delete_document"
    RENAME_DOCUMENT = "rename_document"
    CREATE_DIRECTORY = "create_directory"
    DELETE_DIRECTORY = "delete_directory"
    RENAME_DIRECTORY = "rename_directory"

    LIST_DELETED_ITEMS = "list_deleted_items"
    """permission to view the list of deleted documents/directories in a directory."""
    PURGE = "purge"
    """permission to permanently delete documents/directories."""
    RESTORE = "restore"
    """permission to restore documents/directories from deletion."""

    SEARCH = "search"
    """permission to search for documents/directories."""

    # Super operations
    SUPER_CREATE_DOCUMENT = "super_create_document"
    SUPER_CREATE_DIRECTORY = "super_create_directory"
    SUPER_LIST_DIRECTORY = "super_list_directory"
    SUPER_SET_PASSWD = "super_set_passwd"
    SUPER_SET_USER_AVATAR = "super_set_user_avatar"

    # System and management
    SHUTDOWN = "shutdown"
    MANAGE_SYSTEM = "manage_system"
    """
    A general permission for performing various system management 
    tasks that have not been assigned to other specific permissions.
    """
    DEBUGGING = "debugging"
    DIAGNOSTICS = "diagnostics"

    # User management
    CREATE_USER = "create_user"
    DELETE_USER = "delete_user"
    RENAME_USER = "rename_user"
    MANAGE_USER_STATUS = "manage_user_status"
    GET_USER_INFO = "get_user_info"
    LIST_USERS = "list_users"
    MANAGE_2FA = "manage_2fa"
    SET_PASSWD = "set_passwd"
    SET_USER_PERMISSIONS = "set_user_permissions"
    SET_USER_AVATAR = "set_user_avatar"

    SUPER_RENAME_USER = "super_rename_user"

    # Group management
    CREATE_GROUP = "create_group"
    DELETE_GROUP = "delete_group"
    RENAME_GROUP = "rename_group"
    GET_GROUP_INFO = "get_group_info"
    LIST_GROUPS = "list_groups"
    CHANGE_USER_GROUPS = "change_user_groups"
    SET_GROUP_PERMISSIONS = "set_group_permissions"

    # Access control and lockdown
    VIEW_ACCESS_RULES = "view_access_rules"
    SET_ACCESS_RULES = "set_access_rules"
    VIEW_METADATA = "view_metadata"
    SET_METADATA_TAGS = "set_metadata_tags"
    MANAGE_ACCESS = "manage_access"
    VIEW_ACCESS_ENTRIES = "view_access_entries"
    APPLY_LOCKDOWN = "apply_lockdown"
    BYPASS_LOCKDOWN = "bypass_lockdown"
    BYPASS_DOCUMENT_CREATION_RATE_LIMIT = "bypass_document_creation_rate_limit"
    BYPASS_DOCUMENT_DOWNLOAD_RATE_LIMIT = "bypass_document_download_rate_limit"
    BYPASS_REQUEST_RATE_LIMIT = "bypass_request_rate_limit"
    BLOCK = "block"
    UNBLOCK = "unblock"
    LIST_USER_BLOCKS = "list_user_blocks"
    LIST_BANNED_SUBNETS = "list_banned_subnets"
    MANAGE_BANNED_SUBNETS = "manage_banned_subnets"
    LIST_AUTH_LOCKOUTS = "list_auth_lockouts"
    UNLOCK_AUTH_LOCKOUTS = "unlock_auth_lockouts"

    # Logs and version control
    VIEW_AUDIT_LOGS = "view_audit_logs"
    LIST_REVISIONS = "list_revisions"
    VIEW_REVISION = "view_revision"
    SET_CURRENT_REVISION = "set_current_revision"
    DELETE_REVISION = "delete_revision"

    # Key management
    MANAGE_KEYRINGS = "manage_keyrings"
