from types import MappingProxyType

from include.domains.access.permissions import Permissions

DEFAULT_GROUP_PERMISSIONS: MappingProxyType[str, tuple[Permissions, ...]] = (
    MappingProxyType(
        {
            "user": (
                Permissions.CONFIGURE_AUTH_METHODS,
                Permissions.SEARCH,
                Permissions.SET_USERNAME,
            ),
            "sysop": (
                Permissions.PURGE,
                Permissions.DELETE_REVISION,
                Permissions.BYPASS_DACL,
                Permissions.BYPASS_TRAVERSE_CHECKING,
                Permissions.SHUTDOWN,
                Permissions.VIEW_SETTINGS,
                Permissions.MANAGE_SETTINGS,
                Permissions.DIAGNOSTICS,
                Permissions.VIEW_SCHEDULES,
                Permissions.MANAGE_SCHEDULES,
                Permissions.CREATE_USER,
                Permissions.DELETE_USER,
                Permissions.SET_NICKNAME,
                Permissions.SUPER_SET_USERNAME,
                Permissions.MANAGE_USER_STATUS,
                Permissions.GET_USER_INFO,
                Permissions.SET_USER_PERMISSIONS,
                Permissions.GET_GROUP_INFO,
                Permissions.CHANGE_USER_GROUPS,
                Permissions.SUPER_CONFIGURE_AUTH_METHODS,
                Permissions.LIST_USERS,
                Permissions.LIST_GROUPS,
                Permissions.CREATE_GROUP,
                Permissions.DELETE_GROUP,
                Permissions.RENAME_GROUP,
                Permissions.SET_GROUP_PERMISSIONS,
                Permissions.BYPASS_LOCKDOWN,
                Permissions.BYPASS_DOCUMENT_CREATION_RATE_LIMIT,
                Permissions.BYPASS_DOCUMENT_DOWNLOAD_RATE_LIMIT,
                Permissions.BYPASS_REQUEST_RATE_LIMIT,
                Permissions.APPLY_LOCKDOWN,
                Permissions.VIEW_AUDIT_LOGS,
                Permissions.SUPER_SET_USER_AVATAR,
                Permissions.DEBUGGING,
                Permissions.SUPER_LIST_USER_AUTH_METHODS,
                Permissions.MANAGE_KEYRINGS,
                Permissions.LIST_BANNED_SUBNETS,
                Permissions.MANAGE_BANNED_SUBNETS,
                Permissions.LIST_AUTH_LOCKOUTS,
                Permissions.UNLOCK_AUTH_LOCKOUTS,
                Permissions.SUPER_SET_NICKNAME,
                Permissions.SET_USER_AVATAR,
            ),
        }
    )
)
