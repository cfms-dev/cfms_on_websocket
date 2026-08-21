from collections.abc import Iterable

from include.database.models.identity import UserGroupPermission, UserPermission


def serialize_permission_entries(
    entries: Iterable[UserPermission | UserGroupPermission],
) -> list[dict[str, str | bool | float | None]]:
    return [
        {
            "permission": str(entry.permission),
            "granted": entry.granted,
            "start_time": entry.start_time,
            "end_time": entry.end_time,
        }
        for entry in entries
    ]
