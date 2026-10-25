import time
from dataclasses import dataclass
lazy from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
lazy from sqlalchemy.orm import Session as OrmSession

from include.domains.identity.default_groups import DEFAULT_GROUP_PERMISSIONS
from include.runtime_lock import RuntimeLockError, server_runtime_lock
from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.runtime import enter_server_root, load_database_models
lazy from include.config.validation import IdentityPermissionRetentionPolicy
lazy from include.database.models.identity import UserGroup, UserGroupPermission
lazy from include.database.session import Session
lazy from include.domains.identity.commands.permission_cleanup import (
    count_expired_permission_entries,
    purge_expired_permission_entries,
)

_SECONDS_PER_DAY = 24 * 60 * 60


@dataclass(frozen=True, slots=True)
class DefaultGroupPermissionDiff:
    group_names: tuple[str, ...]
    existing_permissions: frozenset[tuple[str, str]]
    missing_permissions: frozenset[tuple[str, str]]
    missing_groups: frozenset[str]


def _inspect_default_group_permissions(
    session: OrmSession, group_names: tuple[str, ...]
) -> DefaultGroupPermissionDiff:
    existing_groups = set(
        session.scalars(
            select(UserGroup.group_name).where(UserGroup.group_name.in_(group_names))
        )
    )
    expected = frozenset(
        (group_name, str(permission))
        for group_name in group_names
        if group_name in existing_groups
        for permission in DEFAULT_GROUP_PERMISSIONS[group_name]
    )
    recorded = frozenset(
        (group_name, permission)
        for group_name, permission in session.execute(
            select(
                UserGroupPermission.group_name, UserGroupPermission.permission
            ).where(UserGroupPermission.group_name.in_(group_names))
        )
    )
    return DefaultGroupPermissionDiff(
        group_names=group_names,
        existing_permissions=expected & recorded,
        missing_permissions=expected - recorded,
        missing_groups=frozenset(group_names) - existing_groups,
    )


def inspect_default_group_permissions(
    groups: Iterable[str] | None = None,
) -> DefaultGroupPermissionDiff:
    enter_server_root()
    load_database_models()
    group_names = tuple(
        sorted(set(DEFAULT_GROUP_PERMISSIONS if groups is None else groups))
    )
    try:
        with Session() as session:
            return _inspect_default_group_permissions(session, group_names)
    except SQLAlchemyError as exc:
        raise MaintenanceOperationError(
            f"Unable to inspect default group permissions: {exc}"
        ) from exc


def sync_default_group_permissions(preview: DefaultGroupPermissionDiff) -> int:
    server_root = enter_server_root()
    load_database_models()
    try:
        with server_runtime_lock(server_root), Session.begin() as session:
            current = _inspect_default_group_permissions(session, preview.group_names)
            if (
                current.missing_permissions != preview.missing_permissions
                or current.missing_groups != preview.missing_groups
            ):
                raise MaintenanceOperationError(
                    "Default group permission differences changed after preview. "
                    "Run the command again to review the current differences."
                )
            session.add_all(
                UserGroupPermission(
                    group_name=group_name,
                    permission=permission,
                    granted=True,
                    start_time=0.0,
                    end_time=None,
                )
                for group_name, permission in sorted(current.missing_permissions)
            )
        return len(current.missing_permissions)
    except (OSError, RuntimeLockError, SQLAlchemyError) as exc:
        raise MaintenanceOperationError(
            f"Unable to synchronize default group permissions: {exc}"
        ) from exc


@dataclass(frozen=True, slots=True)
class PermissionPurgeResult:
    cutoff: float
    user_entries: int
    group_entries: int

    @property
    def total(self) -> int:
        return self.user_entries + self.group_entries


def inspect_expired_permissions(now: float | None = None) -> PermissionPurgeResult:
    enter_server_root()
    load_database_models()

    policy = IdentityPermissionRetentionPolicy.from_config()
    reference_time = time.time() if now is None else now
    cutoff = reference_time - policy.retention_days * _SECONDS_PER_DAY
    with Session() as session:
        counts = count_expired_permission_entries(session, cutoff)

    return PermissionPurgeResult(
        cutoff=cutoff,
        user_entries=counts.user_entries,
        group_entries=counts.group_entries,
    )


def purge_expired_permissions(
    cutoff: float | None = None,
) -> PermissionPurgeResult:
    enter_server_root()
    load_database_models()

    policy = IdentityPermissionRetentionPolicy.from_config()
    if cutoff is None:
        cutoff = time.time() - policy.retention_days * _SECONDS_PER_DAY

    with Session() as session:
        eligible = count_expired_permission_entries(session, cutoff)

    batch_count = max(
        (eligible.user_entries + policy.batch_size - 1) // policy.batch_size,
        (eligible.group_entries + policy.batch_size - 1) // policy.batch_size,
    )
    removed_user_entries = 0
    removed_group_entries = 0
    for _ in range(batch_count):
        with Session.begin() as session:
            removed = purge_expired_permission_entries(
                session,
                cutoff,
                policy.batch_size,
            )
        removed_user_entries += removed.user_entries
        removed_group_entries += removed.group_entries

    return PermissionPurgeResult(
        cutoff=cutoff,
        user_entries=removed_user_entries,
        group_entries=removed_group_entries,
    )
