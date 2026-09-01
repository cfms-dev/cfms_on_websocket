import time
from dataclasses import dataclass

from maintenance.runtime import enter_server_root, load_database_models

_SECONDS_PER_DAY = 24 * 60 * 60


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

    from include.config.validation import IdentityPermissionRetentionPolicy
    from include.database.session import Session
    from include.domains.identity.commands.permission_cleanup import (
        count_expired_permission_entries,
    )

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

    from include.config.validation import IdentityPermissionRetentionPolicy
    from include.database.session import Session
    from include.domains.identity.commands.permission_cleanup import (
        count_expired_permission_entries,
        purge_expired_permission_entries,
    )

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
