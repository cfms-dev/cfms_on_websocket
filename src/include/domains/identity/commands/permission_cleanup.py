from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy import delete, func, select
from sqlalchemy.engine import CursorResult
from sqlalchemy.orm import Session

from include.database.models.identity import UserGroupPermission, UserPermission


@dataclass(frozen=True, slots=True)
class PermissionEntryCounts:
    user_entries: int = 0
    group_entries: int = 0

    @property
    def total(self) -> int:
        return self.user_entries + self.group_entries


def _count_expired_entries(
    session: Session,
    model: type[UserPermission | UserGroupPermission],
    cutoff: float,
) -> int:
    return int(
        session.scalar(
            select(func.count())
            .select_from(model)
            .where(model.end_time.is_not(None), model.end_time < cutoff)
        )
        or 0
    )


def count_expired_permission_entries(
    session: Session,
    cutoff: float,
) -> PermissionEntryCounts:
    return PermissionEntryCounts(
        user_entries=_count_expired_entries(session, UserPermission, cutoff),
        group_entries=_count_expired_entries(session, UserGroupPermission, cutoff),
    )


def _purge_expired_entry_batch(
    session: Session,
    model: type[UserPermission | UserGroupPermission],
    cutoff: float,
    batch_size: int,
) -> int:
    entry_ids = list(
        session.scalars(
            select(model.id)
            .where(model.end_time.is_not(None), model.end_time < cutoff)
            .order_by(model.end_time, model.id)
            .limit(batch_size)
        )
    )
    if not entry_ids:
        return 0

    result = cast(
        CursorResult[Any],
        session.execute(
            delete(model)
            .where(
                model.id.in_(entry_ids),
                model.end_time.is_not(None),
                model.end_time < cutoff,
            )
            .execution_options(synchronize_session="fetch")
        ),
    )
    return result.rowcount


def purge_expired_permission_entries(
    session: Session,
    cutoff: float,
    batch_size: int,
) -> PermissionEntryCounts:
    return PermissionEntryCounts(
        user_entries=_purge_expired_entry_batch(
            session, UserPermission, cutoff, batch_size
        ),
        group_entries=_purge_expired_entry_batch(
            session, UserGroupPermission, cutoff, batch_size
        ),
    )
