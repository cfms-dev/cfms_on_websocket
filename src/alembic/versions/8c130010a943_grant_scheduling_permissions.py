"""grant scheduling permissions

Revision ID: 8c130010a943
Revises: ab7efda19079
Create Date: 2026-09-02 19:41:16.993199

"""
import time
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "8c130010a943"
down_revision: str | Sequence[str] | None = "ab7efda19079"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_MIGRATION_OWNER = "migration:8c130010a943"
_PERMISSIONS = ("view_schedules", "manage_schedules")


def _tables():
    return (
        sa.table("user_groups", sa.column("group_name", sa.String())),
        sa.table(
            "group_permissions",
            sa.column("group_name", sa.String()),
            sa.column("permission", sa.String()),
            sa.column("granted", sa.Boolean()),
            sa.column("start_time", sa.Double()),
            sa.column("end_time", sa.Double()),
        ),
        sa.table(
            "system_states",
            sa.column("owner", sa.String()),
            sa.column("state_key", sa.String()),
            sa.column("schema_version", sa.Integer()),
            sa.column("revision", sa.BigInteger()),
            sa.column("payload", sa.JSON()),
            sa.column("updated_at", sa.Double()),
        ),
    )


def upgrade() -> None:
    connection = op.get_bind()
    user_groups, group_permissions, system_states = _tables()
    sysop_exists = connection.execute(
        sa.select(user_groups.c.group_name).where(
            user_groups.c.group_name == "sysop"
        )
    ).first()
    if not sysop_exists:
        return

    for permission in _PERMISSIONS:
        grant_exists = connection.execute(
            sa.select(group_permissions.c.permission).where(
                group_permissions.c.group_name == "sysop",
                group_permissions.c.permission == permission,
                group_permissions.c.granted == sa.true(),
            )
        ).first()
        if grant_exists:
            continue
        connection.execute(
            group_permissions.insert().values(
                group_name="sysop",
                permission=permission,
                granted=True,
                start_time=0.0,
                end_time=None,
            )
        )
        connection.execute(
            system_states.insert().values(
                owner=_MIGRATION_OWNER,
                state_key=permission,
                schema_version=1,
                revision=1,
                payload={},
                updated_at=time.time(),
            )
        )


def downgrade() -> None:
    connection = op.get_bind()
    _user_groups, group_permissions, system_states = _tables()
    for permission in _PERMISSIONS:
        marker = connection.execute(
            sa.select(system_states.c.state_key).where(
                system_states.c.owner == _MIGRATION_OWNER,
                system_states.c.state_key == permission,
            )
        ).first()
        if marker is None:
            continue
        connection.execute(
            group_permissions.delete().where(
                group_permissions.c.group_name == "sysop",
                group_permissions.c.permission == permission,
                group_permissions.c.granted == sa.true(),
            )
        )
        connection.execute(
            system_states.delete().where(
                system_states.c.owner == _MIGRATION_OWNER,
                system_states.c.state_key == permission,
            )
        )
