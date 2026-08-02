"""grant request rate limit bypass

Revision ID: 47c4c49d237b
Revises: 7e576d23d5f9
Create Date: 2026-08-01 13:46:15.858353

"""
from typing import Sequence

import sqlalchemy as sa
from alembic import op


# revision identifiers, used by Alembic.
revision: str = "47c4c49d237b"
down_revision: str | Sequence[str] | None = "7e576d23d5f9"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PERMISSION = "bypass_request_rate_limit"


def _permission_tables():
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
    )


def upgrade() -> None:
    connection = op.get_bind()
    user_groups, group_permissions = _permission_tables()
    sysop_exists = connection.execute(
        sa.select(user_groups.c.group_name).where(
            user_groups.c.group_name == "sysop"
        )
    ).first()
    if not sysop_exists:
        return

    grant_exists = connection.execute(
        sa.select(group_permissions.c.permission).where(
            group_permissions.c.group_name == "sysop",
            group_permissions.c.permission == _PERMISSION,
            group_permissions.c.granted == sa.true(),
        )
    ).first()
    if grant_exists:
        return

    connection.execute(
        group_permissions.insert().values(
            group_name="sysop",
            permission=_PERMISSION,
            granted=True,
            start_time=0.0,
            end_time=None,
        )
    )


def downgrade() -> None:
    _user_groups, group_permissions = _permission_tables()
    op.get_bind().execute(
        group_permissions.delete().where(
            group_permissions.c.group_name == "sysop",
            group_permissions.c.permission == _PERMISSION,
            group_permissions.c.granted == sa.true(),
        )
    )
