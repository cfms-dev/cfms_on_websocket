"""rename nickname permissions

Revision ID: 03197fed3401
Revises: 3815ba18197b
Create Date: 2026-11-11 13:10:39.570142

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "03197fed3401"
down_revision: str | Sequence[str] | None = "3815ba18197b"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_RENAMES = {
    "rename_user": "set_nickname",
    "super_rename_user": "super_set_nickname",
}


def _rename_permissions(renames: dict[str, str]) -> None:
    connection = op.get_bind()
    for table_name in ("user_permissions", "group_permissions"):
        permissions = sa.table(table_name, sa.column("permission", sa.String()))
        connection.execute(
            permissions.update()
            .where(permissions.c.permission.in_(renames))
            .values(permission=sa.case(renames, value=permissions.c.permission))
        )


def upgrade() -> None:
    _rename_permissions(_RENAMES)


def downgrade() -> None:
    _rename_permissions({new: old for old, new in _RENAMES.items()})
