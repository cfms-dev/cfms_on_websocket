"""administer security blocks

Revision ID: 052c13c19603
Revises: 7a0988691147
Create Date: 2026-07-24 19:25:32.365819

"""

import datetime as dt
from collections.abc import Sequence
from typing import Any

import sqlalchemy as sa
from alembic import op


revision: str = "052c13c19603"
down_revision: str | Sequence[str] | None = "7a0988691147"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_PERMISSIONS = (
    "list_banned_subnets",
    "manage_banned_subnets",
    "list_auth_lockouts",
    "unlock_auth_lockouts",
)


def _as_epoch(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    if not isinstance(value, dt.datetime):
        raise TypeError(f"Unsupported datetime value: {value!r}")
    if value.tzinfo is None:
        value = value.replace(tzinfo=dt.UTC)
    return value.timestamp()


def _as_datetime(value: Any) -> dt.datetime | None:
    if value is None:
        return None
    return dt.datetime.fromtimestamp(float(value), dt.UTC).replace(tzinfo=None)


def _convert_time_columns(
    table_name: str,
    primary_keys: tuple[tuple[str, sa.types.TypeEngine], ...],
    time_columns: tuple[tuple[str, bool], ...],
    *,
    to_epoch: bool,
    indexed_columns: tuple[str, ...] = (),
) -> None:
    connection = op.get_bind()
    source_type = sa.DateTime() if to_epoch else sa.Double()
    target_type = sa.Double() if to_epoch else sa.DateTime()
    suffix = "epoch" if to_epoch else "datetime"
    temporary_names = {
        name: f"__migration_{name}_{suffix}" for name, _nullable in time_columns
    }

    for temporary_name in temporary_names.values():
        op.add_column(
            table_name, sa.Column(temporary_name, target_type, nullable=True)
        )

    table = sa.table(
        table_name,
        *(sa.column(name, column_type) for name, column_type in primary_keys),
        *(sa.column(name, source_type) for name, _nullable in time_columns),
        *(sa.column(name, target_type) for name in temporary_names.values()),
    )
    selected_columns = [table.c[name] for name, _column_type in primary_keys]
    selected_columns.extend(table.c[name] for name, _nullable in time_columns)
    converter = _as_epoch if to_epoch else _as_datetime
    for row in connection.execute(sa.select(*selected_columns)).mappings():
        condition = sa.and_(
            *(table.c[name] == row[name] for name, _column_type in primary_keys)
        )
        connection.execute(
            table.update()
            .where(condition)
            .values(
                **{
                    temporary_names[name]: converter(row[name])
                    for name, _nullable in time_columns
                }
            )
        )

    if indexed_columns:
        with op.batch_alter_table(table_name) as batch_op:
            for column_name in indexed_columns:
                batch_op.drop_index(op.f(f"ix_{table_name}_{column_name}"))

    with op.batch_alter_table(table_name) as batch_op:
        for name, _nullable in time_columns:
            batch_op.drop_column(name)
        for name, nullable in time_columns:
            batch_op.alter_column(
                temporary_names[name],
                new_column_name=name,
                existing_type=target_type,
                nullable=nullable,
            )
    if indexed_columns:
        with op.batch_alter_table(table_name) as batch_op:
            for column_name in indexed_columns:
                batch_op.create_index(
                    op.f(f"ix_{table_name}_{column_name}"),
                    [column_name],
                    unique=False,
                )


def _upgrade_banned_subnets() -> None:
    connection = op.get_bind()
    op.add_column(
        "banned_subnets",
        sa.Column("__migration_created_at_epoch", sa.Double(), nullable=True),
    )
    op.add_column(
        "banned_subnets", sa.Column("starts_at", sa.Double(), nullable=True)
    )
    op.add_column(
        "banned_subnets", sa.Column("expires_at", sa.Double(), nullable=True)
    )
    table = sa.table(
        "banned_subnets",
        sa.column("subnet", sa.String()),
        sa.column("created_at", sa.DateTime()),
        sa.column("__migration_created_at_epoch", sa.Double()),
        sa.column("starts_at", sa.Double()),
    )
    for row in connection.execute(
        sa.select(table.c.subnet, table.c.created_at)
    ).mappings():
        created_at = _as_epoch(row["created_at"])
        connection.execute(
            table.update()
            .where(table.c.subnet == row["subnet"])
            .values(
                __migration_created_at_epoch=created_at,
                starts_at=created_at,
            )
        )

    with op.batch_alter_table("banned_subnets") as batch_op:
        batch_op.drop_column("created_at")
        batch_op.alter_column(
            "__migration_created_at_epoch",
            new_column_name="created_at",
            existing_type=sa.Double(),
            nullable=False,
        )
        batch_op.alter_column(
            "starts_at", existing_type=sa.Double(), nullable=False
        )


def _downgrade_banned_subnets() -> None:
    connection = op.get_bind()
    op.add_column(
        "banned_subnets",
        sa.Column("__migration_created_at_datetime", sa.DateTime(), nullable=True),
    )
    table = sa.table(
        "banned_subnets",
        sa.column("subnet", sa.String()),
        sa.column("created_at", sa.Double()),
        sa.column("__migration_created_at_datetime", sa.DateTime()),
    )
    for row in connection.execute(
        sa.select(table.c.subnet, table.c.created_at)
    ).mappings():
        connection.execute(
            table.update()
            .where(table.c.subnet == row["subnet"])
            .values(__migration_created_at_datetime=_as_datetime(row["created_at"]))
        )

    with op.batch_alter_table("banned_subnets") as batch_op:
        batch_op.drop_column("created_at")
        batch_op.drop_column("expires_at")
        batch_op.drop_column("starts_at")
        batch_op.alter_column(
            "__migration_created_at_datetime",
            new_column_name="created_at",
            existing_type=sa.DateTime(),
            nullable=False,
            server_default=sa.text("CURRENT_TIMESTAMP"),
        )


def _grant_sysop_permissions() -> None:
    connection = op.get_bind()
    user_groups = sa.table("user_groups", sa.column("group_name", sa.String()))
    group_permissions = sa.table(
        "group_permissions",
        sa.column("group_name", sa.String()),
        sa.column("permission", sa.String()),
        sa.column("granted", sa.Boolean()),
        sa.column("start_time", sa.Double()),
        sa.column("end_time", sa.Double()),
    )
    if not connection.execute(
        sa.select(user_groups.c.group_name).where(user_groups.c.group_name == "sysop")
    ).first():
        return
    for permission in _PERMISSIONS:
        exists = connection.execute(
            sa.select(group_permissions.c.permission).where(
                group_permissions.c.group_name == "sysop",
                group_permissions.c.permission == permission,
                group_permissions.c.granted == sa.true(),
            )
        ).first()
        if not exists:
            connection.execute(
                group_permissions.insert().values(
                    group_name="sysop",
                    permission=permission,
                    granted=True,
                    start_time=0.0,
                    end_time=None,
                )
            )


def upgrade() -> None:
    _upgrade_banned_subnets()
    _convert_time_columns(
        "account_throttles",
        (("username", sa.String()), ("factor", sa.String())),
        (("last_attempt", False), ("locked_until", True)),
        to_epoch=True,
        indexed_columns=("last_attempt",),
    )
    _convert_time_columns(
        "login_throttles",
        (("username", sa.String()), ("ip_address", sa.String())),
        (
            ("window_started_at", False),
            ("last_attempt", False),
            ("locked_until", True),
        ),
        to_epoch=True,
        indexed_columns=("last_attempt",),
    )
    _convert_time_columns(
        "traffic_throttles",
        (("ip_address", sa.String()),),
        (
            ("window_started_at", False),
            ("last_attempt", False),
            ("locked_until", True),
        ),
        to_epoch=True,
        indexed_columns=("last_attempt",),
    )
    _grant_sysop_permissions()


def downgrade() -> None:
    connection = op.get_bind()
    group_permissions = sa.table(
        "group_permissions",
        sa.column("group_name", sa.String()),
        sa.column("permission", sa.String()),
    )
    connection.execute(
        group_permissions.delete().where(
            group_permissions.c.group_name == "sysop",
            group_permissions.c.permission.in_(_PERMISSIONS),
        )
    )
    _convert_time_columns(
        "traffic_throttles",
        (("ip_address", sa.String()),),
        (
            ("window_started_at", False),
            ("last_attempt", False),
            ("locked_until", True),
        ),
        to_epoch=False,
        indexed_columns=("last_attempt",),
    )
    _convert_time_columns(
        "login_throttles",
        (("username", sa.String()), ("ip_address", sa.String())),
        (
            ("window_started_at", False),
            ("last_attempt", False),
            ("locked_until", True),
        ),
        to_epoch=False,
        indexed_columns=("last_attempt",),
    )
    _convert_time_columns(
        "account_throttles",
        (("username", sa.String()), ("factor", sa.String())),
        (("last_attempt", False), ("locked_until", True)),
        to_epoch=False,
        indexed_columns=("last_attempt",),
    )
    _downgrade_banned_subnets()
