"""preserve float precision across databases

Revision ID: 7bddfba0d8aa
Revises: 170e0a16133e
Create Date: 2026-08-26 00:35:36.120982

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

revision: str = "7bddfba0d8aa"
down_revision: str | Sequence[str] | None = "170e0a16133e"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None

_FLOAT_COLUMNS = {
    "audit_entries": (("logged_time", False),),
    "compiled_access_rule_sets": (("created_at", False),),
    "document_revisions": (("created_time", False),),
    "documents": (("created_time", False),),
    "file_deduplication_tasks": (
        ("available_at", False),
        ("lease_expires_at", True),
        ("created_time", False),
    ),
    "file_tasks": (("start_time", False), ("end_time", True)),
    "files": (("created_time", False),),
    "folders": (("created_time", False),),
    "group_permissions": (("start_time", False), ("end_time", True)),
    "keyrings": (("created_time", False),),
    "object_access_entries": (("start_time", False), ("end_time", True)),
    "rate_limit_buckets": (
        ("tokens", False),
        ("last_refill_at", False),
        ("last_denied_at", True),
        ("last_attempt", False),
    ),
    "risk_ip_accounts": (("last_attempt", False),),
    "system_states": (("updated_at", False),),
    "user_memberships": (("start_time", False), ("end_time", True)),
    "user_permissions": (("start_time", False), ("end_time", True)),
    "userblock_entries": (
        ("timestamp", False),
        ("not_before", False),
        ("not_after", False),
    ),
    "users": (
        ("passwd_last_modified", False),
        ("last_login", True),
        ("created_time", False),
    ),
}


def _alter_float_columns(
    existing_type: sa.types.TypeEngine,
    target_type: sa.types.TypeEngine,
) -> None:
    if op.get_bind().dialect.name != "mysql":
        return

    for table_name, columns in _FLOAT_COLUMNS.items():
        with op.batch_alter_table(table_name, schema=None) as batch_op:
            for column_name, nullable in columns:
                batch_op.alter_column(
                    column_name,
                    existing_type=existing_type,
                    type_=target_type,
                    existing_nullable=nullable,
                )


def upgrade() -> None:
    """Upgrade schema."""
    _alter_float_columns(sa.Float(), sa.Double())


def downgrade() -> None:
    """Downgrade schema."""
    _alter_float_columns(sa.Double(), sa.Float())
