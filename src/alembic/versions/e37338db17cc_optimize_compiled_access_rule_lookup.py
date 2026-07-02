"""optimize compiled access rule lookup

Revision ID: e37338db17cc
Revises: 6684e3c18160
Create Date: 2026-07-02 22:05:00.000000

"""

from collections.abc import Sequence

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "e37338db17cc"
down_revision: str | Sequence[str] | None = "6684e3c18160"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_index(
        "ix_compiled_access_rules_target_type_id_access",
        "compiled_access_rules",
        ["target_type", "target_id", "access_type"],
        unique=False,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(
        "ix_compiled_access_rules_target_type_id_access",
        table_name="compiled_access_rules",
    )
