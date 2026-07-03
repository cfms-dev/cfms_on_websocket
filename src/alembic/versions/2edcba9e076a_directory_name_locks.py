"""directory name locks

Revision ID: 2edcba9e076a
Revises: e37338db17cc
Create Date: 2026-07-03 19:27:28.237437

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '2edcba9e076a'
down_revision: Union[str, Sequence[str], None] = 'e37338db17cc'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "directory_name_locks",
        sa.Column("parent_id", sa.VARCHAR(length=255), nullable=False),
        sa.Column("name", sa.VARCHAR(length=255), nullable=False),
        sa.PrimaryKeyConstraint(
            "parent_id", "name", name=op.f("pk_directory_name_locks")
        ),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("directory_name_locks")
