"""mount_to_root_node

Revision ID: 50df72915860
Revises: a8eba9cf56e2
Create Date: 2026-04-05 16:24:38.346346

"""

from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '50df72915860'
down_revision: str | Sequence[str] | None = 'a8eba9cf56e2'
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.execute("UPDATE folders SET parent_id = '/' WHERE parent_id IS NULL AND id != '/'")
    op.execute("UPDATE documents SET folder_id = '/' WHERE folder_id IS NULL AND id != '/'")


def downgrade() -> None:
    """Downgrade schema."""
    op.execute("UPDATE folders SET parent_id = NULL WHERE parent_id = '/' AND id != '/'")
    op.execute("UPDATE documents SET folder_id = NULL WHERE folder_id = '/' AND id != '/'")
