"""index document revision lookups

Revision ID: 0460356a5ba6
Revises: 3c496a214a87
Create Date: 2026-09-08 18:10:31.438263

"""
from collections.abc import Sequence

from alembic import op


# revision identifiers, used by Alembic.
revision: str = "0460356a5ba6"
down_revision: str | Sequence[str] | None = "3c496a214a87"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table("document_revisions", schema=None) as batch_op:
        batch_op.create_index(
            "ix_document_revisions_document_created_id",
            ["document_id", "created_time", "id"],
            unique=False,
        )
        batch_op.create_index(
            "ix_document_revisions_parent_revision_id",
            ["parent_revision_id"],
            unique=False,
        )

    with op.batch_alter_table("documents", schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f("ix_documents_current_revision_id"),
            ["current_revision_id"],
            unique=False,
        )


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("documents", schema=None) as batch_op:
        batch_op.drop_index(batch_op.f("ix_documents_current_revision_id"))

    with op.batch_alter_table("document_revisions", schema=None) as batch_op:
        batch_op.drop_index("ix_document_revisions_parent_revision_id")
        batch_op.drop_index("ix_document_revisions_document_created_id")
