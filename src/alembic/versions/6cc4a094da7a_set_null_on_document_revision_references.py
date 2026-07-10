"""set null on document revision references

Revision ID: 6cc4a094da7a
Revises: 0b73fbf3e15a
Create Date: 2026-07-09 19:29:57.252644

"""
from collections.abc import Sequence

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "6cc4a094da7a"
down_revision: str | Sequence[str] | None = "0b73fbf3e15a"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


NAMING_CONVENTION = {
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
}


def _find_fk_name(
    inspector: sa.engine.reflection.Inspector,
    table_name: str,
    constrained_columns: list[str],
    referred_table: str,
    referred_columns: list[str],
) -> str:
    for fk in inspector.get_foreign_keys(table_name):
        if (
            fk.get("constrained_columns") == constrained_columns
            and fk.get("referred_table") == referred_table
            and fk.get("referred_columns") == referred_columns
        ):
            return fk.get("name") or (
                f"fk_{table_name}_{constrained_columns[0]}_{referred_table}"
            )

    raise RuntimeError(
        "Could not find foreign key on "
        f"{table_name}({', '.join(constrained_columns)})"
    )


def _clear_orphan_revision_references() -> None:
    bind = op.get_bind()
    bind.execute(
        sa.text(
            """
            UPDATE documents
            SET current_revision_id = NULL
            WHERE current_revision_id IS NOT NULL
            AND NOT EXISTS (
                SELECT 1
                FROM document_revisions
                WHERE document_revisions.id = documents.current_revision_id
            )
            """
        )
    )
    bind.execute(
        sa.text(
            """
            UPDATE document_revisions
            SET parent_revision_id = NULL
            WHERE parent_revision_id IS NOT NULL
            AND NOT EXISTS (
                SELECT 1
                FROM document_revisions AS parent_revisions
                WHERE parent_revisions.id = document_revisions.parent_revision_id
            )
            """
        )
    )


def upgrade() -> None:
    """Upgrade schema."""
    _clear_orphan_revision_references()
    inspector = sa.inspect(op.get_bind())
    parent_revision_fk_name = _find_fk_name(
        inspector,
        "document_revisions",
        ["parent_revision_id"],
        "document_revisions",
        ["id"],
    )
    current_revision_fk_name = _find_fk_name(
        inspector,
        "documents",
        ["current_revision_id"],
        "document_revisions",
        ["id"],
    )

    with op.batch_alter_table(
        "document_revisions", schema=None, naming_convention=NAMING_CONVENTION
    ) as batch_op:
        batch_op.drop_constraint(parent_revision_fk_name, type_="foreignkey")
        batch_op.create_foreign_key(
            batch_op.f("fk_document_revisions_parent_revision_id_document_revisions"),
            "document_revisions",
            ["parent_revision_id"],
            ["id"],
            ondelete="SET NULL",
        )

    with op.batch_alter_table(
        "documents", schema=None, naming_convention=NAMING_CONVENTION
    ) as batch_op:
        batch_op.drop_constraint(current_revision_fk_name, type_="foreignkey")
        batch_op.create_foreign_key(
            batch_op.f("fk_documents_current_revision_id_document_revisions"),
            "document_revisions",
            ["current_revision_id"],
            ["id"],
            ondelete="SET NULL",
            use_alter=True,
        )


def downgrade() -> None:
    """Downgrade schema."""
    _clear_orphan_revision_references()
    inspector = sa.inspect(op.get_bind())
    current_revision_fk_name = _find_fk_name(
        inspector,
        "documents",
        ["current_revision_id"],
        "document_revisions",
        ["id"],
    )
    parent_revision_fk_name = _find_fk_name(
        inspector,
        "document_revisions",
        ["parent_revision_id"],
        "document_revisions",
        ["id"],
    )

    with op.batch_alter_table(
        "documents", schema=None, naming_convention=NAMING_CONVENTION
    ) as batch_op:
        batch_op.drop_constraint(current_revision_fk_name, type_="foreignkey")
        batch_op.create_foreign_key(
            batch_op.f("fk_documents_current_revision_id"),
            "document_revisions",
            ["current_revision_id"],
            ["id"],
        )

    with op.batch_alter_table(
        "document_revisions", schema=None, naming_convention=NAMING_CONVENTION
    ) as batch_op:
        batch_op.drop_constraint(parent_revision_fk_name, type_="foreignkey")
        batch_op.create_foreign_key(
            batch_op.f("fk_document_revisions_parent_revision_id_document_revisions"),
            "document_revisions",
            ["parent_revision_id"],
            ["id"],
        )
