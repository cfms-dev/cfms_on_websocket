"""string-revision-ids

Revision ID: d3da8345e1a2
Revises: ddacf7741794
Create Date: 2026-05-25 12:00:00.000000

"""
import secrets
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'd3da8345e1a2'
down_revision: Union[str, Sequence[str], None] = 'ddacf7741794'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    conn = op.get_bind()

    # Pre-compute the mapping from old integer IDs to new hex strings.
    old_ids = [
        row[0] for row in
        conn.execute(sa.text("SELECT id FROM document_revisions")).fetchall()
    ]
    id_map = {old_id: secrets.token_hex(32) for old_id in old_ids}

    # Drop FK constraints first so we can modify the referenced columns.
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.drop_constraint(
            'fk_documents_current_revision_id_document_revisions',
            type_='foreignkey'
        )

    with op.batch_alter_table('document_revisions', schema=None) as batch_op:
        batch_op.drop_constraint(
            'fk_document_revisions_parent_revision_id_document_revisions',
            type_='foreignkey'
        )

    # Add new string columns alongside the old integer ones.
    with op.batch_alter_table('document_revisions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('new_id', sa.String(64), nullable=True))
        batch_op.add_column(sa.Column('new_parent_revision_id', sa.String(64), nullable=True))

    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('new_current_revision_id', sa.String(64), nullable=True))

    # Populate the new columns using the pre-computed mapping.
    for old_id, new_hex in id_map.items():
        conn.execute(
            sa.text("UPDATE document_revisions SET new_id = :new WHERE id = :old"),
            {"new": new_hex, "old": old_id}
        )
        conn.execute(
            sa.text("UPDATE documents SET new_current_revision_id = :new WHERE current_revision_id = :old"),
            {"new": new_hex, "old": old_id}
        )
        conn.execute(
            sa.text("UPDATE document_revisions SET new_parent_revision_id = :new WHERE parent_revision_id = :old"),
            {"new": new_hex, "old": old_id}
        )

    # Drop old integer columns and rename new string columns.
    with op.batch_alter_table('document_revisions', schema=None) as batch_op:
        batch_op.drop_column('id')
        batch_op.drop_column('parent_revision_id')
        batch_op.alter_column('new_id', new_column_name='id',
                              existing_type=sa.String(64), nullable=False)
        batch_op.alter_column('new_parent_revision_id', new_column_name='parent_revision_id',
                              existing_type=sa.String(64), nullable=True)
        batch_op.create_primary_key('pk_document_revisions', ['id'])

    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.drop_column('current_revision_id')
        batch_op.alter_column('new_current_revision_id', new_column_name='current_revision_id',
                              existing_type=sa.String(64), nullable=True)

    # Recreate FK constraints.
    with op.batch_alter_table('document_revisions', schema=None) as batch_op:
        batch_op.create_foreign_key(
            'fk_document_revisions_parent_revision_id_document_revisions',
            'document_revisions', ['parent_revision_id'], ['id']
        )

    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.create_foreign_key(
            'fk_documents_current_revision_id_document_revisions',
            'document_revisions', ['current_revision_id'], ['id']
        )


def downgrade() -> None:
    conn = op.get_bind()

    # Drop FKs before altering columns.
    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.drop_constraint(
            'fk_documents_current_revision_id_document_revisions',
            type_='foreignkey'
        )

    with op.batch_alter_table('document_revisions', schema=None) as batch_op:
        batch_op.drop_constraint(
            'fk_document_revisions_parent_revision_id_document_revisions',
            type_='foreignkey'
        )

    # Pre-compute mapping from hex strings back to integer IDs.
    # Use row number as the new integer ID.
    hex_ids = [
        row[0] for row in
        conn.execute(sa.text("SELECT id FROM document_revisions ORDER BY created_time")).fetchall()
    ]
    id_map = {hex_id: idx + 1 for idx, hex_id in enumerate(hex_ids)}

    # Add temporary integer columns.
    with op.batch_alter_table('document_revisions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('new_id', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('new_parent_revision_id', sa.Integer(), nullable=True))

    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('new_current_revision_id', sa.Integer(), nullable=True))

    # Populate integer columns from the reverse mapping.
    for hex_id, new_int in id_map.items():
        conn.execute(
            sa.text("UPDATE document_revisions SET new_id = :new WHERE id = :old"),
            {"new": new_int, "old": hex_id}
        )
        conn.execute(
            sa.text("UPDATE documents SET new_current_revision_id = :new WHERE current_revision_id = :old"),
            {"new": new_int, "old": hex_id}
        )
        conn.execute(
            sa.text("UPDATE document_revisions SET new_parent_revision_id = :new WHERE parent_revision_id = :old"),
            {"new": new_int, "old": hex_id}
        )

    # Drop hex string columns and rename integer columns.
    with op.batch_alter_table('document_revisions', schema=None) as batch_op:
        batch_op.drop_column('id')
        batch_op.drop_column('parent_revision_id')
        batch_op.alter_column('new_id', new_column_name='id',
                              existing_type=sa.Integer(), nullable=False)
        batch_op.alter_column('new_parent_revision_id', new_column_name='parent_revision_id',
                              existing_type=sa.Integer(), nullable=True)
        batch_op.create_primary_key('pk_document_revisions', ['id'])

    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.drop_column('current_revision_id')
        batch_op.alter_column('new_current_revision_id', new_column_name='current_revision_id',
                              existing_type=sa.Integer(), nullable=True)

    # Recreate FK constraints.
    with op.batch_alter_table('document_revisions', schema=None) as batch_op:
        batch_op.create_foreign_key(
            'fk_document_revisions_parent_revision_id_document_revisions',
            'document_revisions', ['parent_revision_id'], ['id']
        )

    with op.batch_alter_table('documents', schema=None) as batch_op:
        batch_op.create_foreign_key(
            'fk_documents_current_revision_id_document_revisions',
            'document_revisions', ['current_revision_id'], ['id']
        )
