"""unify file task chunk size for resumable uploads

Revision ID: 3c0666dd9068
Revises: 8be3cdd47846
Create Date: 2026-07-31 10:17:17.079808

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = '3c0666dd9068'
down_revision: Union[str, Sequence[str], None] = '8be3cdd47846'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    with op.batch_alter_table('file_tasks', schema=None) as batch_op:
        batch_op.alter_column(
            'download_chunk_size',
            new_column_name='chunk_size',
            existing_type=sa.Integer(),
            existing_nullable=True,
        )
        batch_op.add_column(sa.Column('upload_file_size', sa.BigInteger(), nullable=True))
        batch_op.add_column(sa.Column('upload_sha256', sa.VARCHAR(length=64), nullable=True))
        batch_op.add_column(sa.Column('upload_session_id', sa.Text(), nullable=True))
        batch_op.add_column(sa.Column('upload_checkpoint_size', sa.BigInteger(), nullable=True))


def downgrade() -> None:
    """Downgrade schema."""
    connection = op.get_bind()
    file_tasks = sa.table(
        'file_tasks',
        sa.column('mode', sa.Integer()),
        sa.column('chunk_size', sa.Integer()),
        sa.column('upload_session_id', sa.Text()),
    )
    pending_sessions = connection.scalar(
        sa.select(sa.func.count())
        .select_from(file_tasks)
        .where(file_tasks.c.upload_session_id.is_not(None))
    )
    if pending_sessions:
        raise RuntimeError(
            'Cannot downgrade while resumable S3 upload sessions remain; '
            'complete or abort them first.'
        )

    connection.execute(
        sa.update(file_tasks)
        .where(file_tasks.c.mode == 1)
        .values(chunk_size=None)
    )
    with op.batch_alter_table('file_tasks', schema=None) as batch_op:
        batch_op.drop_column('upload_checkpoint_size')
        batch_op.drop_column('upload_session_id')
        batch_op.drop_column('upload_sha256')
        batch_op.drop_column('upload_file_size')
        batch_op.alter_column(
            'chunk_size',
            new_column_name='download_chunk_size',
            existing_type=sa.Integer(),
            existing_nullable=True,
        )
