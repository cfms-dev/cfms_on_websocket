"""decouple_user_credentials

Revision ID: 5ad5aca75635
Revises: 0460356a5ba6
Create Date: 2026-10-22 21:30:44.268175

"""
import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.mysql import BINARY as MySQLBinary


# revision identifiers, used by Alembic.
revision: str = '5ad5aca75635'
down_revision: str | None = '0460356a5ba6'
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        'user_auth_public_keys',
        sa.Column('id', sa.VARCHAR(length=32), nullable=False),
        sa.Column('username', sa.VARCHAR(length=256), nullable=False),
        sa.Column('public_key_der', sa.LargeBinary(), nullable=False),
        sa.Column(
            'fingerprint',
            sa.LargeBinary(32).with_variant(MySQLBinary(32), 'mysql'),
            nullable=False,
        ),
        sa.Column('label', sa.VARCHAR(length=255), nullable=True),
        sa.Column('created_time', sa.Double(), nullable=False),
        sa.Column('last_used_time', sa.Double(), nullable=True),
        sa.ForeignKeyConstraint(
            ['username'],
            ['users.username'],
            name=op.f('fk_user_auth_public_keys_username_users'),
            ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('id', name=op.f('pk_user_auth_public_keys')),
        sa.UniqueConstraint(
            'username', 'fingerprint', name='uq_user_auth_public_keys_user_fingerprint'
        ),
    )
    with op.batch_alter_table('user_auth_public_keys', schema=None) as batch_op:
        batch_op.create_index(
            'ix_user_auth_public_keys_fingerprint', ['fingerprint'], unique=False
        )

    op.create_table(
        'user_passwords',
        sa.Column('username', sa.VARCHAR(length=256), nullable=False),
        sa.Column('pass_hash', sa.Text(), nullable=False),
        sa.Column('passwd_last_modified', sa.Double(), nullable=False),
        sa.ForeignKeyConstraint(
            ['username'],
            ['users.username'],
            name=op.f('fk_user_passwords_username_users'),
            ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('username', name=op.f('pk_user_passwords')),
    )

    op.create_table(
        'user_totp_credentials',
        sa.Column('username', sa.VARCHAR(length=256), nullable=False),
        sa.Column('secret', sa.VARCHAR(length=32), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=False),
        sa.Column('backup_codes', sa.Text(), nullable=True),
        sa.Column('created_time', sa.Double(), nullable=False),
        sa.ForeignKeyConstraint(
            ['username'],
            ['users.username'],
            name=op.f('fk_user_totp_credentials_username_users'),
            ondelete='CASCADE',
        ),
        sa.PrimaryKeyConstraint('username', name=op.f('pk_user_totp_credentials')),
    )

    # Data migration: copy existing passwords and TOTP credentials from users table
    op.execute(
        """
        INSERT INTO user_passwords (username, pass_hash, passwd_last_modified)
        SELECT username, pass_hash, COALESCE(passwd_last_modified, 0)
        FROM users
        WHERE pass_hash IS NOT NULL
        """
    )
    op.execute(
        """
        INSERT INTO user_totp_credentials (username, secret, enabled, backup_codes, created_time)
        SELECT username, totp_secret, COALESCE(totp_enabled, 0), totp_backup_codes, COALESCE(created_time, 0)
        FROM users
        WHERE totp_secret IS NOT NULL
        """
    )

    # Native DROP COLUMN avoids recreating the referenced users table on SQLite.
    for column in (
        'passwd_last_modified', 'totp_enabled', 'totp_secret',
        'totp_backup_codes', 'pass_hash',
    ):
        op.drop_column('users', column)


def downgrade() -> None:
    """Downgrade schema."""
    connection = op.get_bind()
    keys = sa.table('user_auth_public_keys', sa.column('id'))
    if connection.scalar(sa.select(keys.c.id).limit(1)) is not None:
        raise ValueError('Cannot downgrade while public key credentials exist')
    op.add_column('users', sa.Column('pass_hash', sa.Text(), nullable=False, server_default=sa.text("('')")))
    op.add_column('users', sa.Column('totp_backup_codes', sa.Text(), nullable=True))
    op.add_column('users', sa.Column('totp_secret', sa.VARCHAR(32), nullable=True))
    op.add_column('users', sa.Column('totp_enabled', sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column('users', sa.Column('passwd_last_modified', sa.Double(), nullable=False, server_default='0'))

    # Restore data back to users table before dropping credential tables
    op.execute(
        """
        UPDATE users
        SET pass_hash = (SELECT pass_hash FROM user_passwords WHERE user_passwords.username = users.username),
            passwd_last_modified = (SELECT passwd_last_modified FROM user_passwords WHERE user_passwords.username = users.username)
        WHERE EXISTS (SELECT 1 FROM user_passwords WHERE user_passwords.username = users.username)
        """
    )
    op.execute(
        """
        UPDATE users
        SET totp_secret = (SELECT secret FROM user_totp_credentials WHERE user_totp_credentials.username = users.username),
            totp_enabled = (SELECT enabled FROM user_totp_credentials WHERE user_totp_credentials.username = users.username),
            totp_backup_codes = (SELECT backup_codes FROM user_totp_credentials WHERE user_totp_credentials.username = users.username)
        WHERE EXISTS (SELECT 1 FROM user_totp_credentials WHERE user_totp_credentials.username = users.username)
        """
    )
    op.drop_table('user_totp_credentials')
    op.drop_table('user_passwords')
    with op.batch_alter_table('user_auth_public_keys', schema=None) as batch_op:
        batch_op.drop_index('ix_user_auth_public_keys_fingerprint')

    op.drop_table('user_auth_public_keys')
