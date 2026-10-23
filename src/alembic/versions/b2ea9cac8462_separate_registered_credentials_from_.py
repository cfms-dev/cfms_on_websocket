"""Separate registered credentials from authentication purpose policies.

Revision ID: b2ea9cac8462
Revises: d252e662fc05
Create Date: 2026-10-23
"""

import secrets

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects.mysql import BINARY as MySQLBinary

revision: str = "b2ea9cac8462"
down_revision: str | None = "d252e662fc05"
branch_labels: str | None = None
depends_on: str | None = None


def upgrade() -> None:
    op.create_table(
        "user_auth_policies",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("purpose", sa.VARCHAR(16), nullable=False),
        sa.Column("revision", sa.Integer(), nullable=False),
        sa.Column("chains", sa.JSON(), nullable=False),
        sa.CheckConstraint(
            "purpose IN ('login', 'mfa', 'escalation')", name="ck_auth_policy_purpose"
        ),
        sa.CheckConstraint("revision > 0", name="ck_auth_policy_revision"),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"],
            name=op.f("fk_user_auth_policies_user_id_users"), ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("user_id", "purpose", name=op.f("pk_user_auth_policies")),
    )
    op.create_table(
        "user_oidc_credentials",
        sa.Column("id", sa.VARCHAR(32), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("issuer", sa.Text(), nullable=False),
        sa.Column("subject", sa.Text(), nullable=False),
        sa.Column(
            "identity_digest",
            sa.LargeBinary(32).with_variant(MySQLBinary(32), "mysql"), nullable=False,
        ),
        sa.ForeignKeyConstraint(
            ["user_id"], ["users.id"],
            name=op.f("fk_user_oidc_credentials_user_id_users"), ondelete="CASCADE",
        ),
        sa.PrimaryKeyConstraint("id", name=op.f("pk_user_oidc_credentials")),
        sa.UniqueConstraint(
            "identity_digest", name=op.f("uq_user_oidc_credentials_identity_digest")
        ),
    )
    op.create_index("ix_user_oidc_credentials_user_id", "user_oidc_credentials", ["user_id"])

    connection = op.get_bind()
    for name in ("user_passwords", "user_totp_credentials"):
        with op.batch_alter_table(name) as batch_op:
            batch_op.add_column(sa.Column("credential_id", sa.VARCHAR(32), nullable=True))
        credentials = sa.table(
            name, sa.column("user_id", sa.Uuid()), sa.column("credential_id", sa.String(32))
        )
        for user_id in connection.scalars(sa.select(credentials.c.user_id)).all():
            connection.execute(
                credentials.update().where(credentials.c.user_id == user_id)
                .values(credential_id=secrets.token_hex(16))
            )
        with op.batch_alter_table(name) as batch_op:
            batch_op.alter_column(
                "credential_id", existing_type=sa.String(32), nullable=False
            )
            batch_op.create_unique_constraint(f"uq_{name}_credential_id", ["credential_id"])

    policies = sa.table(
        "user_auth_policies", sa.column("user_id", sa.Uuid()),
        sa.column("purpose", sa.String(16)), sa.column("revision", sa.Integer()),
        sa.column("chains", sa.JSON()),
    )
    for user_id, defaults in _default_policies(connection):
        connection.execute(policies.insert(), [
            {"user_id": user_id, "purpose": purpose, "revision": 1, "chains": chains}
            for purpose, chains in defaults.items()
        ])


def downgrade() -> None:
    connection = op.get_bind()
    has_oidc_table = sa.inspect(connection).has_table("user_oidc_credentials")
    oidc = sa.table("user_oidc_credentials", sa.column("id", sa.String(32)))
    if has_oidc_table and connection.scalar(sa.select(oidc.c.id).limit(1)) is not None:
        raise ValueError("Cannot downgrade while OIDC bindings exist")
    policies = sa.table(
        "user_auth_policies", sa.column("user_id", sa.Uuid()),
        sa.column("purpose", sa.String(16)), sa.column("chains", sa.JSON()),
    )
    for user_id, defaults in _default_policies(connection):
        actual = dict(connection.execute(
            sa.select(policies.c.purpose, policies.c.chains)
            .where(policies.c.user_id == user_id)
        ).all())
        if any(actual.get(purpose, []) != chains for purpose, chains in defaults.items()):
            raise ValueError(
                "Cannot downgrade custom authentication policies; restore legacy defaults first"
            )
    for name in ("user_totp_credentials", "user_passwords"):
        with op.batch_alter_table(name) as batch_op:
            batch_op.drop_constraint(f"uq_{name}_credential_id", type_="unique")
            batch_op.drop_column("credential_id")
    if has_oidc_table:
        op.drop_index("ix_user_oidc_credentials_user_id", table_name="user_oidc_credentials")
        op.drop_table("user_oidc_credentials")
    op.drop_table("user_auth_policies")


def _default_policies(connection):
    users = sa.table("users", sa.column("id", sa.Uuid()))
    passwords = sa.table(
        "user_passwords", sa.column("user_id", sa.Uuid()),
        sa.column("credential_id", sa.String(32)),
    )
    totp = sa.table(
        "user_totp_credentials", sa.column("user_id", sa.Uuid()),
        sa.column("credential_id", sa.String(32)), sa.column("enabled", sa.Boolean()),
    )
    password_ids = dict(connection.execute(
        sa.select(passwords.c.user_id, passwords.c.credential_id)
    ).all())
    totp_ids = dict(connection.execute(
        sa.select(totp.c.user_id, totp.c.credential_id).where(totp.c.enabled == True)
    ).all())
    for user_id in connection.scalars(sa.select(users.c.id)).all():
        yield user_id, {
            "login": [[{"method": "password", "credential_ids": [password_ids[user_id]]}]]
            if user_id in password_ids else [],
            "mfa": [[{"method": "totp", "credential_ids": [totp_ids[user_id]]}]]
            if user_id in totp_ids else [],
            "escalation": [],
        }
