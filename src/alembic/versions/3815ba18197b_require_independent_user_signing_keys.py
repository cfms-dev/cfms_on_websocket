"""require independent user signing keys

Revision ID: 3815ba18197b
Revises: b2ea9cac8462
Create Date: 2026-10-24 11:51:13.679752

"""

import secrets
from graphlib import TopologicalSorter

import sqlalchemy as sa

from alembic import op

revision: str = "3815ba18197b"
down_revision: str | None = "b2ea9cac8462"
branch_labels: str | None = None
depends_on: str | None = None

_NAMING = {"fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"}


def _alter_secret_key(*, nullable: bool) -> None:
    connection = op.get_bind()
    users = sa.table(
        "users", sa.column("id", sa.Uuid()), sa.column("preference_dek_id", sa.String(64))
    )
    references = {}
    preferences = []
    order = ()
    if connection.dialect.name == "sqlite":
        inspector = sa.inspect(connection)
        foreign_keys = {
            name: inspector.get_foreign_keys(name)
            for name in inspector.get_table_names()
        }
        affected = {"users"}
        while additional := {
            name
            for name, keys in foreign_keys.items()
            if name not in affected
            and any(key["referred_table"] in affected for key in keys)
        }:
            affected.update(additional)
        references = {
            name: [key for key in foreign_keys[name] if key["referred_table"] in affected]
            for name in affected - {"users"}
        }
        order = tuple(
            TopologicalSorter(
                {
                    name: {key["referred_table"] for key in keys} - {"users"}
                    for name, keys in references.items()
                }
            ).static_order()
        )
        # Break the users/keyrings cycle before copying either table.
        preferences = connection.execute(
            sa.select(users.c.id, users.c.preference_dek_id)
            .where(users.c.preference_dek_id.is_not(None))
        ).all()
        if preferences:
            connection.execute(sa.update(users).values(preference_dek_id=None))
        # Remove child references first so table copies cannot cascade into data.
        for name in reversed(order):
            with op.batch_alter_table(name, naming_convention=_NAMING) as batch:
                for key in references[name]:
                    constraint_name = key["name"] or (
                        f"fk_{name}_{key['constrained_columns'][0]}_"
                        f"{key['referred_table']}"
                    )
                    batch.drop_constraint(constraint_name, type_="foreignkey")

    with op.batch_alter_table("users") as batch:
        batch.alter_column("secret_key", existing_type=sa.VARCHAR(64), nullable=nullable)
        if nullable:
            batch.drop_constraint("ck_users_secret_key_nonempty", type_="check")
        else:
            batch.create_check_constraint(
                "ck_users_secret_key_nonempty", "length(secret_key) > 0"
            )

    for name in order:
        with op.batch_alter_table(name, naming_convention=_NAMING) as batch:
            for key in references[name]:
                batch.create_foreign_key(
                    key["name"],
                    key["referred_table"],
                    key["constrained_columns"],
                    key["referred_columns"],
                    referent_schema=key["referred_schema"],
                    **key["options"],
                )
    for user_id, key_id in preferences:
        connection.execute(
            sa.update(users).where(users.c.id == user_id).values(preference_dek_id=key_id)
        )


def upgrade() -> None:
    connection = op.get_bind()
    users = sa.table(
        "users", sa.column("id", sa.Uuid()), sa.column("secret_key", sa.VARCHAR(64))
    )
    missing = connection.scalars(
        sa.select(users.c.id).where(
            sa.or_(users.c.secret_key.is_(None), sa.func.length(users.c.secret_key) == 0)
        )
    ).all()
    for user_id in missing:
        connection.execute(
            users.update()
            .where(users.c.id == user_id)
            .values(secret_key=secrets.token_hex(32))
        )
    _alter_secret_key(nullable=False)


def downgrade() -> None:
    _alter_secret_key(nullable=True)
