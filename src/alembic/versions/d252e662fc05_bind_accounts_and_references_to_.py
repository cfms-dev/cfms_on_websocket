"""Bind accounts and references to immutable user IDs.

Revision ID: d252e662fc05
Revises: 5ad5aca75635
"""

import uuid

import sqlalchemy as sa
from alembic import op

revision = "d252e662fc05"
down_revision = "5ad5aca75635"
branch_labels = None
depends_on = None

_NAMING = {
    "pk": "pk_%(table_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
}
_REFERENCES = (
    ("user_passwords", "username", "user_id", "CASCADE"),
    ("user_totp_credentials", "username", "user_id", "CASCADE"),
    ("user_auth_public_keys", "username", "user_id", "CASCADE"),
    ("user_permissions", "username", "user_id", "CASCADE"),
    ("user_memberships", "username", "user_id", "CASCADE"),
    ("keyrings", "username", "user_id", "CASCADE"),
    ("userblock_entries", "username", "user_id", "CASCADE"),
    ("audit_entries", "username", "user_id", "SET NULL"),
    ("document_metadata", "creator_username", "creator_id", "SET NULL"),
    ("document_metadata", "last_modified_by_username", "last_modified_by_id", "SET NULL"),
    ("file_tasks", "issued_by_username", "issued_by_id", "SET NULL"),
    ("schedules", "created_by", "created_by", "SET NULL"),
    ("schedules", "updated_by", "updated_by", "SET NULL"),
)
_DEPENDENT_REFERENCES = (
    (
        "userblock_sub_entries", "parent_id", "userblock_entries", "block_id",
        "fk_userblock_sub_entries_parent_id_userblock_entries",
    ),
    (
        "document_metadata_tags", "document_id", "document_metadata", "document_id",
        "fk_document_metadata_tags_document_id_document_metadata",
    ),
    (
        "schedule_executions", "schedule_id", "schedules", "id",
        "fk_schedule_executions_schedule_id_schedules",
    ),
)


def _dependent_foreign_keys(*, create):
    """Keep SQLite table copies from cascading into dependent rows."""
    if op.get_bind().dialect.name != "sqlite":
        return
    for table, column, parent, parent_column, name in _DEPENDENT_REFERENCES:
        with op.batch_alter_table(table, naming_convention=_NAMING) as batch:
            if create:
                batch.create_foreign_key(
                    name, parent, [column], [parent_column], ondelete="CASCADE"
                )
            else:
                batch.drop_constraint(name, type_="foreignkey")


def _convert_reference(table_name, old_name, new_name, identities, *, upgrade):
    connection = op.get_bind()
    inspector = sa.inspect(connection)
    column = next(c for c in inspector.get_columns(table_name) if c["name"] == old_name)
    indexes = [i for i in inspector.get_indexes(table_name) if old_name in i["column_names"]]
    uniques = [u for u in inspector.get_unique_constraints(table_name) if old_name in u["column_names"]]
    unique_names = {u["name"] for u in uniques}
    indexes = [i for i in indexes if i["name"] not in unique_names]
    primary_key = inspector.get_pk_constraint(table_name)
    foreign_keys = [f for f in inspector.get_foreign_keys(table_name) if old_name in f["constrained_columns"]]
    new_type = sa.Uuid() if upgrade else sa.String(256)
    temporary = "_cfms_identity"
    op.add_column(table_name, sa.Column(temporary, new_type, nullable=True))
    table = sa.Table(table_name, sa.MetaData(), autoload_with=connection, resolve_fks=False)
    table.c[temporary].type = new_type
    for value in connection.scalars(sa.select(table.c[old_name]).distinct()).all():
        if value is None:
            continue
        key = value if upgrade else str(uuid.UUID(str(value)))
        mapped = identities.get(key)
        if mapped is None and not column["nullable"]:
            raise RuntimeError(f"Orphaned account reference in {table_name}.{old_name}")
        connection.execute(sa.update(table).where(table.c[old_name] == value).values({temporary: mapped}))

    def renamed(columns):
        return [new_name if c == old_name else c for c in columns]

    with op.batch_alter_table(table_name, naming_convention=_NAMING) as batch:
        for fk in foreign_keys:
            batch.drop_constraint(fk["name"] or f"fk_{table_name}_{old_name}_users", type_="foreignkey")
        for index in indexes:
            batch.drop_index(index["name"])
        for unique in uniques:
            batch.drop_constraint(unique["name"] or f"uq_{table_name}_{old_name}", type_="unique")
        if old_name in primary_key["constrained_columns"]:
            batch.drop_constraint(primary_key["name"] or f"pk_{table_name}", type_="primary")
        batch.drop_column(old_name)
        batch.alter_column(temporary, new_column_name=new_name, existing_type=new_type, nullable=column["nullable"])
    with op.batch_alter_table(table_name, naming_convention=_NAMING) as batch:
        if old_name in primary_key["constrained_columns"]:
            batch.create_primary_key(primary_key["name"] or f"pk_{table_name}", renamed(primary_key["constrained_columns"]))
        for unique in uniques:
            batch.create_unique_constraint(unique["name"] or f"uq_{table_name}_{new_name}", renamed(unique["column_names"]))
        for index in indexes:
            batch.create_index(index["name"].replace(old_name, new_name), renamed(index["column_names"]), unique=index["unique"])


def _rewrite_grants(identities):
    connection = op.get_bind()
    grants = sa.table("object_access_entries", sa.column("id"), sa.column("entity_type"), sa.column("entity_identifier"))
    for entry_id, value in connection.execute(sa.select(grants.c.id, grants.c.entity_identifier).where(grants.c.entity_type == "user")).all():
        mapped = identities.get(value)
        if mapped is None:
            connection.execute(sa.delete(grants).where(grants.c.id == entry_id))
        else:
            connection.execute(sa.update(grants).where(grants.c.id == entry_id).values(entity_identifier=str(mapped)))


def _drop_account_foreign_keys(*, upgrade):
    connection = op.get_bind()
    for table_name, username, user_id, _ondelete in _REFERENCES:
        column = username if upgrade else user_id
        for fk in sa.inspect(connection).get_foreign_keys(table_name):
            if column in fk["constrained_columns"]:
                with op.batch_alter_table(table_name, naming_convention=_NAMING) as batch:
                    batch.drop_constraint(fk["name"] or f"fk_{table_name}_{column}_users", type_="foreignkey")


def _create_account_foreign_keys(*, upgrade):
    for table_name, username, user_id, ondelete in _REFERENCES:
        column = user_id if upgrade else username
        with op.batch_alter_table(table_name, naming_convention=_NAMING) as batch:
            batch.create_foreign_key(f"fk_{table_name}_{column}_users", "users", [column], ["id" if upgrade else "username"], ondelete=ondelete)


def upgrade():
    connection = op.get_bind()
    # Validate required references before changing a schema; nullable history may
    # already reference deleted users on databases without FK enforcement.
    users = sa.Table("users", sa.MetaData(), autoload_with=connection, resolve_fks=False)
    names = set(connection.scalars(sa.select(users.c.username)))
    preferences = connection.execute(
        sa.select(users.c.username, users.c.preference_dek_id)
        .where(users.c.preference_dek_id.is_not(None))
    ).all()
    for table_name, username, _user_id, _ondelete in _REFERENCES:
        table = sa.Table(table_name, sa.MetaData(), autoload_with=connection, resolve_fks=False)
        if not table.c[username].nullable:
            values = set(connection.scalars(sa.select(table.c[username]).distinct()))
            if values - names:
                raise RuntimeError(f"Orphaned account reference in {table_name}.{username}")
    _dependent_foreign_keys(create=False)
    _drop_account_foreign_keys(upgrade=True)
    op.add_column("users", sa.Column("id", sa.Uuid(), nullable=True))
    users = sa.Table("users", sa.MetaData(), autoload_with=connection, resolve_fks=False)
    users.c.id.type = sa.Uuid()
    identities = {name: uuid.uuid4() for name in names}
    for name, user_id in identities.items():
        connection.execute(sa.update(users).where(users.c.username == name).values(id=user_id))
    pk = sa.inspect(connection).get_pk_constraint("users")
    with op.batch_alter_table("users", naming_convention=_NAMING) as batch:
        batch.drop_constraint(pk["name"] or "pk_users", type_="primary")
        batch.alter_column("id", existing_type=sa.Uuid(), nullable=False)
        batch.create_primary_key("pk_users", ["id"])
    op.create_index("ix_users_username", "users", ["username"], unique=True)
    for table_name, username, user_id, _ondelete in _REFERENCES:
        _convert_reference(table_name, username, user_id, identities, upgrade=True)
    _create_account_foreign_keys(upgrade=True)
    _dependent_foreign_keys(create=True)
    for name, key_id in preferences:
        connection.execute(
            sa.update(users).where(users.c.username == name)
            .values(preference_dek_id=key_id)
        )
    _rewrite_grants(identities)
    # These short-lived counters must not attach a deleted account's activity to
    # its replacement. Login throttles intentionally still address input names.
    op.execute("DELETE FROM risk_ip_accounts")
    with op.batch_alter_table("risk_ip_accounts", naming_convention=_NAMING) as batch:
        batch.drop_constraint("pk_risk_ip_accounts", type_="primary")
        batch.drop_column("username")
        batch.add_column(sa.Column("user_id", sa.Uuid(), nullable=False))
        batch.create_primary_key("pk_risk_ip_accounts", ["namespace", "ip_address", "user_id"])
    op.execute("DELETE FROM rate_limit_buckets WHERE scope = 'account'")


def downgrade():
    connection = op.get_bind()
    users = sa.Table("users", sa.MetaData(), autoload_with=connection, resolve_fks=False)
    users.c.id.type = sa.Uuid()
    identities = {str(user_id): name for user_id, name in connection.execute(sa.select(users.c.id, users.c.username))}
    preferences = connection.execute(
        sa.select(users.c.username, users.c.preference_dek_id)
        .where(users.c.preference_dek_id.is_not(None))
    ).all()
    _dependent_foreign_keys(create=False)
    _drop_account_foreign_keys(upgrade=False)
    for table_name, username, user_id, _ondelete in reversed(_REFERENCES):
        _convert_reference(table_name, user_id, username, identities, upgrade=False)
    _rewrite_grants(identities)
    with op.batch_alter_table("users", naming_convention=_NAMING) as batch:
        batch.drop_constraint("pk_users", type_="primary")
        batch.drop_index("ix_users_username")
        batch.drop_column("id")
        batch.create_primary_key("pk_users", ["username"])
    _create_account_foreign_keys(upgrade=False)
    _dependent_foreign_keys(create=True)
    for name, key_id in preferences:
        connection.execute(
            sa.update(users).where(users.c.username == name)
            .values(preference_dek_id=key_id)
        )
    op.execute("DELETE FROM risk_ip_accounts")
    with op.batch_alter_table("risk_ip_accounts", naming_convention=_NAMING) as batch:
        batch.drop_constraint("pk_risk_ip_accounts", type_="primary")
        batch.drop_column("user_id")
        batch.add_column(sa.Column("username", sa.String(256), nullable=False))
        batch.create_primary_key("pk_risk_ip_accounts", ["namespace", "ip_address", "username"])
    op.execute("DELETE FROM rate_limit_buckets WHERE scope = 'account'")
