import uuid
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic.config import Config
from sqlalchemy.dialects import mysql, postgresql
from sqlalchemy.orm import sessionmaker
from sqlalchemy.schema import CreateTable

from alembic import command
from include.database.models.auth import (
    UserAuthPolicy,
    UserOidcCredential,
    UserPasswordCredential,
    UserTotpCredential,
)
from include.database.models.identity import User
from include.database.session import Base
from include.domains.identity.commands.oidc import bind_oidc_identity

pytestmark = pytest.mark.component


@pytest.fixture
def auth_migration(sqlite_engine_factory):
    engine = sqlite_engine_factory()
    Base.metadata.create_all(engine)
    config = Config(Path(__file__).resolve().parents[3] / "src/alembic.ini")
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.stamp(config, "head")
        command.downgrade(config, "d252e662fc05")
        yield engine, connection, config


def test_auth_migration_backfills_without_changing_secrets_and_round_trips(
    auth_migration,
):
    _engine, connection, config = auth_migration
    user_id = uuid.uuid4()
    users = sa.table(
        "users",
        sa.column("id", sa.Uuid()),
        sa.column("username"),
        sa.column("created_time"),
        sa.column("status"),
    )
    passwords = sa.table(
        "user_passwords",
        sa.column("user_id", sa.Uuid()),
        sa.column("pass_hash"),
        sa.column("passwd_last_modified"),
    )
    totp = sa.table(
        "user_totp_credentials",
        sa.column("user_id", sa.Uuid()),
        sa.column("secret"),
        sa.column("enabled", sa.Boolean()),
        sa.column("created_time"),
        sa.column("backup_codes"),
    )
    connection.execute(
        users.insert().values(id=user_id, username="legacy", created_time=1.0, status=0)
    )
    connection.execute(
        passwords.insert().values(
            user_id=user_id, pass_hash="preserved", passwd_last_modified=0.0
        )
    )
    connection.execute(
        totp.insert().values(
            user_id=user_id,
            secret="preserved-totp",
            enabled=True,
            created_time=2.0,
            backup_codes="[]",
        )
    )
    connection.commit()
    command.upgrade(config, "head")
    with sessionmaker(bind=connection)() as session:
        password = session.get(UserPasswordCredential, user_id)
        credential = session.get(UserTotpCredential, user_id)
        assert len(password.credential_id) == len(credential.credential_id) == 32
        assert password.pass_hash == "preserved"
        assert password.passwd_last_modified == 0.0
        assert credential.secret == "preserved-totp"
        assert session.get(UserAuthPolicy, (user_id, "login")).chains == [
            [{"method": "password", "credential_ids": [password.credential_id]}]
        ]
        assert session.get(UserAuthPolicy, (user_id, "mfa")).chains == [
            [{"method": "totp", "credential_ids": [credential.credential_id]}]
        ]
        assert session.get(UserAuthPolicy, (user_id, "escalation")).chains == []
    command.downgrade(config, "d252e662fc05")
    assert "credential_id" not in {
        c["name"] for c in sa.inspect(connection).get_columns("user_passwords")
    }
    command.upgrade(config, "head")
    assert "user_auth_policies" in sa.inspect(connection).get_table_names()


@pytest.mark.parametrize("restriction", ["password-denied", "oidc"])
def test_downgrade_cannot_discard_restrictions_or_bindings(auth_migration, restriction):
    _engine, connection, config = auth_migration
    command.upgrade(config, "head")
    with sessionmaker(bind=connection).begin() as session:
        user = User(username="restricted")
        session.add(user)
        session.flush()
        if restriction == "oidc":
            bind_oidc_identity(session, user, "https://issuer.example", "subject")
        else:
            session.add(UserPasswordCredential(user_id=user.id, pass_hash="hash"))
            session.add(UserAuthPolicy(user_id=user.id, purpose="login", chains=[]))
    connection.commit()
    with pytest.raises(ValueError, match="Cannot downgrade"):
        command.downgrade(config, "d252e662fc05")
    assert "user_auth_policies" in sa.inspect(connection).get_table_names()


@pytest.mark.parametrize("dialect", [mysql.dialect(), postgresql.dialect()])
def test_oidc_identity_unique_index_uses_supported_fixed_length_digest(dialect):
    ddl = str(CreateTable(UserOidcCredential.__table__).compile(dialect=dialect))
    assert "UNIQUE (identity_digest)" in ddl
    assert "BINARY(32)" in ddl if dialect.name == "mysql" else "BYTEA" in ddl
