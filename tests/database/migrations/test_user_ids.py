import uuid
from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import MetaData, Table, inspect, select

import include.database.models  # noqa: F401
from alembic import command
from include.database.session import Base

pytestmark = pytest.mark.component


def test_account_identity_migration_preserves_references(sqlite_engine_factory):
    engine = sqlite_engine_factory()
    Base.metadata.create_all(engine)
    config = Config(Path(__file__).resolve().parents[3] / "src/alembic.ini")
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.stamp(config, "head")
        command.downgrade(config, "5ad5aca75635")
        metadata = MetaData()
        metadata.reflect(connection)
        tables = metadata.tables
        connection.execute(
            tables["users"].insert(),
            {
                "username": "alice",
                "created_time": 1.0,
                "status": 0,
                "secret_key": "s" * 64,
            },
        )
        connection.execute(
            tables["user_passwords"].insert(),
            {
                "username": "alice",
                "pass_hash": "preserved",
                "passwd_last_modified": 123.0,
            },
        )
        connection.execute(
            tables["audit_entries"].insert(),
            {
                "id": "audit",
                "username": "alice",
                "target": "alice",
                "action": "login",
                "result": 200,
                "logged_time": 1.0,
            },
        )
        connection.execute(
            tables["user_permissions"].insert(),
            {
                "username": "alice",
                "permission": "list_users",
                "granted": True,
                "start_time": 0.0,
            },
        )
        connection.execute(
            tables["object_access_entries"].insert(),
            {
                "entity_type": "user",
                "entity_identifier": "alice",
                "target_type": "directory",
                "target_identifier": "/",
                "access_type": "read",
                "start_time": 0.0,
            },
        )
        connection.execute(
            tables["object_access_entries"].insert(),
            {
                "entity_type": "user",
                "entity_identifier": "deleted-user",
                "target_type": "directory",
                "target_identifier": "/",
                "access_type": "write",
                "start_time": 0.0,
            },
        )
        connection.commit()

        command.upgrade(config, "head")
        users = Base.metadata.tables["users"]
        user_id = connection.scalar(
            select(users.c.id).where(users.c.username == "alice")
        )
        assert isinstance(user_id, uuid.UUID)
        assert user_id.version == 4
        for name in ("user_passwords", "user_permissions", "audit_entries"):
            assert (
                connection.scalar(select(Base.metadata.tables[name].c.user_id))
                == user_id
            )
        password = connection.execute(
            select(Base.metadata.tables["user_passwords"])
        ).one()
        assert password.pass_hash == "preserved"
        grants = (
            connection.execute(
                select(
                    Base.metadata.tables["object_access_entries"].c.entity_identifier
                )
            )
            .scalars()
            .all()
        )
        assert grants == [str(user_id)]
        assert (
            connection.scalar(select(Base.metadata.tables["audit_entries"].c.target))
            == "alice"
        )
        assert inspect(connection).get_pk_constraint("users")[
            "constrained_columns"
        ] == ["id"]
        assert any(
            index["name"] == "ix_users_username" and index["unique"]
            for index in inspect(connection).get_indexes("users")
        )
        for table in Base.metadata.tables.values():
            assert all(
                fk["referred_columns"] == ["id"]
                for fk in inspect(connection).get_foreign_keys(table.name)
                if fk["referred_table"] == "users"
            )
        command.downgrade(config, "5ad5aca75635")
        old_passwords = Table("user_passwords", MetaData(), autoload_with=connection)
        assert connection.scalar(select(old_passwords.c.username)) == "alice"
        assert connection.scalar(select(old_passwords.c.pass_hash)) == "preserved"
