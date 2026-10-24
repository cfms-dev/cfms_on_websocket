import uuid
from pathlib import Path

import jwt
import pytest
import sqlalchemy as sa
from alembic.config import Config
from sqlalchemy.dialects import mysql, postgresql
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.schema import CreateTable

from alembic import command
from include.config.settings import global_config
from include.database.models.identity import User
from include.database.models.keyrings import UserKey
from include.database.session import Base
from include.domains.identity.tokens import Token
from include.extensions.oidc_sso.credentials import bind_oidc_identity
from include.extensions.oidc_sso.models import OIDCBase

pytestmark = pytest.mark.component
_EXISTING_SECRET = "existing-non-hex-key-longer-than-32-bytes"


@pytest.mark.parametrize("dialect", [mysql.dialect(), postgresql.dialect()])
def test_user_secret_constraints_compile_for_supported_dialects(dialect):
    ddl = str(CreateTable(User.__table__).compile(dialect=dialect))
    assert "secret_key VARCHAR(64) NOT NULL" in ddl
    assert "ck_users_secret_key_nonempty CHECK (length(secret_key) > 0)" in ddl


@pytest.mark.parametrize("extension_tables", [False, True])
def test_secret_migration_preserves_data_and_round_trips(
    sqlite_engine_factory, extension_tables
):
    engine = sqlite_engine_factory()
    Base.metadata.create_all(engine)
    OIDCBase.metadata.create_all(engine)
    extra = sa.MetaData()
    records = sa.Table(
        "secret_extension_records",
        extra,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "user_id",
            sa.Uuid(),
            sa.ForeignKey(User.id, name="fk_secret_extension_user", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("content", sa.String(64), nullable=False),
    )
    details = sa.Table(
        "secret_extension_details",
        extra,
        sa.Column("id", sa.Integer(), primary_key=True),
        sa.Column(
            "record_id",
            sa.Integer(),
            sa.ForeignKey(
                records.c.id, name="fk_secret_extension_detail", ondelete="CASCADE"
            ),
            nullable=False,
        ),
    )
    if extension_tables:
        extra.create_all(engine)
    tables = {**Base.metadata.tables, **OIDCBase.metadata.tables}
    if extension_tables:
        tables.update(extra.tables)
    config = Config(Path(__file__).resolve().parents[3] / "src/alembic.ini")
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.stamp(config, "head")
        command.downgrade(config, "b2ea9cac8462")
        user_ids = {
            name: uuid.uuid4()
            for name in ("null", "empty", "kept", "disabled", "space")
        }
        for name, key, status in (
            ("null", None, 0),
            ("empty", "", 0),
            ("kept", _EXISTING_SECRET, 0),
            ("disabled", None, 1),
            ("space", " ", 0),
        ):
            connection.execute(
                User.__table__.insert().values(
                    id=user_ids[name], username=name, secret_key=key, status=status
                )
            )
        connection.execute(
            UserKey.__table__.insert().values(
                id="preference", user_id=user_ids["kept"], content="encrypted-dek"
            )
        )
        connection.execute(
            sa.update(User)
            .where(User.id == user_ids["kept"])
            .values(preference_dek_id="preference")
        )
        with sessionmaker(bind=connection).begin() as session:
            bind_oidc_identity(
                session,
                session.get(User, user_ids["kept"]),
                "https://issuer.example",
                "subject",
            )
        if extension_tables:
            connection.execute(
                records.insert().values(
                    id=1, user_id=user_ids["null"], content="preserved"
                )
            )
            connection.execute(details.insert().values(id=1, record_id=1))
        old_tokens = {
            name: Token.new(user_id, 300, global_config["server"]["secret_key"]).raw
            for name, user_id in user_ids.items()
            if name in ("null", "empty", "disabled")
        }
        kept_token = Token.new(user_ids["kept"], 300, _EXISTING_SECRET).raw
        expected = {
            name: connection.execute(
                sa.select(
                    *(column for column in table.c if column.name != "secret_key")
                ).order_by(*table.primary_key.columns)
            ).all()
            for name, table in tables.items()
        }
        expected_foreign_keys = {
            name: {
                key["name"]: key
                for key in sa.inspect(connection).get_foreign_keys(name)
            }
            for name in tables
        }
        connection.commit()
        generated_keys = None

        for revision, nullable in (
            ("head", False),
            ("b2ea9cac8462", True),
            ("head", False),
        ):
            if nullable:
                command.downgrade(config, revision)
            else:
                command.upgrade(config, revision)
            keys = dict(
                connection.execute(sa.select(User.username, User.secret_key)).all()
            )
            assert keys["kept"] == _EXISTING_SECRET
            assert keys["space"] == " "
            assert len({keys[name] for name in old_tokens}) == 3
            assert all(len(bytes.fromhex(keys[name])) == 32 for name in old_tokens)
            if generated_keys is None:
                generated_keys = keys
            assert keys == generated_keys
            assert Token.from_raw(kept_token, keys["kept"]).sub == user_ids["kept"]
            for name, raw in old_tokens.items():
                with pytest.raises(jwt.InvalidSignatureError):
                    Token.from_raw(raw, keys[name])
            for name, table in tables.items():
                assert (
                    connection.execute(
                        sa.select(
                            *(
                                column
                                for column in table.c
                                if column.name != "secret_key"
                            )
                        ).order_by(*table.primary_key.columns)
                    ).all()
                    == expected[name]
                ), name
                assert {
                    key["name"]: key
                    for key in sa.inspect(connection).get_foreign_keys(name)
                } == expected_foreign_keys[name], name
            columns = {
                column["name"]: column
                for column in sa.inspect(connection).get_columns("users")
            }
            assert columns["secret_key"]["nullable"] is nullable
            assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
            assert connection.exec_driver_sql("PRAGMA foreign_key_check").all() == []
            if not nullable:
                for missing in (None, ""):
                    with pytest.raises(IntegrityError), connection.begin_nested():
                        connection.execute(
                            sa.update(User)
                            .where(User.id == user_ids["kept"])
                            .values(secret_key=missing)
                        )
            connection.commit()
