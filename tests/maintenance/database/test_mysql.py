import os
import uuid
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.migration import MigrationContext
from sqlalchemy import create_engine, insert, inspect, select, text

from alembic import command
from include.database.engine import create_database_engine
from maintenance.operations.database.migration import migrate_database
from maintenance.operations.database.schema import (
    DatabaseSchemaError,
    upgrade_database_schema,
)
from maintenance.operations.database.tables import APPLICATION_TABLE_NAMES
from tests.maintenance.backup.roundtrip_support import _seed_source
from tests.maintenance.database.support import (
    _script_directory,
    _seed_runtime_tables,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        "CFMS_TEST_MYSQL_URL" not in os.environ,
        reason="CFMS_TEST_MYSQL_URL is required for MySQL migration integration tests",
    ),
]

_PROJECT_ROOT = Path(__file__).resolve().parents[3]


def test_unversioned_mysql_schema_is_rejected_without_stamping(
    backup_context, request
) -> None:
    mysql_engine = create_engine(os.environ["CFMS_TEST_MYSQL_URL"])
    request.addfinalizer(mysql_engine.dispose)
    _clear_mysql_database(mysql_engine)
    try:
        backup_context.Base.metadata.create_all(mysql_engine)

        with pytest.raises(DatabaseSchemaError, match="Non-empty unversioned"):
            upgrade_database_schema(mysql_engine, backup_context.Base.metadata)

        with mysql_engine.connect() as connection:
            assert "users" in inspect(connection).get_table_names()
            assert MigrationContext.configure(connection).get_current_revision() is None
    finally:
        _clear_mysql_database(mysql_engine)


def test_document_lookup_indexes_round_trip_on_mysql(backup_context, request) -> None:
    mysql_engine = create_engine(os.environ["CFMS_TEST_MYSQL_URL"])
    request.addfinalizer(mysql_engine.dispose)
    _clear_mysql_database(mysql_engine)
    config = Config(_PROJECT_ROOT / "src" / "alembic.ini")
    scripts = _script_directory()
    head = scripts.get_current_head()
    assert head is not None
    expected_indexes = {
        "documents": {"ix_documents_current_revision_id"},
        "document_revisions": {
            "ix_document_revisions_document_created_id",
            "ix_document_revisions_parent_revision_id",
        },
    }
    expected_foreign_keys = {
        "documents": {
            ("current_revision_id",): (
                "fk_documents_current_revision_id_document_revisions",
                "SET NULL",
            ),
        },
        "document_revisions": {
            ("document_id",): (
                "fk_document_revisions_document_id_documents",
                None,
            ),
            ("parent_revision_id",): (
                "fk_document_revisions_parent_revision_id_document_revisions",
                "SET NULL",
            ),
        },
    }
    try:
        backup_context.Base.metadata.create_all(mysql_engine)
        with mysql_engine.begin() as connection:
            MigrationContext.configure(connection).stamp(scripts, head)

        with mysql_engine.connect() as connection:
            config.attributes["connection"] = connection
            command.downgrade(config, "3c496a214a87")

        with mysql_engine.connect() as connection:
            inspector = inspect(connection)
            for table_name, index_names in expected_indexes.items():
                assert index_names.isdisjoint(
                    index["name"] for index in inspector.get_indexes(table_name)
                )
            for table_name, expected in expected_foreign_keys.items():
                actual = {
                    tuple(foreign_key["constrained_columns"]): (
                        foreign_key["name"],
                        foreign_key["options"].get("ondelete"),
                    )
                    for foreign_key in inspector.get_foreign_keys(table_name)
                }
                assert expected.items() <= actual.items()

        with mysql_engine.connect() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")

        with mysql_engine.connect() as connection:
            inspector = inspect(connection)
            for table_name, index_names in expected_indexes.items():
                assert index_names <= {
                    index["name"] for index in inspector.get_indexes(table_name)
                }
    finally:
        _clear_mysql_database(mysql_engine)


def test_system_schedule_revision_round_trips_on_mysql(backup_context, request) -> None:
    mysql_engine = create_engine(os.environ["CFMS_TEST_MYSQL_URL"])
    request.addfinalizer(mysql_engine.dispose)
    _clear_mysql_database(mysql_engine)
    config = Config(_PROJECT_ROOT / "src" / "alembic.ini")
    scripts = _script_directory()
    head = scripts.get_current_head()
    assert head is not None
    try:
        backup_context.Base.metadata.create_all(mysql_engine)
        with mysql_engine.begin() as connection:
            MigrationContext.configure(connection).stamp(scripts, head)

        with mysql_engine.connect() as connection:
            config.attributes["connection"] = connection
            command.downgrade(config, "8c130010a943")
        with mysql_engine.connect() as connection:
            assert "system_managed" not in {
                item["name"] for item in inspect(connection).get_columns("schedules")
            }

        with mysql_engine.connect() as connection:
            config.attributes["connection"] = connection
            command.upgrade(config, "head")
        with mysql_engine.connect() as connection:
            assert "system_managed" in {
                item["name"] for item in inspect(connection).get_columns("schedules")
            }
            assert "ck_schedules_system_ownership" not in {
                item["name"]
                for item in inspect(connection).get_check_constraints("schedules")
            }
            schedule_foreign_keys = {
                tuple(item["constrained_columns"]): item
                for item in inspect(connection).get_foreign_keys("schedules")
            }
            assert schedule_foreign_keys[("created_by",)]["options"]["ondelete"] == (
                "SET NULL"
            )
            assert schedule_foreign_keys[("updated_by",)]["options"]["ondelete"] == (
                "SET NULL"
            )
        tables = backup_context.Base.metadata.tables
        owner_id = uuid.uuid4()
        with mysql_engine.begin() as connection:
            connection.execute(
                tables["users"].insert(),
                {
                    "id": owner_id,
                    "username": "schedule-owner",
                    "created_time": 100.0,
                    "status": 0,
                    "secret_key": "secret",
                },
            )
            connection.execute(
                tables["schedules"].insert(),
                {
                    "id": "user-schedule",
                    "task_name": "test.record",
                    "task_contract_version": 1,
                    "payload": {"value": 1},
                    "trigger_type": "date",
                    "trigger_data": {"run_at": "2026-01-01T00:00:00+00:00"},
                    "timezone": "UTC",
                    "system_managed": False,
                    "enabled": True,
                    "status": "active",
                    "revision": 1,
                    "created_by": owner_id,
                    "created_at": 100.0,
                    "updated_by": owner_id,
                    "updated_at": 100.0,
                },
            )
            connection.execute(
                tables["users"].delete().where(tables["users"].c.id == owner_id)
            )
            assert connection.execute(
                select(
                    tables["schedules"].c.created_by,
                    tables["schedules"].c.updated_by,
                ).where(tables["schedules"].c.id == "user-schedule")
            ).one() == (None, None)
    finally:
        _clear_mysql_database(mysql_engine)


def test_legacy_credentials_round_trip_on_mysql(backup_context, request) -> None:
    mysql_engine = create_engine(os.environ["CFMS_TEST_MYSQL_URL"])
    request.addfinalizer(mysql_engine.dispose)
    _clear_mysql_database(mysql_engine)
    config = Config(_PROJECT_ROOT / "src" / "alembic.ini")
    tables = backup_context.Base.metadata.tables
    owner_id = uuid.uuid4()
    try:
        backup_context.Base.metadata.create_all(mysql_engine)
        with mysql_engine.begin() as connection:
            connection.execute(
                tables["users"].insert(),
                {"id": owner_id, "username": "credential-owner"},
            )
            connection.execute(
                tables["user_passwords"].insert(),
                {
                    "user_id": owner_id,
                    "credential_id": "password-credential",
                    "pass_hash": "retained-hash",
                    "passwd_last_modified": 0,
                },
            )
            connection.execute(
                tables["user_totp_credentials"].insert(),
                {
                    "user_id": owner_id,
                    "credential_id": "totp-credential",
                    "secret": "JBSWY3DPEHPK3PXP",
                    "enabled": True,
                    "backup_codes": "[]",
                },
            )
            connection.execute(
                tables["user_auth_policies"].insert(),
                [
                    {
                        "user_id": owner_id,
                        "purpose": purpose,
                        "revision": 1,
                        "chains": chains,
                    }
                    for purpose, chains in (
                        (
                            "login",
                            [
                                [
                                    {
                                        "method": "password",
                                        "credential_ids": ["password-credential"],
                                    }
                                ]
                            ],
                        ),
                        (
                            "mfa",
                            [
                                [
                                    {
                                        "method": "totp",
                                        "credential_ids": ["totp-credential"],
                                    }
                                ]
                            ],
                        ),
                        ("escalation", []),
                    )
                ],
            )
            config.attributes["connection"] = connection
            command.stamp(config, "head")

        with mysql_engine.connect() as connection:
            config.attributes["connection"] = connection
            command.downgrade(config, "0460356a5ba6")
            assert connection.execute(
                text(
                    "SELECT pass_hash, passwd_last_modified, totp_secret, "
                    "totp_enabled, totp_backup_codes FROM users "
                    "WHERE username = 'credential-owner'"
                )
            ).one() == ("retained-hash", 0, "JBSWY3DPEHPK3PXP", True, "[]")
            assert "user_passwords" not in inspect(connection).get_table_names()
            command.upgrade(config, "head")

        with mysql_engine.connect() as connection:
            user_id = connection.scalar(
                select(tables["users"].c.id).where(
                    tables["users"].c.username == "credential-owner"
                )
            )
            assert isinstance(user_id, uuid.UUID)
            assert connection.execute(
                select(
                    tables["user_passwords"].c.pass_hash,
                    tables["user_passwords"].c.passwd_last_modified,
                ).where(tables["user_passwords"].c.user_id == user_id)
            ).one() == ("retained-hash", 0)
            assert connection.execute(
                select(
                    tables["user_totp_credentials"].c.secret,
                    tables["user_totp_credentials"].c.enabled,
                    tables["user_totp_credentials"].c.backup_codes,
                ).where(tables["user_totp_credentials"].c.user_id == user_id)
            ).one() == ("JBSWY3DPEHPK3PXP", True, "[]")
    finally:
        _clear_mysql_database(mysql_engine)


@pytest.mark.parametrize("direction", ["sqlite-to-mysql", "mysql-to-sqlite"])
def test_database_migration_round_trip_with_supported_mysql_lts(
    backup_context,
    tmp_path,
    direction,
    request,
) -> None:
    base = backup_context.Base
    mysql_engine = create_engine(os.environ["CFMS_TEST_MYSQL_URL"])
    request.addfinalizer(mysql_engine.dispose)
    _clear_mysql_database(mysql_engine)
    sqlite_engine = create_database_engine(
        {"type": "sqlite", "file": str(tmp_path / "migration.db")}
    )
    request.addfinalizer(sqlite_engine.dispose)
    scripts = _script_directory()
    head = scripts.get_current_head()
    assert head is not None

    if direction == "sqlite-to-mysql":
        source_engine, target_engine = sqlite_engine, mysql_engine
        base.metadata.create_all(source_engine)
    else:
        source_engine, target_engine = mysql_engine, sqlite_engine
        base.metadata.create_all(source_engine)

    storage_root = tmp_path / "storage"
    storage_root.mkdir()
    try:
        _seed_source(base, source_engine, storage_root)
        _seed_runtime_tables(base, source_engine)
        with source_engine.begin() as connection:
            MigrationContext.configure(connection).stamp(scripts, head)

        result = migrate_database(
            source_engine,
            target_engine,
            base.metadata,
            scripts,
        )

        expected_dialects = (
            ("sqlite", "mysql")
            if direction == "sqlite-to-mysql"
            else ("mysql", "sqlite")
        )
        assert (result.source_dialect, result.target_dialect) == expected_dialects
        assert tuple(table.name for table in result.tables) == APPLICATION_TABLE_NAMES
        with target_engine.begin() as connection:
            comments = base.metadata.tables["comments"]
            inserted = connection.execute(
                insert(comments).values(
                    digest_version=1,
                    content_digest=bytes.fromhex("11" * 32),
                    comment_text="post-migration sequence check",
                    comment_data={"verified": True},
                )
            )
            assert inserted.inserted_primary_key[0] > 3
            assert MigrationContext.configure(connection).get_current_heads() == (head,)
    finally:
        _clear_mysql_database(mysql_engine)


def _clear_mysql_database(mysql_engine) -> None:
    with mysql_engine.connect() as connection:
        connection.execute(text("SET FOREIGN_KEY_CHECKS=0"))
        for table_name in inspect(connection).get_table_names():
            quoted_name = connection.dialect.identifier_preparer.quote(table_name)
            connection.execute(text(f"DROP TABLE {quoted_name}"))
        connection.execute(text("SET FOREIGN_KEY_CHECKS=1"))
        connection.commit()
