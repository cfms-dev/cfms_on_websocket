from pathlib import Path

import pytest
from alembic.config import Config
from sqlalchemy import inspect, select
from sqlalchemy.orm import sessionmaker

from alembic import command
from include.database.models.auth import (
    UserAuthPolicy,
    UserPasswordCredential,
    UserTotpCredential,
)
from include.database.models.identity import User
from include.database.session import Base

pytestmark = pytest.mark.component
_ROOT = Path(__file__).resolve().parents[3]
_FIXTURES = _ROOT / "tests/fixtures/authentication_v27"


def test_real_legacy_schema_preserves_credentials_and_references(sqlite_engine_factory):
    engine = sqlite_engine_factory()
    with engine.connect() as connection:
        raw = connection.connection.driver_connection
        raw.execute("PRAGMA foreign_keys=OFF")
        raw.executescript((_FIXTURES / "schema.sql").read_text(encoding="utf-8"))
        raw.executescript((_FIXTURES / "seed.sql").read_text(encoding="utf-8"))
        raw.execute("PRAGMA foreign_keys=ON")
        assert raw.execute("PRAGMA foreign_key_check").fetchall() == []
        connection.exec_driver_sql(
            "INSERT INTO document_metadata_tags (document_id, tag, position) "
            "VALUES ('legacy-document', 'retained', 0)"
        )
        connection.exec_driver_sql(
            "INSERT INTO userblock_entries "
            "(block_id, username, timestamp, not_before, not_after, target_type) "
            "VALUES ('legacy-block', 'alice', 1, 0, 999, 'all')"
        )
        connection.exec_driver_sql(
            "INSERT INTO userblock_sub_entries (parent_id, block_type) "
            "VALUES ('legacy-block', 'read')"
        )
        connection.exec_driver_sql(
            "INSERT INTO schedule_executions "
            "(id, schedule_id, task_name, task_contract_version, payload, provider_generation, "
            "scheduled_for, state, dispatch_state, attempt, created_at) "
            "SELECT 'legacy-execution', id, task_name, task_contract_version, payload, "
            "1, 100, 'pending', 'pending', 0, 100 FROM schedules"
        )
        original_hash = connection.exec_driver_sql(
            "SELECT pass_hash FROM users WHERE username = 'alice'"
        ).scalar_one()
        config = Config(_ROOT / "src/alembic.ini")
        config.attributes["connection"] = connection
        command.stamp(config, "0460356a5ba6")
        command.upgrade(config, "b2ea9cac8462")
        with sessionmaker(bind=connection)() as session:
            user = session.scalar(select(User).where(User.username == "alice"))
            user_id = user.id
            assert user.secret_key == "s" * 64
            assert user.preference_dek_id == "legacy-key"
            password = session.get(UserPasswordCredential, user_id)
            assert password.pass_hash == original_hash
            assert password.verify("LegacyPassword123!")
            assert password.passwd_last_modified == 0
            totp = session.get(UserTotpCredential, user_id)
            assert totp.enabled is True
            assert totp.secret == "JBSWY3DPEHPK3PXP"
            assert totp.backup_codes == "[]"
            assert session.get(UserAuthPolicy, (user_id, "mfa")).chains == [
                [{"method": "totp", "credential_ids": [totp.credential_id]}]
            ]
        for name, column in (
            ("user_permissions", "user_id"),
            ("user_memberships", "user_id"),
            ("keyrings", "user_id"),
            ("audit_entries", "user_id"),
            ("document_metadata", "creator_id"),
            ("document_metadata", "last_modified_by_id"),
            ("schedules", "created_by"),
            ("schedules", "updated_by"),
        ):
            assert (
                connection.scalar(select(Base.metadata.tables[name].c[column]))
                == user_id
            )
        assert raw.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.exec_driver_sql(
            "SELECT tag FROM document_metadata_tags"
        ).scalars().all() == ["retained"]
        assert connection.exec_driver_sql(
            "SELECT parent_id FROM userblock_sub_entries"
        ).scalars().all() == ["legacy-block"]
        assert connection.exec_driver_sql(
            "SELECT id FROM schedule_executions"
        ).scalars().all() == ["legacy-execution"]
        command.downgrade(config, "0460356a5ba6")
        assert {"pass_hash", "totp_secret"} <= {
            column["name"] for column in inspect(connection).get_columns("users")
        }
        assert connection.exec_driver_sql(
            "SELECT pass_hash, passwd_last_modified, totp_secret, totp_enabled "
            "FROM users WHERE username = 'alice'"
        ).one() == (original_hash, 0, "JBSWY3DPEHPK3PXP", 1)
        assert "user_passwords" not in inspect(connection).get_table_names()
        assert (
            connection.exec_driver_sql(
                "SELECT preference_dek_id FROM users WHERE username = 'alice'"
            ).scalar_one()
            == "legacy-key"
        )
        command.upgrade(config, "b2ea9cac8462")
        assert raw.execute("PRAGMA foreign_key_check").fetchall() == []
