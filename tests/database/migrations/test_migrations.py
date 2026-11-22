import uuid
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import (
    JSON,
    Boolean,
    Float,
    Integer,
    String,
    column,
    inspect,
    select,
    table,
)

import include.database.models  # noqa: F401
from alembic import command
from include.database.session import Base

pytestmark = pytest.mark.component
_ALEMBIC_INI = Path(__file__).resolve().parents[3] / "src/alembic.ini"


def test_document_lookup_indexes_round_trip(sqlite_engine_factory):
    config = Config(_ALEMBIC_INI)
    engine = sqlite_engine_factory()
    expected_indexes = {
        "documents": {"ix_documents_current_revision_id"},
        "document_revisions": {
            "ix_document_revisions_document_created_id",
            "ix_document_revisions_parent_revision_id",
        },
    }
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.stamp(config, "head")
        command.downgrade(config, "3c496a214a87")

        inspector = inspect(connection)
        for table_name, index_names in expected_indexes.items():
            assert index_names.isdisjoint(
                index["name"] for index in inspector.get_indexes(table_name)
            )

        command.upgrade(config, "0460356a5ba6")

        inspector = inspect(connection)
        for table_name, index_names in expected_indexes.items():
            assert index_names <= {
                index["name"] for index in inspector.get_indexes(table_name)
            }


def test_retained_revision_chain_round_trips_to_head(sqlite_engine_factory):
    config = Config(_ALEMBIC_INI)
    scripts = ScriptDirectory.from_config(config)
    assert scripts.get_base() == "fe8863687aa4"
    expected_heads = tuple(scripts.get_heads())
    engine = sqlite_engine_factory()
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.stamp(config, "head")
        command.downgrade(config, "76f1c7621e23")
        assert (
            MigrationContext.configure(connection).get_current_heads() != expected_heads
        )
        assert "ix_user_permissions_end_time_id" not in {
            index["name"]
            for index in inspect(connection).get_indexes("user_permissions")
        }
        assert "ix_group_permissions_end_time_id" not in {
            index["name"]
            for index in inspect(connection).get_indexes("group_permissions")
        }
        node_columns = {
            column["name"] for column in inspect(connection).get_columns("nodes")
        }
        assert "active_parent_id" in node_columns
        assert "active_name" not in node_columns

        command.upgrade(config, "head")
        assert (
            MigrationContext.configure(connection).get_current_heads() == expected_heads
        )
        assert "ix_user_permissions_end_time_id" in {
            index["name"]
            for index in inspect(connection).get_indexes("user_permissions")
        }
        assert "ix_group_permissions_end_time_id" in {
            index["name"]
            for index in inspect(connection).get_indexes("group_permissions")
        }
        node_columns = {
            column["name"] for column in inspect(connection).get_columns("nodes")
        }
        assert "active_name" in node_columns
        assert "active_parent_id" not in node_columns
        runtime_columns = {
            column["name"]
            for column in inspect(connection).get_columns("scheduling_runtime_state")
        }
        assert "redis_namespace" in runtime_columns


def test_execution_contract_snapshot_migration_backfills_queued_work(
    sqlite_engine_factory,
):
    config = Config(_ALEMBIC_INI)
    engine = sqlite_engine_factory()
    schedules = Base.metadata.tables["schedules"]
    old_executions = table(
        "schedule_executions",
        column("id", String()),
        column("schedule_id", String()),
        column("provider_generation", Integer()),
        column("scheduled_for", Float()),
        column("state", String()),
        column("dispatch_state", String()),
        column("attempt", Integer()),
        column("created_at", Float()),
    )
    snapshot_rows = table(
        "schedule_executions",
        column("task_name", String()),
        column("task_contract_version", Integer()),
        column("payload", JSON()),
    )
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.stamp(config, "head")
        command.downgrade(config, "6dba0956fa9d")
        connection.execute(
            schedules.insert(),
            {
                "id": "schedule-1",
                "task_name": "test.record",
                "task_contract_version": 3,
                "payload": {"value": 7},
                "trigger_type": "interval",
                "trigger_data": {"seconds": 60},
                "timezone": "UTC",
                "system_managed": False,
                "enabled": True,
                "status": "active",
                "revision": 1,
                "created_at": 1.0,
                "updated_at": 1.0,
            },
        )
        connection.execute(
            old_executions.insert(),
            {
                "id": "execution-1",
                "schedule_id": "schedule-1",
                "provider_generation": 1,
                "scheduled_for": 1.0,
                "state": "pending",
                "dispatch_state": "pending",
                "attempt": 0,
                "created_at": 1.0,
            },
        )
        connection.commit()

        command.upgrade(config, "3c496a214a87")

        assert connection.execute(select(snapshot_rows)).one() == (
            "test.record",
            3,
            {"value": 7},
        )


def test_scheduling_permission_downgrade_preserves_other_grants(sqlite_engine_factory):
    config = Config(_ALEMBIC_INI)
    engine = sqlite_engine_factory()
    tables = Base.metadata.tables
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        command.stamp(config, "head")
        command.downgrade(config, "ab7efda19079")
        connection.execute(
            tables["user_groups"].insert(),
            {"group_name": "sysop", "group_display_name": "System operators"},
        )
        connection.execute(
            tables["group_permissions"].insert(),
            {
                "group_name": "sysop",
                "permission": "view_schedules",
                "granted": True,
                "start_time": 0.0,
                "end_time": None,
            },
        )
        connection.commit()

        command.upgrade(config, "8c130010a943")
        connection.execute(
            tables["group_permissions"].insert(),
            {
                "group_name": "sysop",
                "permission": "manage_schedules",
                "granted": True,
                "start_time": 100.0,
                "end_time": 200.0,
            },
        )
        connection.commit()
        command.downgrade(config, "ab7efda19079")

        grants = set(
            connection.execute(
                select(
                    tables["group_permissions"].c.permission,
                    tables["group_permissions"].c.start_time,
                    tables["group_permissions"].c.end_time,
                ).where(tables["group_permissions"].c.group_name == "sysop")
            )
        )
        assert grants == {
            ("view_schedules", 0.0, None),
            ("manage_schedules", 100.0, 200.0),
        }


def test_system_schedule_migration_preserves_user_schedules_and_is_reversible(
    sqlite_engine_factory,
):
    config = Config(_ALEMBIC_INI)
    engine = sqlite_engine_factory()
    schedules = Base.metadata.tables["schedules"]
    users = Base.metadata.tables["users"]
    schedule_rows = table(
        "schedules",
        column("id", String()),
        column("system_managed", Boolean()),
    )
    Base.metadata.create_all(engine)
    with engine.connect() as connection:
        config.attributes["connection"] = connection
        admin_id = uuid.uuid4()
        connection.execute(
            users.insert(),
            {"id": admin_id, "username": "admin", "created_time": 1.0},
        )
        connection.execute(
            schedules.insert(),
            [
                {
                    "id": "user-schedule",
                    "task_name": "test.record",
                    "task_contract_version": 1,
                    "payload": {},
                    "trigger_type": "interval",
                    "trigger_data": {
                        "seconds": 60,
                        "start_at": "2026-01-01T00:00:00+00:00",
                    },
                    "timezone": "UTC",
                    "system_managed": False,
                    "enabled": True,
                    "status": "active",
                    "revision": 1,
                    "created_by": admin_id,
                    "created_at": 1.0,
                    "updated_by": admin_id,
                    "updated_at": 1.0,
                },
                {
                    "id": "system-schedule",
                    "task_name": "test.cleanup",
                    "task_contract_version": 1,
                    "payload": {},
                    "trigger_type": "interval",
                    "trigger_data": {
                        "seconds": 60,
                        "start_at": "2026-01-01T00:00:00+00:00",
                    },
                    "timezone": "UTC",
                    "system_managed": True,
                    "enabled": True,
                    "status": "active",
                    "revision": 1,
                    "created_by": None,
                    "created_at": 1.0,
                    "updated_by": None,
                    "updated_at": 1.0,
                },
                {
                    "id": "orphaned-user-schedule",
                    "task_name": "test.record",
                    "task_contract_version": 1,
                    "payload": {},
                    "trigger_type": "interval",
                    "trigger_data": {
                        "seconds": 60,
                        "start_at": "2026-01-01T00:00:00+00:00",
                    },
                    "timezone": "UTC",
                    "system_managed": False,
                    "enabled": True,
                    "status": "active",
                    "revision": 1,
                    "created_by": None,
                    "created_at": 1.0,
                    "updated_by": None,
                    "updated_at": 1.0,
                },
            ],
        )
        connection.commit()
        command.stamp(config, "head")

        command.downgrade(config, "8c130010a943")
        assert "system_managed" not in {
            item["name"] for item in inspect(connection).get_columns("schedules")
        }
        assert set(connection.scalars(select(schedule_rows.c.id))) == {"user-schedule"}

        command.upgrade(config, "39084f380eaa")
        assert "system_managed" in {
            item["name"] for item in inspect(connection).get_columns("schedules")
        }
        assert connection.execute(
            select(schedule_rows.c.id, schedule_rows.c.system_managed)
        ).all() == [("user-schedule", False)]
        assert "ck_schedules_system_ownership" not in {
            item["name"]
            for item in inspect(connection).get_check_constraints("schedules")
        }
        schedule_foreign_keys = {
            tuple(item["constrained_columns"]): item
            for item in inspect(connection).get_foreign_keys("schedules")
        }
        assert (
            schedule_foreign_keys[("created_by",)].get("options", {}).get("ondelete")
            == "SET NULL"
        )
        assert (
            schedule_foreign_keys[("updated_by",)].get("options", {}).get("ondelete")
            == "SET NULL"
        )
