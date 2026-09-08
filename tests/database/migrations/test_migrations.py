from pathlib import Path
from shutil import copyfile

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
    create_engine,
    inspect,
    select,
    table,
)

from alembic import command
from tests.support.config import reserve_local_port, write_test_config


def test_document_lookup_indexes_round_trip(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src_dir = Path(__file__).resolve().parents[3] / "src"
    copyfile(src_dir / "config.toml.sample", tmp_path / "config.toml")
    write_test_config(tmp_path, reserve_local_port())
    monkeypatch.chdir(tmp_path)

    from include.database import models as database_models

    config = Config(src_dir / "alembic.ini")
    database_url = f"sqlite:///{(tmp_path / 'document-indexes.db').as_posix()}"
    config.set_main_option("sqlalchemy.url", database_url)
    engine = create_engine(database_url)
    expected_indexes = {
        "documents": {"ix_documents_current_revision_id"},
        "document_revisions": {
            "ix_document_revisions_document_created_id",
            "ix_document_revisions_parent_revision_id",
        },
    }
    try:
        database_models.User.metadata.create_all(engine)
        command.stamp(config, "head")
        command.downgrade(config, "3c496a214a87")

        inspector = inspect(engine)
        for table_name, index_names in expected_indexes.items():
            assert index_names.isdisjoint(
                index["name"] for index in inspector.get_indexes(table_name)
            )

        command.upgrade(config, "head")

        inspector = inspect(engine)
        for table_name, index_names in expected_indexes.items():
            assert index_names <= {
                index["name"] for index in inspector.get_indexes(table_name)
            }
    finally:
        engine.dispose()


def test_retained_revision_chain_round_trips_to_head(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src_dir = Path(__file__).resolve().parents[3] / "src"
    copyfile(src_dir / "config.toml.sample", tmp_path / "config.toml")
    write_test_config(tmp_path, reserve_local_port())
    monkeypatch.chdir(tmp_path)

    from include.database import models as database_models

    config = Config(src_dir / "alembic.ini")
    database_url = f"sqlite:///{(tmp_path / 'migrations.db').as_posix()}"
    config.set_main_option("sqlalchemy.url", database_url)

    scripts = ScriptDirectory.from_config(config)
    assert scripts.get_base() == "fe8863687aa4"
    expected_heads = tuple(scripts.get_heads())
    engine = create_engine(database_url)
    try:
        database_models.User.metadata.create_all(engine)
        command.stamp(config, "head")
        command.downgrade(config, "76f1c7621e23")
        with engine.connect() as connection:
            assert (
                MigrationContext.configure(connection).get_current_heads()
                != expected_heads
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
        with engine.connect() as connection:
            assert MigrationContext.configure(connection).get_current_heads() == (
                expected_heads
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
                for column in inspect(connection).get_columns(
                    "scheduling_runtime_state"
                )
            }
            assert "redis_namespace" in runtime_columns
    finally:
        engine.dispose()


def test_execution_contract_snapshot_migration_backfills_queued_work(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src_dir = Path(__file__).resolve().parents[3] / "src"
    copyfile(src_dir / "config.toml.sample", tmp_path / "config.toml")
    write_test_config(tmp_path, reserve_local_port())
    monkeypatch.chdir(tmp_path)

    from include.database import models as database_models

    config = Config(src_dir / "alembic.ini")
    database_url = f"sqlite:///{(tmp_path / 'execution-snapshots.db').as_posix()}"
    config.set_main_option("sqlalchemy.url", database_url)
    engine = create_engine(database_url)
    schedules = database_models.User.metadata.tables["schedules"]
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
    try:
        database_models.User.metadata.create_all(engine)
        command.stamp(config, "head")
        command.downgrade(config, "6dba0956fa9d")
        with engine.begin() as connection:
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

        command.upgrade(config, "head")

        with engine.connect() as connection:
            assert connection.execute(select(snapshot_rows)).one() == (
                "test.record",
                3,
                {"value": 7},
            )
    finally:
        engine.dispose()


def test_scheduling_permission_downgrade_preserves_other_grants(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src_dir = Path(__file__).resolve().parents[3] / "src"
    copyfile(src_dir / "config.toml.sample", tmp_path / "config.toml")
    write_test_config(tmp_path, reserve_local_port())
    monkeypatch.chdir(tmp_path)

    from include.database import models as database_models

    config = Config(src_dir / "alembic.ini")
    database_url = f"sqlite:///{(tmp_path / 'permissions.db').as_posix()}"
    config.set_main_option("sqlalchemy.url", database_url)
    engine = create_engine(database_url)
    tables = database_models.User.metadata.tables
    try:
        database_models.User.metadata.create_all(engine)
        command.stamp(config, "head")
        command.downgrade(config, "ab7efda19079")
        with engine.begin() as connection:
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
        command.upgrade(config, "head")
        with engine.begin() as connection:
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
        command.downgrade(config, "ab7efda19079")

        with engine.connect() as connection:
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
    finally:
        engine.dispose()


def test_system_schedule_migration_preserves_user_schedules_and_is_reversible(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    src_dir = Path(__file__).resolve().parents[3] / "src"
    copyfile(src_dir / "config.toml.sample", tmp_path / "config.toml")
    write_test_config(tmp_path, reserve_local_port())
    monkeypatch.chdir(tmp_path)

    from include.database import models as database_models

    config = Config(src_dir / "alembic.ini")
    database_url = f"sqlite:///{(tmp_path / 'system-schedules.db').as_posix()}"
    config.set_main_option("sqlalchemy.url", database_url)
    engine = create_engine(database_url)
    schedules = database_models.User.metadata.tables["schedules"]
    schedule_rows = table(
        "schedules",
        column("id", String()),
        column("system_managed", Boolean()),
    )
    try:
        database_models.User.metadata.create_all(engine)
        with engine.begin() as connection:
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
                        "created_by": "admin",
                        "created_at": 1.0,
                        "updated_by": "admin",
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
        command.stamp(config, "head")

        command.downgrade(config, "8c130010a943")
        with engine.connect() as connection:
            assert "system_managed" not in {
                item["name"] for item in inspect(connection).get_columns("schedules")
            }
            assert set(connection.scalars(select(schedule_rows.c.id))) == {
                "user-schedule"
            }

        command.upgrade(config, "head")
        with engine.connect() as connection:
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
            assert schedule_foreign_keys[("created_by",)]["options"]["ondelete"] == (
                "SET NULL"
            )
            assert schedule_foreign_keys[("updated_by",)]["options"]["ondelete"] == (
                "SET NULL"
            )
    finally:
        engine.dispose()
