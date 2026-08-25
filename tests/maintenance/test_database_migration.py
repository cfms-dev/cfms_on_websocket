from pathlib import Path

import pytest
import tomlkit
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import create_engine, insert, inspect, select
from sqlalchemy.dialects import mysql

from include.database.engine import create_database_engine
from maintenance.database_migration import (
    DatabaseMigrationError,
    migrate_database,
    transfer_database_contents,
)
from maintenance.database_tables import APPLICATION_TABLE_NAMES
from maintenance.operations.database import (
    _activate_target_database,
    _load_target_database_config,
)
from maintenance.operations.exceptions import MaintenanceOperationError
from tests.maintenance.test_backup_format_compatibility import (
    _new_database,
    _seed_source,
)

_PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _script_directory() -> ScriptDirectory:
    return ScriptDirectory.from_config(Config(_PROJECT_ROOT / "src" / "alembic.ini"))


def test_mysql_schema_preserves_python_float_precision(backup_context) -> None:
    float_columns = []
    for table in backup_context.Base.metadata.tables.values():
        for column in table.columns:
            try:
                python_type = column.type.python_type
            except NotImplementedError:
                continue
            if python_type is float:
                float_columns.append(f"{table.name}.{column.name}")
                assert column.type.compile(dialect=mysql.dialect()) == "DOUBLE"

    assert "file_tasks.end_time" in float_columns


def test_transfer_clones_every_application_table(backup_context, tmp_path) -> None:
    base = backup_context.Base
    source_engine, _source_session = _new_database(base, tmp_path / "source.db")
    target_engine = create_database_engine(
        {"type": "sqlite", "file": str(tmp_path / "target.db")}
    )
    storage_root = tmp_path / "storage"
    storage_root.mkdir()
    _seed_source(base, source_engine, storage_root)
    _seed_runtime_tables(base, source_engine)

    scripts = _script_directory()
    head = scripts.get_current_head()
    assert head is not None
    results = transfer_database_contents(
        source_engine,
        target_engine,
        base.metadata,
        scripts,
        head,
    )

    assert tuple(result.name for result in results) == APPLICATION_TABLE_NAMES
    rows_by_table = {result.name: result.rows for result in results}
    assert rows_by_table["file_tasks"] == 1
    assert rows_by_table["system_states"] == 1
    assert rows_by_table["file_deduplication_tasks"] == 1
    with source_engine.connect() as source, target_engine.connect() as target:
        for table_name in APPLICATION_TABLE_NAMES:
            table = base.metadata.tables[table_name]
            statement = select(table).order_by(*table.primary_key.columns)
            assert target.execute(statement).all() == source.execute(statement).all()
        assert MigrationContext.configure(target).get_current_heads() == (head,)

    source_engine.dispose()
    target_engine.dispose()


def _seed_runtime_tables(base, source_engine) -> None:
    tables = base.metadata.tables
    with source_engine.begin() as connection:
        connection.execute(
            insert(tables["account_throttles"]),
            {
                "username": "alice",
                "factor": "password",
                "failed_attempts": 2,
                "last_attempt": 1_700_000_000.0,
                "locked_until": None,
            },
        )
        connection.execute(
            insert(tables["rate_limit_buckets"]),
            {
                "namespace": "request",
                "scope": "account",
                "identity": "alice",
                "tokens": 3.5,
                "last_refill_at": 1_700_000_000.0,
                "denial_count": 1,
                "last_denied_at": None,
                "last_attempt": 1_700_000_000.0,
            },
        )
        connection.execute(
            insert(tables["risk_ip_accounts"]),
            {
                "namespace": "request",
                "ip_address": "192.0.2.10",
                "username": "alice",
                "last_attempt": 1_700_000_000.0,
            },
        )
        connection.execute(
            insert(tables["file_deduplication_tasks"]),
            {
                "file_id": "file-doc",
                "phase": 0,
                "available_at": 1_700_000_000.0,
                "lease_owner": None,
                "lease_expires_at": None,
                "attempts": 0,
                "last_error": None,
                "created_time": 1_700_000_000.0,
            },
        )


def test_transfer_cleans_target_when_verification_fails(
    backup_context,
    tmp_path,
    monkeypatch,
) -> None:
    from maintenance import database_migration

    base = backup_context.Base
    source_engine, _source_session = _new_database(base, tmp_path / "source.db")
    target_engine = create_engine(f"sqlite:///{tmp_path / 'target.db'}")
    scripts = _script_directory()
    head = scripts.get_current_head()
    assert head is not None

    def fail_verification(*_args, **_kwargs):
        raise DatabaseMigrationError("verification failed")

    monkeypatch.setattr(database_migration, "_verify_tables", fail_verification)
    with pytest.raises(DatabaseMigrationError, match="verification failed"):
        transfer_database_contents(
            source_engine,
            target_engine,
            base.metadata,
            scripts,
            head,
        )

    assert inspect(target_engine).get_table_names() == []
    source_engine.dispose()
    target_engine.dispose()


def test_public_migration_rejects_same_database_engine() -> None:
    source_engine = create_engine("sqlite:///:memory:")
    target_engine = create_engine("sqlite:///:memory:")

    with pytest.raises(
        DatabaseMigrationError,
        match="Source and target database engines must be different",
    ):
        migrate_database(source_engine, target_engine, object(), object())


def test_target_config_is_validated_and_can_be_activated(tmp_path) -> None:
    workdir = tmp_path / "src"
    workdir.mkdir()
    current_source = (_PROJECT_ROOT / "src" / "config.toml.sample").read_text(
        encoding="utf-8"
    )
    config_path = workdir / "config.toml"
    config_path.write_text(current_source, encoding="utf-8")
    target_path = workdir / "target.toml"
    target_path.write_text(
        '[database]\ntype = "sqlite"\nfile = "migrated.db"\n',
        encoding="utf-8",
    )

    resolved, target_document, database = _load_target_database_config(
        workdir,
        target_path,
    )
    backup_path = _activate_target_database(config_path, target_document)

    assert resolved == target_path.resolve()
    assert database["file"] == "migrated.db"
    activated = tomlkit.parse(config_path.read_text(encoding="utf-8"))
    assert activated["database"]["type"] == "sqlite"
    assert activated["database"]["file"] == "migrated.db"
    assert activated["server"]["name"] == "CFMS WebSocket Server"
    assert backup_path.read_text(encoding="utf-8") == current_source


@pytest.mark.parametrize(
    ("source", "message"),
    [
        ('[database]\ntype = "sqlite"\nfile = ":memory:"\n', "in-memory"),
        (
            "[database]\n"
            'type = "mysql"\n'
            'host = "localhost"\n'
            "port = 3306\n"
            'username = "cfms"\n'
            'password = "secret"\n'
            'name = "app_db"\n'
            'charset = "latin1"\n',
            "utf8mb4",
        ),
    ],
)
def test_target_config_rejects_unsafe_database_settings(
    tmp_path,
    source,
    message,
) -> None:
    workdir = tmp_path / "src"
    workdir.mkdir()
    (workdir / "config.toml").write_text("", encoding="utf-8")
    target_path = workdir / "target.toml"
    target_path.write_text(source, encoding="utf-8")

    with pytest.raises(MaintenanceOperationError, match=message):
        _load_target_database_config(workdir, target_path)
