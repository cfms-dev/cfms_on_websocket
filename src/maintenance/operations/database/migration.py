import base64
import datetime as dt
import decimal
import enum
import hashlib
import logging
import time
from typing import TYPE_CHECKING, Any

import orjson
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import (
    MetaData,
    inspect,
    select,
    text,
)
from sqlalchemy.engine import Connection, Engine

from maintenance.operations.database.copying import (
    copy_tables,
    restore_deferred_columns,
)
from maintenance.operations.database.models import (
    DatabaseMigrationError,
    DatabaseMigrationResult,
    TableMigrationResult,
)
from maintenance.operations.database.progress import (
    add_progress_task,
    advance_progress,
    update_progress,
)
from maintenance.operations.database.tables import APPLICATION_TABLE_NAMES

if TYPE_CHECKING:
    from rich.progress import Progress, TaskID

_BATCH_SIZE = 1000
_ALEMBIC_TABLE_NAME = "alembic_version"
_SUPPORTED_DIALECTS = frozenset({"mysql", "sqlite"})
_SUPPORTED_MYSQL_LTS_SERIES = frozenset({(8, 4), (9, 7)})
_NODE_TABLE_NAMES = frozenset({"nodes", "folders", "documents"})
LOGGER = logging.getLogger(__name__)


def migrate_database(
    source_engine: Engine,
    target_engine: Engine,
    metadata: MetaData,
    script_directory: ScriptDirectory,
    *,
    progress: Progress | None = None,
) -> DatabaseMigrationResult:
    started_at = time.monotonic()
    source_dialect = source_engine.dialect.name
    target_dialect = target_engine.dialect.name
    _validate_dialect_pair(source_dialect, target_dialect)
    expected_head = script_directory.get_current_head()
    if expected_head is None:
        raise DatabaseMigrationError("The Alembic migration history has no head")

    with source_engine.connect() as source_connection:
        _validate_mysql_version(source_connection)
        _validate_source_schema(source_connection, metadata, expected_head)
    with target_engine.connect() as target_connection:
        _validate_mysql_version(target_connection)
        _validate_empty_target(target_connection)

    tables = transfer_database_contents(
        source_engine,
        target_engine,
        metadata,
        script_directory,
        expected_head,
        progress=progress,
    )
    return DatabaseMigrationResult(
        source_dialect=source_dialect,
        target_dialect=target_dialect,
        tables=tables,
        elapsed_seconds=time.monotonic() - started_at,
    )


def transfer_database_contents(
    source_engine: Engine,
    target_engine: Engine,
    metadata: MetaData,
    script_directory: ScriptDirectory,
    expected_head: str,
    *,
    progress: Progress | None = None,
) -> tuple[TableMigrationResult, ...]:
    _validate_metadata(metadata)
    target_schema_created = False
    try:
        target_schema_created = True
        metadata.create_all(target_engine)
        with (
            source_engine.connect() as source_connection,
            target_engine.connect() as target_connection,
            source_connection.begin(),
            target_connection.begin(),
        ):
            task_id = add_progress_task(progress)
            copy_tables(
                source_connection,
                target_connection,
                metadata,
                progress,
                task_id,
            )
            restore_deferred_columns(
                source_connection,
                target_connection,
                metadata,
            )
            source_results = _verify_tables(
                source_connection,
                target_connection,
                metadata,
                progress,
                task_id,
            )
            MigrationContext.configure(target_connection).stamp(
                script_directory,
                expected_head,
            )
        return source_results
    except Exception:
        if target_schema_created:
            _clean_target_schema(target_engine, metadata)
        raise


def _validate_dialect_pair(source_dialect: str, target_dialect: str) -> None:
    if source_dialect not in _SUPPORTED_DIALECTS:
        raise DatabaseMigrationError(
            f"Unsupported source database dialect: {source_dialect}"
        )
    if target_dialect not in _SUPPORTED_DIALECTS:
        raise DatabaseMigrationError(
            f"Unsupported target database dialect: {target_dialect}"
        )
    if source_dialect == target_dialect:
        raise DatabaseMigrationError(
            "Source and target database engines must be different"
        )


def _validate_mysql_version(connection: Connection) -> None:
    if connection.dialect.name != "mysql":
        return
    version = connection.dialect.server_version_info
    if version is None or version[:2] not in _SUPPORTED_MYSQL_LTS_SERIES:
        rendered = "unknown" if version is None else ".".join(map(str, version))
        raise DatabaseMigrationError(
            "Database migration requires MySQL 8.4.x or 9.7.x LTS; "
            f"connected to {rendered}"
        )


def _validate_metadata(metadata: MetaData) -> None:
    actual = set(metadata.tables)
    expected = set(APPLICATION_TABLE_NAMES)
    if actual != expected:
        missing = sorted(expected - actual)
        unexpected = sorted(actual - expected)
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        raise DatabaseMigrationError(
            "Application table metadata does not match the migration contract ("
            + "; ".join(details)
            + ")"
        )


def _validate_source_schema(
    connection: Connection,
    metadata: MetaData,
    expected_head: str,
) -> None:
    _validate_metadata(metadata)
    actual = set(inspect(connection).get_table_names())
    expected = set(APPLICATION_TABLE_NAMES)
    missing = sorted(expected - actual)
    unexpected = sorted(actual - expected - {_ALEMBIC_TABLE_NAME})
    if missing or unexpected:
        details = []
        if missing:
            details.append("missing: " + ", ".join(missing))
        if unexpected:
            details.append("unexpected: " + ", ".join(unexpected))
        raise DatabaseMigrationError(
            "Source database schema does not match the current application ("
            + "; ".join(details)
            + ")"
        )

    current_heads = MigrationContext.configure(connection).get_current_heads()
    if current_heads != (expected_head,):
        rendered = ", ".join(current_heads) if current_heads else "unversioned"
        raise DatabaseMigrationError(
            f"Source database must be at Alembic head {expected_head}; "
            f"current revision: {rendered}"
        )


def _validate_empty_target(connection: Connection) -> None:
    tables = sorted(inspect(connection).get_table_names())
    if tables:
        raise DatabaseMigrationError(
            "Target database must not contain tables; found: " + ", ".join(tables)
        )


def _verify_tables(
    source: Connection,
    target: Connection,
    metadata: MetaData,
    progress: Progress | None,
    task_id: TaskID | None,
) -> tuple[TableMigrationResult, ...]:
    results = []
    for table_name in APPLICATION_TABLE_NAMES:
        update_progress(progress, task_id, f"Verifying table {table_name}")
        table = metadata.tables[table_name]
        source_count, source_digest = _table_signature(source, table)
        target_count, target_digest = _table_signature(target, table)
        if target_count != source_count or target_digest != source_digest:
            raise DatabaseMigrationError(
                f"Target verification failed for table {table_name!r}"
            )
        results.append(
            TableMigrationResult(
                name=table_name,
                rows=source_count,
                sha256=source_digest,
            )
        )
        advance_progress(progress, task_id)
    return tuple(results)


def _table_signature(connection: Connection, table) -> tuple[int, str]:
    columns = tuple(table.columns)
    statement = select(*columns).order_by(*table.primary_key.columns)
    digest = hashlib.sha256()
    row_count = 0
    rows = connection.execute(
        statement,
        execution_options={"stream_results": True},
    ).mappings()
    for partition in rows.partitions(_BATCH_SIZE):
        for row in partition:
            _update_digest(digest, columns, row)
            row_count += 1
    return row_count, digest.hexdigest()


def _update_digest(digest, columns, row) -> None:
    values = [_canonical_value(row[column.name]) for column in columns]
    encoded = orjson.dumps(values, option=orjson.OPT_SORT_KEYS)
    digest.update(len(encoded).to_bytes(8, "big"))
    digest.update(encoded)


def _canonical_value(value: Any) -> Any:
    if isinstance(value, enum.Enum):
        return ["enum", _canonical_value(value.value)]
    if isinstance(value, bytes | bytearray | memoryview):
        return ["bytes", base64.b64encode(bytes(value)).decode("ascii")]
    if isinstance(value, dt.datetime):
        return ["datetime", value.isoformat()]
    if isinstance(value, dt.date):
        return ["date", value.isoformat()]
    if isinstance(value, decimal.Decimal):
        return ["decimal", str(value)]
    return value


def _clean_target_schema(target_engine: Engine, metadata: MetaData) -> None:
    try:
        metadata.drop_all(target_engine, checkfirst=True)
        with target_engine.begin() as connection:
            connection.execute(text("DROP TABLE IF EXISTS alembic_version"))
    except Exception:
        LOGGER.exception("Unable to clean the failed database migration target")
