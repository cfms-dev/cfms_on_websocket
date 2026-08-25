import base64
import datetime as dt
import decimal
import enum
import hashlib
import logging
import time
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import orjson
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import (
    MetaData,
    bindparam,
    func,
    insert,
    inspect,
    literal,
    or_,
    select,
    text,
)
from sqlalchemy.engine import Connection, Engine

from maintenance.database_tables import (
    APPLICATION_TABLE_NAMES,
    DEFERRED_COLUMNS,
    DEFERRED_UPDATE_ORDER,
)

if TYPE_CHECKING:
    from rich.progress import Progress, TaskID

_BATCH_SIZE = 1000
_ALEMBIC_TABLE_NAME = "alembic_version"
_SUPPORTED_DIALECTS = frozenset({"mysql", "sqlite"})
_NODE_TABLE_NAMES = frozenset({"nodes", "folders", "documents"})
LOGGER = logging.getLogger(__name__)


class DatabaseMigrationError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class TableMigrationResult:
    name: str
    rows: int
    sha256: str


@dataclass(frozen=True, slots=True)
class DatabaseMigrationResult:
    source_dialect: str
    target_dialect: str
    tables: tuple[TableMigrationResult, ...]
    elapsed_seconds: float

    @property
    def row_count(self) -> int:
        return sum(table.rows for table in self.tables)


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
            task_id = _add_progress_task(progress)
            _copy_tables(
                source_connection,
                target_connection,
                metadata,
                progress,
                task_id,
            )
            _restore_deferred_columns(
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
    if version is None or version[:2] != (8, 4):
        rendered = "unknown" if version is None else ".".join(map(str, version))
        raise DatabaseMigrationError(
            f"Database migration requires MySQL 8.4.x; connected to {rendered}"
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


def _copy_tables(
    source: Connection,
    target: Connection,
    metadata: MetaData,
    progress: Progress | None,
    task_id: TaskID | None,
) -> None:
    for table_name in APPLICATION_TABLE_NAMES:
        if table_name in {"folders", "documents"}:
            continue
        if table_name == "nodes":
            _copy_node_tables(source, target, metadata)
            for copied_name in ("nodes", "folders", "documents"):
                _update_progress(progress, task_id, f"Copying table {copied_name}")
                _advance_progress(progress, task_id)
            continue
        _update_progress(progress, task_id, f"Copying table {table_name}")
        table = metadata.tables[table_name]
        columns = tuple(column for column in table.columns if column.computed is None)
        order_by = tuple(table.primary_key.columns)
        if not order_by:
            raise DatabaseMigrationError(
                f"Application table {table_name!r} has no primary key"
            )
        statement = select(*columns).order_by(*order_by)
        rows = (
            source.execution_options(stream_results=True).execute(statement).mappings()
        )
        for partition in rows.partitions(_BATCH_SIZE):
            insert_rows = []
            for row in partition:
                values = {column.name: row[column.name] for column in columns}
                for column_name in DEFERRED_COLUMNS.get(table_name, ()):
                    values[column_name] = None
                insert_rows.append(values)
            if insert_rows:
                target.execute(insert(table), insert_rows)
        _advance_progress(progress, task_id)


def _copy_node_tables(
    source: Connection,
    target: Connection,
    metadata: MetaData,
) -> None:
    nodes = metadata.tables["nodes"]
    folders = metadata.tables["folders"]
    documents = metadata.tables["documents"]
    node_columns = tuple(column for column in nodes.columns if column.computed is None)
    folder_columns = tuple(
        column for column in folders.columns if column.computed is None
    )
    document_columns = tuple(
        column for column in documents.columns if column.computed is None
    )
    root = select(nodes.c.id, literal(0).label("migration_depth")).where(
        nodes.c.parent_id.is_(None)
    )
    hierarchy = root.cte("migration_node_hierarchy", recursive=True)
    child = nodes.alias("migration_child_node")
    hierarchy = hierarchy.union_all(
        select(child.c.id, (hierarchy.c.migration_depth + 1).label("migration_depth"))
        .select_from(child)
        .join(hierarchy, child.c.parent_id == hierarchy.c.id)
    )
    statement = (
        select(
            *node_columns,
            hierarchy.c.migration_depth,
            *(
                column.label(f"migration_folder_{column.name}")
                for column in folder_columns
            ),
            *(
                column.label(f"migration_document_{column.name}")
                for column in document_columns
            ),
        )
        .select_from(nodes)
        .join(hierarchy, nodes.c.id == hierarchy.c.id)
        .outerjoin(folders, folders.c.id == nodes.c.id)
        .outerjoin(documents, documents.c.id == nodes.c.id)
        .order_by(hierarchy.c.migration_depth, nodes.c.id)
    )

    copied_nodes = 0
    current_depth = None
    node_rows = []
    folder_rows = []
    document_rows = []
    rows = source.execution_options(stream_results=True).execute(statement).mappings()
    for row in rows:
        depth = row["migration_depth"]
        if node_rows and (depth != current_depth or len(node_rows) == _BATCH_SIZE):
            _insert_node_partition(
                target,
                nodes,
                folders,
                documents,
                node_rows,
                folder_rows,
                document_rows,
            )
            copied_nodes += len(node_rows)
            node_rows = []
            folder_rows = []
            document_rows = []
        current_depth = depth
        node_values = {column.name: row[column.name] for column in node_columns}
        for column_name in DEFERRED_COLUMNS["nodes"]:
            node_values[column_name] = None
        node_rows.append(node_values)
        match row["type"]:
            case "directory":
                folder_rows.append(
                    {
                        column.name: row[f"migration_folder_{column.name}"]
                        for column in folder_columns
                    }
                )
            case "document":
                values = {
                    column.name: row[f"migration_document_{column.name}"]
                    for column in document_columns
                }
                for column_name in DEFERRED_COLUMNS["documents"]:
                    values[column_name] = None
                document_rows.append(values)
            case other:
                raise DatabaseMigrationError(
                    f"Unsupported node type {other!r} for node {row['id']!r}"
                )
    if node_rows:
        _insert_node_partition(
            target,
            nodes,
            folders,
            documents,
            node_rows,
            folder_rows,
            document_rows,
        )
        copied_nodes += len(node_rows)

    source_node_count = source.execute(
        select(func.count()).select_from(nodes)
    ).scalar_one()
    if copied_nodes != source_node_count:
        raise DatabaseMigrationError(
            "Source node hierarchy is disconnected or contains a cycle"
        )


def _insert_node_partition(
    target: Connection,
    nodes,
    folders,
    documents,
    node_rows,
    folder_rows,
    document_rows,
) -> None:
    if len(folder_rows) + len(document_rows) != len(node_rows):
        raise DatabaseMigrationError(
            "Source node subtype tables do not match the node hierarchy"
        )
    target.execute(insert(nodes), node_rows)
    if folder_rows:
        target.execute(insert(folders), folder_rows)
    if document_rows:
        target.execute(insert(documents), document_rows)


def _restore_deferred_columns(
    source: Connection,
    target: Connection,
    metadata: MetaData,
) -> None:
    for table_name, pk_name, column_names in DEFERRED_UPDATE_ORDER:
        table = metadata.tables[table_name]
        pk_column = table.c[pk_name]
        deferred_columns = tuple(table.c[name] for name in column_names)
        statement = (
            select(pk_column, *deferred_columns)
            .where(or_(*(column.is_not(None) for column in deferred_columns)))
            .order_by(pk_column)
        )
        update_statement = (
            table.update()
            .where(pk_column == bindparam("migration_primary_key"))
            .values(
                {
                    column.name: bindparam(f"migration_value_{column.name}")
                    for column in deferred_columns
                }
            )
        )
        rows = (
            source.execution_options(stream_results=True).execute(statement).mappings()
        )
        for partition in rows.partitions(_BATCH_SIZE):
            parameters = [
                {
                    "migration_primary_key": row[pk_name],
                    **{
                        f"migration_value_{column.name}": row[column.name]
                        for column in deferred_columns
                    },
                }
                for row in partition
            ]
            if parameters:
                target.execute(update_statement, parameters)


def _verify_tables(
    source: Connection,
    target: Connection,
    metadata: MetaData,
    progress: Progress | None,
    task_id: TaskID | None,
) -> tuple[TableMigrationResult, ...]:
    results = []
    for table_name in APPLICATION_TABLE_NAMES:
        _update_progress(progress, task_id, f"Verifying table {table_name}")
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
        _advance_progress(progress, task_id)
    return tuple(results)


def _table_signature(connection: Connection, table) -> tuple[int, str]:
    columns = tuple(table.columns)
    statement = select(*columns).order_by(*table.primary_key.columns)
    digest = hashlib.sha256()
    row_count = 0
    rows = (
        connection.execution_options(stream_results=True).execute(statement).mappings()
    )
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


def _add_progress_task(progress: Progress | None) -> TaskID | None:
    if progress is None:
        return None
    return progress.add_task(
        "Migrating database tables",
        total=len(APPLICATION_TABLE_NAMES) * 2,
    )


def _update_progress(
    progress: Progress | None,
    task_id: TaskID | None,
    description: str,
) -> None:
    if progress is not None and task_id is not None:
        progress.update(task_id, description=description)


def _advance_progress(
    progress: Progress | None,
    task_id: TaskID | None,
) -> None:
    if progress is not None and task_id is not None:
        progress.advance(task_id)
