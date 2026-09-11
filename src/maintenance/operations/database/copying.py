from typing import TYPE_CHECKING

from sqlalchemy import MetaData, bindparam, func, insert, literal, or_, select
from sqlalchemy.engine import Connection

from maintenance.operations.database.models import DatabaseMigrationError
from maintenance.operations.database.progress import advance_progress, update_progress
from maintenance.operations.database.tables import (
    APPLICATION_TABLE_NAMES,
    DEFERRED_COLUMNS,
    DEFERRED_UPDATE_ORDER,
)

if TYPE_CHECKING:
    from rich.progress import Progress, TaskID

_BATCH_SIZE = 1000


def copy_tables(
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
                update_progress(progress, task_id, f"Copying table {copied_name}")
                advance_progress(progress, task_id)
            continue
        update_progress(progress, task_id, f"Copying table {table_name}")
        table = metadata.tables[table_name]
        columns = tuple(column for column in table.columns if column.computed is None)
        order_by = tuple(table.primary_key.columns)
        if not order_by:
            raise DatabaseMigrationError(
                f"Application table {table_name!r} has no primary key"
            )
        statement = select(*columns).order_by(*order_by)
        rows = source.execute(
            statement,
            execution_options={"stream_results": True},
        ).mappings()
        for partition in rows.partitions(_BATCH_SIZE):
            insert_rows = []
            for row in partition:
                values = {column.name: row[column.name] for column in columns}
                for column_name in DEFERRED_COLUMNS.get(table_name, ()):
                    values[column_name] = None
                insert_rows.append(values)
            if insert_rows:
                target.execute(insert(table), insert_rows)
        advance_progress(progress, task_id)


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
    rows = source.execute(
        statement,
        execution_options={"stream_results": True},
    ).mappings()
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


def restore_deferred_columns(
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
        rows = source.execute(
            statement,
            execution_options={"stream_results": True},
        ).mappings()
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
