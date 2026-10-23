"""Extension-owned persistence declarations, independent of runtime activation."""

import importlib
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from graphlib import TopologicalSorter
from pathlib import Path
from typing import Any

from sqlalchemy import Connection, MetaData, Table, UniqueConstraint, inspect

from include.config import paths
from include.extensions.manager import discover_extensions

type DataRow = dict[str, Any]
type RowCodec = Callable[[DataRow], DataRow]
type RowValidator = Callable[[Mapping[str, Any]], None]


class ExtensionDataError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class ExtensionDataTable:
    owner: str
    table: Table
    backup_component: str | None = None
    encode_row: RowCodec | None = None
    decode_row: RowCodec | None = None
    validate_row: RowValidator | None = None


def load_extension_data(
    core_metadata: MetaData,
    extension_dir: Path | None = None,
) -> dict[str, ExtensionDataTable]:
    """Load installed data entrypoints without loading extension runtime code."""
    root = paths.EXTENSION_ROOT if extension_dir is None else extension_dir
    if not root.exists():
        return {}
    declarations = {}
    for owner, extension in discover_extensions(root).items():
        entrypoint = extension.manifest.data
        if entrypoint is None:
            continue
        try:
            module = importlib.import_module(entrypoint.module)
            entries = module.register_data()
            for entry in entries:
                if not isinstance(entry, ExtensionDataTable) or entry.owner != owner:
                    raise ExtensionDataError(f"Invalid data ownership for {owner!r}")
                name = str(entry.table.name)
                if entry.table.schema is not None or not re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_]*", name
                ):
                    raise ExtensionDataError(
                        f"Unsupported extension table name: {name!r}"
                    )
                existing = core_metadata.tables.get(name)
                if (
                    existing is not None
                    and existing.info.get("extension_data") != entry
                ) or name in declarations:
                    raise ExtensionDataError(
                        f"Duplicate data table ownership: {name!r}"
                    )
                if entry.backup_component not in {
                    None,
                    "accounts",
                    "documents",
                    "audit",
                    "banned_subnets",
                }:
                    raise ExtensionDataError(f"Invalid backup component for {name!r}")
                declarations[name] = entry
        except ExtensionDataError:
            raise
        except Exception as exc:
            raise ExtensionDataError(
                f"Failed to load data for extension {owner!r}"
            ) from exc

    graph = {}
    for name, entry in declarations.items():
        dependencies = {
            key.target_fullname.rsplit(".", 1)[0] for key in entry.table.foreign_keys
        }
        unknown = dependencies - set(core_metadata.tables) - set(declarations)
        if unknown:
            raise ExtensionDataError(
                f"Unknown data dependencies for {name!r}: {sorted(unknown)}"
            )
        graph[name] = dependencies & set(declarations) - {name}
    ordered = {
        name: declarations[name] for name in TopologicalSorter(graph).static_order()
    }
    for entry in ordered.values():
        entry.table.info["extension_data"] = entry
    return ordered


def extension_metadata(
    core_metadata: MetaData,
    declarations: Mapping[str, ExtensionDataTable],
    table_names: set[str] | None = None,
) -> MetaData:
    """Compose operation-local metadata without registering extension models in core."""
    metadata = MetaData(naming_convention=core_metadata.naming_convention)
    for name, table in core_metadata.tables.items():
        if name not in declarations or table_names is None or name in table_names:
            table.to_metadata(metadata)
    for name, entry in declarations.items():
        if name not in metadata.tables and (table_names is None or name in table_names):
            entry.table.to_metadata(metadata)
    return metadata


def prepare_extension_tables(
    connection: Connection,
    metadata: MetaData,
    table_names: set[str],
    *,
    create: bool = True,
) -> None:
    """Adopt compatible existing tables and optionally create missing ones."""
    inspector = inspect(connection)
    existing = set(inspector.get_table_names())
    for name in table_names & existing:
        table = metadata.tables[name]
        columns = {column["name"]: column for column in inspector.get_columns(name)}
        compatible = set(columns) == set(table.c.keys())
        for column in table.columns:
            actual = columns.get(column.name)
            if actual is None:
                continue
            compatible &= (
                str(actual["type"].compile(dialect=connection.dialect)).upper()
                == str(column.type.compile(dialect=connection.dialect)).upper()
                and actual["nullable"] == column.nullable
            )
        compatible &= inspector.get_pk_constraint(name)["constrained_columns"] == [
            column.name for column in table.primary_key.columns
        ]
        unique_sets = {
            tuple(constraint["column_names"])
            for constraint in inspector.get_unique_constraints(name)
        } | {
            tuple(index["column_names"])
            for index in inspector.get_indexes(name)
            if index["unique"]
        }
        compatible &= all(
            tuple(column.name for column in constraint.columns) in unique_sets
            for constraint in table.constraints
            if isinstance(constraint, UniqueConstraint)
        )
        indexes = {
            (tuple(index["column_names"]), bool(index["unique"]))
            for index in inspector.get_indexes(name)
        }
        compatible &= all(
            (tuple(column.name for column in index.columns), bool(index.unique))
            in indexes
            for index in table.indexes
        )
        foreign_keys = {
            (
                tuple(key["constrained_columns"]),
                key["referred_table"],
                tuple(key["referred_columns"]),
                key["options"].get("ondelete"),
            )
            for key in inspector.get_foreign_keys(name)
        }
        compatible &= all(
            (
                tuple(element.parent.name for element in key.elements),
                key.referred_table.name,
                tuple(element.column.name for element in key.elements),
                key.ondelete,
            )
            in foreign_keys
            for key in table.foreign_key_constraints
        )
        if not compatible:
            raise ExtensionDataError(f"Incompatible extension table schema: {name!r}")
    if create:
        metadata.create_all(
            connection, tables=[metadata.tables[name] for name in table_names]
        )
