import datetime as dt
import logging
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import orjson
from sqlalchemy import DateTime, Table

from maintenance.backup.archive import _safe_payload_path
from maintenance.backup.constants import MAX_JSONL_ROW_BYTES
from maintenance.backup.models import BackupFormatError

LOGGER = logging.getLogger(__name__)
_RESTORE_BATCH_SIZE = 1000
_LEGACY_ROW_COLUMNS = {
    "banned_subnets": {"reason"},
    "compiled_access_rules": {"node_id", "target_id"},
    "documents": {"folder_id", "inherit", "status", "status_operation_id", "title"},
    "folders": {"inherit", "name", "parent_id", "status", "status_operation_id"},
}


def _iter_raw_table_rows(
    extract_dir: Path,
    manifest: dict[str, Any],
    table_name: str,
) -> Iterator[dict[str, Any]]:
    table_manifest = manifest["tables"][table_name]
    path = _safe_payload_path(extract_dir, f"tables/{table_name}.jsonl")
    row_count = 0
    with path.open("rb") as f:
        line_number = 0
        while line := f.readline(MAX_JSONL_ROW_BYTES + 2):
            line_number += 1
            row_payload = line.removesuffix(b"\n")
            if len(row_payload) > MAX_JSONL_ROW_BYTES:
                raise BackupFormatError(
                    f"JSON row in {path} at line {line_number} exceeds the "
                    f"{MAX_JSONL_ROW_BYTES}-byte limit"
                )
            if not line.strip():
                continue
            try:
                row = orjson.loads(line)
            except orjson.JSONDecodeError as exc:
                raise BackupFormatError(
                    f"Invalid JSON row in {path} at line {line_number}"
                ) from exc
            if not isinstance(row, dict):
                raise BackupFormatError(
                    f"JSON row in {path} at line {line_number} must be an object"
                )
            row_count += 1
            yield row
    if row_count != table_manifest["rows"]:
        raise BackupFormatError(
            f"Row count mismatch for table {table_name!r}: "
            f"manifest says {table_manifest['rows']}, payload has {row_count}"
        )


def _iter_raw_table_row_batches(
    extract_dir: Path,
    manifest: dict[str, Any],
    table_name: str,
) -> Iterator[list[dict[str, Any]]]:
    batch = []
    for row in _iter_raw_table_rows(extract_dir, manifest, table_name):
        batch.append(row)
        if len(batch) == _RESTORE_BATCH_SIZE:
            yield batch
            batch = []
    if batch:
        yield batch


def _iter_table_row_batches(
    extract_dir: Path,
    manifest: dict[str, Any],
    table: Table,
) -> Iterator[list[dict[str, Any]]]:
    batch = []
    for row in _iter_raw_table_rows(extract_dir, manifest, table.name):
        batch.append(_decode_row(row, table))
        if len(batch) == _RESTORE_BATCH_SIZE:
            yield batch
            batch = []
    if batch:
        yield batch
    LOGGER.debug("Loaded table rows for %s", table.name)


def _decode_row(row: dict[str, Any], table: Table) -> dict[str, Any]:
    stored_columns = {
        column.name for column in table.columns if column.computed is None
    }
    unknown_columns = (
        set(row) - stored_columns - _LEGACY_ROW_COLUMNS.get(table.name, set())
    )
    if unknown_columns:
        raise BackupFormatError(
            f"Backup row for {table.name!r} contains unknown columns: "
            f"{sorted(unknown_columns)}"
        )
    missing_primary_keys = [
        column.name
        for column in table.primary_key.columns
        if column.name not in row or row[column.name] is None
    ]
    if missing_primary_keys:
        raise BackupFormatError(
            f"Backup row for {table.name!r} is missing primary key values: "
            f"{missing_primary_keys}"
        )
    if table.name == "banned_subnets":
        created_at = row.get("created_at")
        if isinstance(created_at, str):
            try:
                parsed_created_at = dt.datetime.fromisoformat(created_at)
            except ValueError as exc:
                raise BackupFormatError(
                    "Invalid datetime for banned_subnets.created_at"
                ) from exc
            if parsed_created_at.tzinfo is None:
                parsed_created_at = parsed_created_at.replace(tzinfo=dt.UTC)
            created_at = parsed_created_at.timestamp()
            row = {**row, "created_at": created_at}
        if "starts_at" not in row:
            row = {**row, "starts_at": created_at}
        if "expires_at" not in row:
            row = {**row, "expires_at": None}

    decoded = {}
    for column in table.columns:
        if column.computed is not None:
            continue
        if column.name not in row:
            decoded[column.name] = None
            continue
        value = row[column.name]
        if value is not None and isinstance(column.type, DateTime):
            try:
                value = dt.datetime.fromisoformat(value)
            except (TypeError, ValueError) as exc:
                raise BackupFormatError(
                    f"Invalid datetime for {table.name}.{column.name}"
                ) from exc
        if (
            value is not None
            and table.name == "comments"
            and column.name == "content_digest"
        ):
            if not isinstance(value, str) or len(value) != 64:
                raise BackupFormatError("Invalid comment digest in backup")
            try:
                value = bytes.fromhex(value)
            except ValueError as exc:
                raise BackupFormatError("Invalid comment digest in backup") from exc
            if len(value) != 32:
                raise BackupFormatError("Invalid comment digest in backup")
        decoded[column.name] = value
    return decoded
