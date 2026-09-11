import datetime as dt
import logging
from pathlib import Path
from typing import Any

import orjson
from sqlalchemy import DateTime, Table

from maintenance.backup.archive import _safe_payload_path
from maintenance.backup.models import BackupFormatError

LOGGER = logging.getLogger(__name__)


def _load_table_rows(
    extract_dir: Path,
    manifest: dict[str, Any],
    table: Table,
) -> list[dict[str, Any]]:
    table_name = table.name
    table_manifest = manifest["tables"][table_name]
    path = _safe_payload_path(extract_dir, f"tables/{table_name}.jsonl")
    rows = []
    with path.open("rb") as f:
        for line_number, line in enumerate(f, start=1):
            if not line.strip():
                continue
            try:
                row = orjson.loads(line)
            except orjson.JSONDecodeError as exc:
                raise BackupFormatError(
                    f"Invalid JSON row in {path} at line {line_number}"
                ) from exc
            rows.append(_decode_row(row, table))
    if len(rows) != table_manifest["rows"]:
        raise BackupFormatError(
            f"Row count mismatch for table {table_name!r}: "
            f"manifest says {table_manifest['rows']}, payload has {len(rows)}"
        )
    LOGGER.debug("Loaded %d row(s) for table %s", len(rows), table_name)
    return rows


def _decode_row(row: dict[str, Any], table: Table) -> dict[str, Any]:
    if table.name == "banned_subnets":
        created_at = row.get("created_at")
        if isinstance(created_at, str):
            parsed_created_at = dt.datetime.fromisoformat(created_at)
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
            value = dt.datetime.fromisoformat(value)
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
