import contextlib
import datetime as dt
import math
import os
import tempfile
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

import orjson
from sqlalchemy import Table, delete, func, select
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql.elements import ColumnElement

from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.runtime import enter_server_root, load_database_models

_SECONDS_PER_DAY = 24 * 60 * 60
_AUDIT_COLUMNS = (
    "id",
    "action",
    "username",
    "target",
    "data",
    "result",
    "remote_address",
    "logged_time",
)


@dataclass(frozen=True, slots=True)
class AuditSelection:
    cutoff: float
    actions: tuple[str, ...] = ()
    usernames: tuple[str, ...] = ()
    targets: tuple[str, ...] = ()
    results: tuple[int, ...] = ()
    remote_addresses: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class AuditInspectionResult:
    selection: AuditSelection
    total: int
    action_counts: tuple[tuple[str, int], ...]
    result_counts: tuple[tuple[int, int], ...]


@dataclass(frozen=True, slots=True)
class AuditExportResult:
    output_path: Path
    selection: AuditSelection
    record_count: int


@dataclass(frozen=True, slots=True)
class AuditPurgeResult:
    archive_path: Path
    selection: AuditSelection
    archived_count: int
    deleted_count: int


def create_audit_selection(
    *,
    before: dt.datetime | None = None,
    actions: Iterable[str] = (),
    usernames: Iterable[str] = (),
    targets: Iterable[str] = (),
    results: Iterable[int] = (),
    remote_addresses: Iterable[str] = (),
    now: float | None = None,
) -> AuditSelection:
    enter_server_root()

    from include.config.validation import AuditRetentionPolicy

    if before is not None:
        if before.tzinfo is None or before.utcoffset() is None:
            raise MaintenanceOperationError("--before must include a timezone offset.")
        try:
            cutoff = before.timestamp()
        except (OSError, OverflowError, ValueError) as exc:
            raise MaintenanceOperationError(
                "--before is outside the supported range."
            ) from exc
    else:
        policy = AuditRetentionPolicy.from_config()
        reference_time = time.time() if now is None else now
        cutoff = reference_time - policy.retention_days * _SECONDS_PER_DAY

    if not math.isfinite(cutoff):
        raise MaintenanceOperationError("Audit cutoff must be a finite timestamp.")

    return AuditSelection(
        cutoff=cutoff,
        actions=tuple(dict.fromkeys(actions)),
        usernames=tuple(dict.fromkeys(usernames)),
        targets=tuple(dict.fromkeys(targets)),
        results=tuple(dict.fromkeys(results)),
        remote_addresses=tuple(dict.fromkeys(remote_addresses)),
    )


def inspect_audit_entries(selection: AuditSelection) -> AuditInspectionResult:
    enter_server_root()
    load_database_models()

    from include.database.models.operations import AuditEntry
    from include.database.session import Session

    table = AuditEntry.__table__
    conditions = _selection_conditions(table, selection)
    try:
        with Session() as session:
            total = session.scalar(
                select(func.count()).select_from(table).where(*conditions)
            )
            action_counts = tuple(
                (str(action), int(count))
                for action, count in session.execute(
                    select(table.c.action, func.count())
                    .where(*conditions)
                    .group_by(table.c.action)
                    .order_by(table.c.action)
                )
            )
            result_counts = tuple(
                (int(result), int(count))
                for result, count in session.execute(
                    select(table.c.result, func.count())
                    .where(*conditions)
                    .group_by(table.c.result)
                    .order_by(table.c.result)
                )
            )
    except SQLAlchemyError as exc:
        raise MaintenanceOperationError(
            f"Unable to inspect eligible audit entries: {exc}"
        ) from exc

    return AuditInspectionResult(
        selection=selection,
        total=int(total or 0),
        action_counts=action_counts,
        result_counts=result_counts,
    )


def export_audit_entries(
    output_path: str | Path,
    selection: AuditSelection,
) -> AuditExportResult:
    enter_server_root()
    load_database_models()

    from include.config.validation import AuditRetentionPolicy
    from include.database.models.operations import AuditEntry
    from include.database.session import Session

    policy = AuditRetentionPolicy.from_config()
    table = AuditEntry.__table__
    output = Path(output_path)
    if output.exists():
        raise MaintenanceOperationError(f"Audit export already exists: {output}")

    columns = [table.c[name] for name in _AUDIT_COLUMNS]
    statement = (
        select(*columns)
        .where(*_selection_conditions(table, selection))
        .order_by(table.c.logged_time, table.c.id)
        .execution_options(yield_per=policy.batch_size)
    )

    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        file_descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{output.name}.",
            suffix=".tmp",
            dir=output.parent,
        )
    except OSError as exc:
        raise MaintenanceOperationError(
            f"Unable to prepare audit export {output}: {exc}"
        ) from exc

    temporary_path = Path(temporary_name)
    record_count = 0
    try:
        with os.fdopen(file_descriptor, "wb") as export_file, Session() as session:
            for row in session.execute(statement).mappings():
                export_file.write(orjson.dumps(dict(row), option=orjson.OPT_SORT_KEYS))
                export_file.write(b"\n")
                record_count += 1
            export_file.flush()
            os.fsync(export_file.fileno())

        try:
            os.link(temporary_path, output)
        except FileExistsError as exc:
            raise MaintenanceOperationError(
                f"Audit export already exists: {output}"
            ) from exc
        except OSError as exc:
            raise MaintenanceOperationError(
                f"Unable to publish audit export {output}: {exc}"
            ) from exc
    except MaintenanceOperationError:
        raise
    except (OSError, SQLAlchemyError, TypeError) as exc:
        raise MaintenanceOperationError(
            f"Unable to export eligible audit entries to {output}: {exc}"
        ) from exc
    finally:
        with contextlib.suppress(OSError):
            temporary_path.unlink()

    return AuditExportResult(
        output_path=output,
        selection=selection,
        record_count=record_count,
    )


def purge_audit_entries(
    archive_path: str | Path,
    selection: AuditSelection,
    *,
    expected_count: int | None = None,
) -> AuditPurgeResult:
    export_result = export_audit_entries(archive_path, selection)
    if expected_count is not None and export_result.record_count != expected_count:
        raise MaintenanceOperationError(
            "Eligible audit entries changed after confirmation. "
            f"Expected {expected_count}, archived {export_result.record_count}; "
            f"nothing was deleted and the archive remains at {export_result.output_path}."
        )

    from include.config.validation import AuditRetentionPolicy
    from include.database.models.operations import AuditEntry
    from include.database.session import Session

    policy = AuditRetentionPolicy.from_config()
    table = AuditEntry.__table__
    deleted_count = 0
    pending_ids: list[str] = []
    try:
        with export_result.output_path.open("rb") as archive_file:
            for line in archive_file:
                entry = orjson.loads(line)
                entry_id = entry.get("id") if isinstance(entry, dict) else None
                if not isinstance(entry_id, str):
                    raise MaintenanceOperationError(
                        f"Audit archive contains an invalid entry ID: {archive_path}"
                    )
                pending_ids.append(entry_id)
                if len(pending_ids) == policy.batch_size:
                    deleted_count += _delete_audit_batch(
                        Session,
                        table,
                        selection,
                        pending_ids,
                    )
                    pending_ids.clear()

            if pending_ids:
                deleted_count += _delete_audit_batch(
                    Session,
                    table,
                    selection,
                    pending_ids,
                )
    except MaintenanceOperationError as exc:
        raise MaintenanceOperationError(
            "Audit purge stopped after deleting "
            f"{deleted_count} of {export_result.record_count} archived entries. "
            f"The complete archive remains at {export_result.output_path}. {exc}"
        ) from exc
    except (OSError, orjson.JSONDecodeError, SQLAlchemyError) as exc:
        raise MaintenanceOperationError(
            "Audit purge stopped after deleting "
            f"{deleted_count} of {export_result.record_count} archived entries. "
            f"The complete archive remains at {export_result.output_path}: {exc}"
        ) from exc

    return AuditPurgeResult(
        archive_path=export_result.output_path,
        selection=selection,
        archived_count=export_result.record_count,
        deleted_count=deleted_count,
    )


def _selection_conditions(
    table: Table,
    selection: AuditSelection,
) -> tuple[ColumnElement[bool], ...]:
    conditions = [table.c.logged_time < selection.cutoff]
    for column_name, values in (
        ("action", selection.actions),
        ("username", selection.usernames),
        ("target", selection.targets),
        ("result", selection.results),
        ("remote_address", selection.remote_addresses),
    ):
        if values:
            conditions.append(table.c[column_name].in_(values))
    return tuple(conditions)


def _delete_audit_batch(
    session_factory: sessionmaker,
    table: Table,
    selection: AuditSelection,
    entry_ids: list[str],
) -> int:
    with session_factory.begin() as session:
        result = session.execute(
            delete(table).where(
                table.c.id.in_(entry_ids),
                *_selection_conditions(table, selection),
            )
        )
    return int(result.rowcount or 0)
