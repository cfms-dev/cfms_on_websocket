import copy
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

import tomlkit
from alembic.config import Config
from alembic.script import ScriptDirectory
from sqlalchemy.exc import SQLAlchemyError
from tomlkit.exceptions import TOMLKitError

from include.config.validation import ConfigValidationError, parse_config_document
from include.database.engine import create_database_engine, database_url
from maintenance.database_migration import (
    DatabaseMigrationError,
)
from maintenance.database_migration import (
    migrate_database as execute_database_migration,
)
from maintenance.operations.config import write_config_atomically
from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.runtime import enter_server_root, load_database_models

if TYPE_CHECKING:
    from rich.progress import Progress


@dataclass(frozen=True, slots=True)
class DatabaseMigrationResult:
    source_dialect: str
    target_dialect: str
    table_count: int
    row_count: int
    elapsed_seconds: float
    target_config_path: Path
    config_backup_path: Path | None


def migrate_database(
    target_config_path: str | Path,
    *,
    activate: bool = False,
    progress: Progress | None = None,
) -> DatabaseMigrationResult:
    workdir = enter_server_root()
    resolved_target_path, target_document, target_database = (
        _load_target_database_config(workdir, target_config_path)
    )
    load_database_models()

    from include.database.session import Base
    from include.database.session import engine as source_engine

    target_engine = None
    try:
        target_engine = create_database_engine(target_database)
        alembic_config = Config(workdir / "alembic.ini")
        script_directory = ScriptDirectory.from_config(alembic_config)
        result = execute_database_migration(
            source_engine,
            target_engine,
            Base.metadata,
            script_directory,
            progress=progress,
        )
    except (DatabaseMigrationError, ImportError, OSError, SQLAlchemyError) as exc:
        raise MaintenanceOperationError(f"Database migration failed: {exc}") from exc
    finally:
        if target_engine is not None:
            target_engine.dispose()

    config_backup_path = None
    if activate:
        try:
            config_backup_path = _activate_target_database(
                workdir / "config.toml",
                target_document,
            )
        except MaintenanceOperationError as exc:
            raise MaintenanceOperationError(
                "Database data migration and verification succeeded, but target "
                f"activation failed: {exc}. The target data remains usable and "
                "the current configuration was not replaced."
            ) from exc

    return DatabaseMigrationResult(
        source_dialect=result.source_dialect,
        target_dialect=result.target_dialect,
        table_count=len(result.tables),
        row_count=result.row_count,
        elapsed_seconds=result.elapsed_seconds,
        target_config_path=resolved_target_path,
        config_backup_path=config_backup_path,
    )


def _load_target_database_config(
    workdir: Path,
    target_config_path: str | Path,
) -> tuple[Path, tomlkit.TOMLDocument, Mapping[str, Any]]:
    candidate = Path(target_config_path)
    if not candidate.is_absolute():
        candidate = workdir / candidate
    resolved = candidate.resolve()
    if resolved == (workdir / "config.toml").resolve():
        raise MaintenanceOperationError(
            "Target database configuration must be different from config.toml"
        )
    if not resolved.is_file():
        raise MaintenanceOperationError(
            f"Target database configuration not found: {resolved}"
        )

    try:
        document = tomlkit.parse(resolved.read_text(encoding="utf-8"))
    except (OSError, TOMLKitError) as exc:
        raise MaintenanceOperationError(
            f"Unable to read target database configuration: {exc}"
        ) from exc
    database = document.get("database")
    if not isinstance(database, Mapping):
        raise MaintenanceOperationError(
            "Target configuration must contain a [database] table"
        )
    _validate_target_database(database)
    try:
        database_url(database)
    except (KeyError, TypeError, ValueError) as exc:
        raise MaintenanceOperationError(
            f"Target database configuration is invalid: {exc}"
        ) from exc
    return resolved, document, database


def _validate_target_database(database: Mapping[str, Any]) -> None:
    db_type = database.get("type")
    if db_type not in {"mysql", "sqlite"}:
        raise MaintenanceOperationError(
            "Target database type must be either 'sqlite' or 'mysql'"
        )
    if db_type == "sqlite":
        database_file = database.get("file")
        if not isinstance(database_file, str) or not database_file.strip():
            raise MaintenanceOperationError(
                "Target SQLite configuration requires a non-empty database.file"
            )
        if database_file == ":memory:":
            raise MaintenanceOperationError(
                "An in-memory SQLite database cannot be used as a migration target"
            )
        return

    for field_name in ("host", "username", "name"):
        value = database.get(field_name)
        if not isinstance(value, str) or not value.strip():
            raise MaintenanceOperationError(
                f"Target MySQL configuration requires database.{field_name}"
            )
    password = database.get("password")
    if not isinstance(password, str):
        raise MaintenanceOperationError(
            "Target MySQL configuration requires string database.password"
        )
    port = database.get("port")
    if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
        raise MaintenanceOperationError(
            "Target MySQL database.port must be an integer from 1 to 65535"
        )
    if database.get("charset") != "utf8mb4":
        raise MaintenanceOperationError(
            "Target MySQL database.charset must be 'utf8mb4'"
        )


def _activate_target_database(
    config_path: Path,
    target_document: tomlkit.TOMLDocument,
) -> Path:
    try:
        current_source = config_path.read_text(encoding="utf-8")
        current_document = tomlkit.parse(current_source)
        current_document["database"] = copy.deepcopy(target_document["database"])
        rendered = tomlkit.dumps(current_document)
        parse_config_document(rendered)
    except (OSError, TOMLKitError, ConfigValidationError) as exc:
        raise MaintenanceOperationError(
            f"Unable to prepare database configuration activation: {exc}"
        ) from exc
    return write_config_atomically(config_path, current_source, rendered)
