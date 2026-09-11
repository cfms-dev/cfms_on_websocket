import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.script.revision import RangeNotAncestorError, ResolutionError
from alembic.util.exc import CommandError
from sqlalchemy.exc import SQLAlchemyError

from alembic import command
from include.config.validation import parse_config_document
from include.database.engine import create_database_engine
from maintenance.operations.deployment.models import _Release
from maintenance.operations.exceptions import MaintenanceOperationError


@contextmanager
def _suppress_bytecode_writes() -> Iterator[None]:
    previous = sys.dont_write_bytecode
    sys.dont_write_bytecode = True
    try:
        yield
    finally:
        sys.dont_write_bytecode = previous


def _alembic(release: _Release, connection=None) -> tuple[Config, ScriptDirectory, str]:
    config = Config(str(release.root / "src" / "alembic.ini"))
    config.set_main_option("script_location", str(release.root / "src" / "alembic"))
    if connection is not None:
        config.attributes["connection"] = connection
    scripts = ScriptDirectory.from_config(config)
    heads = tuple(scripts.get_heads())
    if len(heads) != 1:
        raise MaintenanceOperationError(
            "A release must contain exactly one Alembic head"
        )
    return config, scripts, heads[0]


def _database_engine(project_root: Path):
    config_path = project_root / "src" / "config.toml"
    try:
        document = parse_config_document(config_path.read_text(encoding="utf-8"))
        database = dict(document["database"])
        if database.get("type") == "sqlite":
            database_path = Path(database["file"])
            if database_path != Path(":memory:") and not database_path.is_absolute():
                database["file"] = str(project_root / "src" / database_path)
        return create_database_engine(database)
    except Exception as exc:
        raise MaintenanceOperationError(
            f"Unable to open the configured database: {exc}"
        ) from exc


def _current_revision(connection) -> str | None:
    heads = tuple(MigrationContext.configure(connection).get_current_heads())
    if len(heads) > 1:
        raise MaintenanceOperationError(
            "Database has multiple Alembic heads: " + ", ".join(heads)
        )
    return heads[0] if heads else None


def _is_ancestor(scripts: ScriptDirectory, lower: str, upper: str) -> bool:
    if lower == upper:
        return True
    try:
        revisions = tuple(scripts.iterate_revisions(upper, lower, inclusive=True))
        identifiers = {revision.revision for revision in revisions}
        return lower in identifiers and upper in identifiers
    except RangeNotAncestorError, ResolutionError:
        return False


def _require_source_revision(connection, source_head: str) -> None:
    current = _current_revision(connection)
    if current is None:
        raise MaintenanceOperationError(
            "Database has no Alembic revision; verify that its schema matches "
            f"the active release, then stamp it at {source_head} before switching "
            "releases"
        )
    if current != source_head:
        raise MaintenanceOperationError(
            f"Database revision is {current}; active release expects {source_head}"
        )


def _preflight_upgrade_database(
    project_root: Path,
    source: _Release,
    target: _Release,
) -> None:
    engine = _database_engine(project_root)
    try:
        with _suppress_bytecode_writes(), engine.connect() as connection:
            _, target_scripts, target_head = _alembic(target)
            _, _, source_head = _alembic(source)
            if not _is_ancestor(target_scripts, source_head, target_head):
                raise MaintenanceOperationError(
                    f"Target Alembic head {target_head} does not descend from {source_head}"
                )
            _require_source_revision(connection, source_head)
    except (CommandError, OSError, SQLAlchemyError) as exc:
        raise MaintenanceOperationError(
            f"Database upgrade preflight failed: {exc}"
        ) from exc
    finally:
        engine.dispose()


def _preflight_downgrade_database(
    project_root: Path,
    source: _Release,
    target: _Release,
) -> None:
    engine = _database_engine(project_root)
    try:
        with _suppress_bytecode_writes(), engine.connect() as connection:
            _, source_scripts, source_head = _alembic(source)
            _, _, target_head = _alembic(target)
            if not _is_ancestor(source_scripts, target_head, source_head):
                raise MaintenanceOperationError(
                    f"Target Alembic head {target_head} is not reachable from {source_head}"
                )
            _require_source_revision(connection, source_head)
    except (CommandError, OSError, SQLAlchemyError) as exc:
        raise MaintenanceOperationError(
            f"Database downgrade preflight failed: {exc}"
        ) from exc
    finally:
        engine.dispose()


def _upgrade_database(project_root: Path, source: _Release, target: _Release) -> None:
    engine = _database_engine(project_root)
    try:
        with _suppress_bytecode_writes(), engine.begin() as connection:
            target_config, target_scripts, target_head = _alembic(target, connection)
            _, _, source_head = _alembic(source)
            if not _is_ancestor(target_scripts, source_head, target_head):
                raise MaintenanceOperationError(
                    f"Target Alembic head {target_head} does not descend from {source_head}"
                )
            _require_source_revision(connection, source_head)
            if source_head != target_head:
                command.upgrade(target_config, target_head)
            if _current_revision(connection) != target_head:
                raise MaintenanceOperationError(
                    f"Database did not reach target revision {target_head}"
                )
    except (CommandError, OSError, SQLAlchemyError) as exc:
        raise MaintenanceOperationError(f"Database upgrade failed: {exc}") from exc
    finally:
        engine.dispose()


def _downgrade_database(project_root: Path, source: _Release, target: _Release) -> None:
    engine = _database_engine(project_root)
    try:
        with _suppress_bytecode_writes(), engine.begin() as connection:
            source_config, source_scripts, source_head = _alembic(source, connection)
            _, _, target_head = _alembic(target)
            if not _is_ancestor(source_scripts, target_head, source_head):
                raise MaintenanceOperationError(
                    f"Target Alembic head {target_head} is not reachable from {source_head}"
                )
            _require_source_revision(connection, source_head)
            if source_head != target_head:
                command.downgrade(source_config, target_head)
            if _current_revision(connection) != target_head:
                raise MaintenanceOperationError(
                    f"Database did not reach target revision {target_head}"
                )
    except (CommandError, OSError, SQLAlchemyError) as exc:
        raise MaintenanceOperationError(f"Database downgrade failed: {exc}") from exc
    finally:
        engine.dispose()
