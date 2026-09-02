from dataclasses import dataclass

from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from alembic.script.revision import ResolutionError
from sqlalchemy import Engine, MetaData, inspect

from alembic import command
from include.config.paths import EXECUTABLE_ABSPATH


class DatabaseSchemaError(RuntimeError):
    pass


@dataclass(frozen=True, slots=True)
class SchemaUpgradeResult:
    previous_revision: str | None
    current_revision: str
    bootstrapped: bool


def _alembic_config(connection) -> tuple[Config, ScriptDirectory]:
    config_path = EXECUTABLE_ABSPATH / "alembic.ini"
    config = Config(config_path)
    config.attributes["connection"] = connection
    return config, ScriptDirectory.from_config(config)


def _application_schema(connection) -> dict[str, set[str]]:
    inspector = inspect(connection)
    return {
        table_name: {
            str(column["name"]) for column in inspector.get_columns(table_name)
        }
        for table_name in inspector.get_table_names()
        if table_name != "alembic_version"
    }


def _current_revision(connection) -> str | None:
    heads = MigrationContext.configure(connection).get_current_heads()
    if len(heads) > 1:
        raise DatabaseSchemaError(
            "Database has multiple Alembic heads: " + ", ".join(heads)
        )
    return heads[0] if heads else None


def upgrade_database_schema(
    engine: Engine,
    metadata: MetaData,
) -> SchemaUpgradeResult:
    if engine.dialect.name not in {"sqlite", "mysql"}:
        raise DatabaseSchemaError(
            "Schema upgrades support only SQLite and MySQL; "
            f"configured dialect is {engine.dialect.name!r}"
        )

    with engine.begin() as connection:
        config, scripts = _alembic_config(connection)
        target_heads = tuple(scripts.get_heads())
        if len(target_heads) != 1:
            raise DatabaseSchemaError(
                "The release must contain exactly one Alembic head"
            )
        target_revision = target_heads[0]
        previous_revision = _current_revision(connection)
        schema = _application_schema(connection)
        bootstrapped = False

        if previous_revision is None:
            if schema:
                raise DatabaseSchemaError(
                    "Non-empty unversioned databases are not supported; refusing "
                    "to guess a migration revision"
                )
            metadata.create_all(connection)
            command.stamp(config, target_revision)
            bootstrapped = True
        else:
            try:
                scripts.get_revision(previous_revision)
            except ResolutionError as exc:
                raise DatabaseSchemaError(
                    f"Database revision {previous_revision!r} is not present in "
                    "this release"
                ) from exc
            if previous_revision != target_revision:
                command.upgrade(config, target_revision)

        current_revision = _current_revision(connection)
        if current_revision != target_revision:
            raise DatabaseSchemaError(
                f"Database migration ended at {current_revision!r}; expected "
                f"{target_revision!r}"
            )

    return SchemaUpgradeResult(
        previous_revision=previous_revision,
        current_revision=target_revision,
        bootstrapped=bootstrapped,
    )
