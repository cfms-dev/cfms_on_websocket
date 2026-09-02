from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.script import ScriptDirectory
from sqlalchemy import Engine, MetaData, inspect

from alembic import command
from include.config.paths import EXECUTABLE_ABSPATH


def initialize_database_schema(engine: Engine, metadata: MetaData) -> None:
    with engine.begin() as connection:
        application_tables = {
            table_name
            for table_name in inspect(connection).get_table_names()
            if table_name != "alembic_version"
        }
        metadata.create_all(connection)

        current_heads = MigrationContext.configure(connection).get_current_heads()
        if application_tables or current_heads:
            return

        config = Config(EXECUTABLE_ABSPATH / "alembic.ini")
        config.attributes["connection"] = connection
        scripts = ScriptDirectory.from_config(config)
        target_heads = tuple(scripts.get_heads())
        if len(target_heads) != 1:
            raise RuntimeError("The release must contain exactly one Alembic head")
        command.stamp(config, target_heads[0])
