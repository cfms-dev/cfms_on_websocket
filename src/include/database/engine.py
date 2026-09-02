from collections.abc import Mapping
from pathlib import Path
from typing import Any

from sqlalchemy import URL, Engine, create_engine, event

from include.config import paths
from include.config.constants import DEFAULT_TOKEN_EXPIRY_SECONDS

SUPPORTED_DB_TYPES = {
    "mysql": "mysql+mysqlconnector",
    "postgresql": "postgresql+psycopg2",
    "sqlite": "sqlite",
}


def database_url(database_config: Mapping[str, Any]) -> URL:
    db_type = database_config["type"]
    drivername = SUPPORTED_DB_TYPES.get(db_type)
    if drivername is None:
        raise ValueError(f"Unsupported database type: {db_type}")

    if db_type == "sqlite":
        database_path = Path(database_config["file"])
        if database_path != Path(":memory:") and not database_path.is_absolute():
            database_path = paths.EXECUTEABLE_ABSPATH / database_path
        return URL.create(drivername, database=str(database_path))

    query = {}
    if db_type == "mysql":
        query["charset"] = database_config["charset"]
    return URL.create(
        drivername=drivername,
        username=database_config["username"],
        password=database_config["password"],
        host=database_config["host"],
        port=database_config["port"],
        database=database_config["name"],
        query=query,
    )


def create_database_engine(
    database_config: Mapping[str, Any],
    *,
    echo: bool = False,
) -> Engine:
    url = database_url(database_config)
    if url.get_backend_name() == "sqlite":
        engine = create_engine(
            url,
            connect_args={"timeout": 30},
            echo=echo,
        )

        @event.listens_for(engine, "connect")
        def _configure_sqlite(dbapi_connection, _connection_record) -> None:
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.execute("PRAGMA busy_timeout=30000")
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

        return engine

    return create_engine(
        url,
        pool_recycle=DEFAULT_TOKEN_EXPIRY_SECONDS,
        echo=echo,
    )
