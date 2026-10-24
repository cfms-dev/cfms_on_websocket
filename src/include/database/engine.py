import sqlite3
from pathlib import Path
from typing import Any, cast
lazy from collections.abc import Mapping

from sqlalchemy import URL, Connection, Engine, Select, create_engine, event

from include.config import paths
from include.config.constants import DEFAULT_TOKEN_EXPIRY_SECONDS
from include.config.validation import DatabasePoolPolicy

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
            database_path = paths.EXECUTABLE_ABSPATH / database_path
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
    """Create an engine with backend-specific locking read support.

    SQLite reserves its writer before native FOR UPDATE reads and initial
    SAVEPOINTs. Ordinary reads retain legacy driver transaction behavior;
    sessions continue to own commit and rollback.
    """
    url = database_url(database_config)
    pool_policy = DatabasePoolPolicy.from_config({"database": database_config})
    pool_options = {
        "pool_size": pool_policy.size,
        "max_overflow": pool_policy.max_overflow,
        "pool_timeout": pool_policy.timeout_seconds,
    }
    match url.get_backend_name():
        case "sqlite":
            if url.database == ":memory:":
                pool_options = {}
            engine = create_engine(
                url,
                connect_args={
                    "timeout": 30,
                    "autocommit": sqlite3.LEGACY_TRANSACTION_CONTROL,
                },
                echo=echo,
                **pool_options,
            )

            @event.listens_for(engine, "connect")
            def _configure_sqlite(dbapi_connection, _connection_record) -> None:
                cursor = dbapi_connection.cursor()
                cursor.execute("PRAGMA foreign_keys=ON")
                cursor.execute("PRAGMA busy_timeout=30000")
                cursor.execute("PRAGMA journal_mode=WAL")
                cursor.execute("PRAGMA synchronous=NORMAL")
                cursor.close()

            @event.listens_for(engine, "savepoint")
            def _begin_sqlite_write_transaction(
                connection: Connection, _name: str | None
            ) -> None:
                dbapi_connection = cast(
                    sqlite3.Connection, connection.connection.driver_connection
                )
                if not dbapi_connection.in_transaction:
                    connection.exec_driver_sql("BEGIN IMMEDIATE")

            @event.listens_for(engine, "before_execute")
            def _lock_sqlite_select(
                connection: Connection,
                statement,
                _multiparams,
                _params,
                _execution_options,
            ) -> None:
                # SQLAlchemy 2.1 has no public accessor for native FOR UPDATE intent.
                if (
                    isinstance(statement, Select)
                    and statement._for_update_arg is not None
                ):
                    _begin_sqlite_write_transaction(connection, None)

            return engine

    return create_engine(
        url,
        pool_recycle=DEFAULT_TOKEN_EXPIRY_SECONDS,
        echo=echo,
        **pool_options,
    )
