import pytest
from sqlalchemy.exc import TimeoutError as SQLAlchemyTimeoutError
from sqlalchemy.pool import SingletonThreadPool

from include.config.constants import DEFAULT_TOKEN_EXPIRY_SECONDS
from include.database import engine as engine_module
from include.database.engine import create_database_engine, database_url


def test_mysql_database_url_keeps_password_out_of_rendered_value() -> None:
    url = database_url(
        {
            "type": "mysql",
            "host": "database.example",
            "port": 3306,
            "username": "cfms",
            "password": "secret@/value",
            "name": "app_db",
            "charset": "utf8mb4",
        }
    )

    assert url.drivername == "mysql+mysqlconnector"
    assert url.password == "secret@/value"
    assert url.query == {"charset": "utf8mb4"}
    assert "secret" not in str(url)


def test_postgresql_database_url_uses_packaged_driver() -> None:
    url = database_url(
        {
            "type": "postgresql",
            "host": "database.example",
            "port": 5432,
            "username": "cfms",
            "password": "secret@/value",
            "name": "app_db",
        }
    )

    assert url.drivername == "postgresql+psycopg2"
    assert url.password == "secret@/value"
    assert url.query == {}
    assert "secret" not in str(url)


def test_sqlite_engine_applies_runtime_pragmas(tmp_path) -> None:
    engine = create_database_engine(
        {"type": "sqlite", "file": str(tmp_path / "runtime.db")}
    )

    with engine.connect() as connection:
        assert connection.exec_driver_sql("PRAGMA foreign_keys").scalar_one() == 1
        assert connection.exec_driver_sql("PRAGMA busy_timeout").scalar_one() == 30000
        assert connection.exec_driver_sql("PRAGMA journal_mode").scalar_one() == "wal"
        assert connection.exec_driver_sql("PRAGMA synchronous").scalar_one() == 1

    engine.dispose()


def test_file_sqlite_engine_applies_configured_queue_pool_limits(tmp_path) -> None:
    engine = create_database_engine(
        {
            "type": "sqlite",
            "file": str(tmp_path / "pooled.db"),
            "pool": {"size": 1, "max_overflow": 1, "timeout_seconds": 0},
        }
    )

    try:
        assert engine.pool.size() == 1
        assert engine.pool.timeout() == 0
        with engine.connect(), engine.connect():
            with pytest.raises(SQLAlchemyTimeoutError, match="QueuePool limit"):
                engine.connect()
    finally:
        engine.dispose()


def test_in_memory_sqlite_keeps_its_dedicated_pool() -> None:
    engine = create_database_engine(
        {
            "type": "sqlite",
            "file": ":memory:",
            "pool": {"size": 1, "max_overflow": 0, "timeout_seconds": 0},
        }
    )

    try:
        assert isinstance(engine.pool, SingletonThreadPool)
    finally:
        engine.dispose()


def test_external_database_keeps_recycle_and_applies_pool_settings(monkeypatch) -> None:
    created = []
    expected_engine = object()

    def capture_create_engine(url, **options):
        created.append((url, options))
        return expected_engine

    monkeypatch.setattr(engine_module, "create_engine", capture_create_engine)

    result = engine_module.create_database_engine(
        {
            "type": "postgresql",
            "host": "database.example",
            "port": 5432,
            "username": "cfms",
            "password": "secret",
            "name": "app_db",
            "pool": {"size": 3, "max_overflow": 4, "timeout_seconds": 0.5},
        },
        echo=True,
    )

    assert result is expected_engine
    assert len(created) == 1
    _, options = created[0]
    assert options == {
        "pool_recycle": DEFAULT_TOKEN_EXPIRY_SECONDS,
        "echo": True,
        "pool_size": 3,
        "max_overflow": 4,
        "pool_timeout": 0.5,
    }


def test_database_url_rejects_unknown_database_type() -> None:
    with pytest.raises(ValueError, match="Unsupported database type: oracle"):
        database_url({"type": "oracle"})
