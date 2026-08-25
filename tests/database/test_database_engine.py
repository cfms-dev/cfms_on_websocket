import pytest

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


def test_database_url_rejects_unknown_database_type() -> None:
    with pytest.raises(ValueError, match="Unsupported database type: oracle"):
        database_url({"type": "oracle"})
