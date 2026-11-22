import logging
import subprocess
import sys
from io import StringIO
from pathlib import Path

import pytest
from alembic.config import Config
from alembic.migration import MigrationContext
from alembic.runtime.environment import EnvironmentContext
from alembic.script import ScriptDirectory
from sqlalchemy import inspect
from tomlkit import dumps, parse

import include.database.models  # noqa: F401
from alembic import command
from include.config import settings
from include.database import engine as engine_module
from include.database.session import Base

_SOURCE_ROOT = Path(__file__).resolve().parents[3] / "src"


@pytest.mark.component
def test_migrations_preserve_existing_application_loggers(sqlite_engine_factory):
    logger = logging.getLogger("include.database.migrations.probe")
    assert not logger.disabled
    config = Config(_SOURCE_ROOT / "alembic.ini")
    with sqlite_engine_factory().begin() as connection:
        config.attributes["connection"] = connection
        command.stamp(config, "head")
    assert not logger.disabled


@pytest.mark.integration
@pytest.mark.parametrize("absolute_path", [False, True])
def test_alembic_reads_config_toml_from_outside_server_root(
    tmp_path, absolute_path, sqlite_engine_factory
):
    server_root = tmp_path / "server"
    server_root.mkdir()
    database_path = server_root / "configured.db"
    document = parse((_SOURCE_ROOT / "config.toml.sample").read_text(encoding="utf-8"))
    document["database"]["file"] = (
        str(database_path) if absolute_path else "configured.db"
    )
    (server_root / "config.toml").write_text(dumps(document), encoding="utf-8")
    (server_root / "init").touch()

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import sys; from pathlib import Path; "
                "from include.config import paths; "
                "paths.EXECUTABLE_ABSPATH = Path(sys.argv[1]); "
                "from alembic.config import Config; from alembic import command; "
                "command.stamp(Config(sys.argv[2]), 'head')"
            ),
            str(server_root),
            str(_SOURCE_ROOT / "alembic.ini"),
        ],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )

    assert result.returncode == 0, result.stderr
    assert database_path.is_file()
    assert not (tmp_path / "app.db").exists()
    assert not (server_root / "app.db").exists()
    engine = sqlite_engine_factory(database_path)
    with engine.connect() as connection:
        assert MigrationContext.configure(connection).get_current_revision() == (
            ScriptDirectory.from_config(
                Config(_SOURCE_ROOT / "alembic.ini")
            ).get_current_head()
        )


@pytest.mark.component
@pytest.mark.parametrize("database_type", ["sqlite", "mysql", "postgresql"])
def test_offline_migrations_use_configured_dialect(monkeypatch, database_type):
    monkeypatch.setattr(
        settings,
        "global_config",
        {
            "database": {
                "type": database_type,
                "file": "configured.db",
                "host": "database.example",
                "port": 3306 if database_type == "mysql" else 5432,
                "username": "cfms",
                "password": "secret%@/:value",
                "name": "configured_database",
                "charset": "utf8mb4",
            }
        },
    )
    config = Config(_SOURCE_ROOT / "alembic.ini", output_buffer=StringIO())
    scripts = ScriptDirectory.from_config(config)
    dialects = []

    def record_dialect(revision, migration_context):
        dialects.append(migration_context.dialect.name)
        return []

    with EnvironmentContext(config, scripts, as_sql=True, fn=record_dialect):
        scripts.run_env()

    assert dialects == [database_type]


@pytest.mark.component
@pytest.mark.parametrize(
    ("database_type", "drivername", "port"),
    [
        ("mysql", "mysql+mysqlconnector", 3306),
        ("postgresql", "postgresql+psycopg2", 5432),
    ],
)
def test_online_migrations_use_configured_external_database(
    monkeypatch, tmp_path, database_type, drivername, port
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        settings,
        "global_config",
        {
            "database": {
                "type": database_type,
                "host": "database.example",
                "port": port,
                "username": "cfms",
                "password": "secret%@/:value",
                "name": "configured_database",
                "charset": "utf8mb4",
            }
        },
    )
    urls = []

    def unavailable_database(url, **options):
        urls.append(url)
        raise ConnectionError("configured database is unavailable")

    monkeypatch.setattr(engine_module, "create_engine", unavailable_database)

    with pytest.raises(ConnectionError, match="configured database is unavailable"):
        command.current(Config(_SOURCE_ROOT / "alembic.ini"))

    assert len(urls) == 1
    url = urls[0]
    assert url.drivername == drivername
    assert url.host == "database.example"
    assert url.port == port
    assert url.username == "cfms"
    assert url.password == "secret%@/:value"
    assert url.database == "configured_database"
    assert dict(url.query) == (
        {"charset": "utf8mb4"} if database_type == "mysql" else {}
    )
    assert not (tmp_path / "app.db").exists()


@pytest.mark.component
def test_online_migrations_round_trip_the_configured_database(
    monkeypatch, tmp_path, sqlite_engine_factory
):
    database_path = tmp_path / "configured.db"
    database = {"type": "sqlite", "file": str(database_path)}
    monkeypatch.setattr(settings, "global_config", {"database": database})
    config = Config(_SOURCE_ROOT / "alembic.ini")
    engine = sqlite_engine_factory(database_path)
    Base.metadata.create_all(engine)
    command.stamp(config, "head")
    command.downgrade(config, "03197fed3401")
    assert "options" not in inspect(engine).get_table_names()

    command.upgrade(config, "head")

    assert "options" in inspect(engine).get_table_names()
    with engine.connect() as connection:
        assert MigrationContext.configure(connection).get_current_revision() == (
            ScriptDirectory.from_config(config).get_current_head()
        )


@pytest.mark.component
def test_supplied_connection_takes_priority_over_runtime_configuration(
    monkeypatch, sqlite_engine_factory
):
    monkeypatch.setattr(settings, "global_config", {"database": {"type": "invalid"}})
    config = Config(_SOURCE_ROOT / "alembic.ini")
    scripts = ScriptDirectory.from_config(config)
    engine = sqlite_engine_factory()
    with engine.begin() as connection:
        config.attributes["connection"] = connection
        command.stamp(config, "head")
        assert MigrationContext.configure(connection).get_current_revision() == (
            scripts.get_current_head()
        )
        assert not connection.closed
