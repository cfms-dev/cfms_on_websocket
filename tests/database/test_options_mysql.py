from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy import select
from sqlalchemy.orm import sessionmaker

from include.config.options import (
    SERVER_NAME_OPTION,
    ensure_option_defaults,
    write_options,
)
from include.config.options import (
    read_option as read_resolved_option,
)
from include.database.models import (
    AuditEntry,
    Comment,
    File,
    OptionEntry,
    SystemStateEntry,
    User,
    UserKey,
)
from include.database.options import (
    create_option,
    read_option,
    update_option,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def mysql_option_sessions(isolated_metadata, mysql_pure_engine):
    tables = [
        isolated_metadata.tables[model.__tablename__]
        for model in (
            Comment,
            File,
            UserKey,
            User,
            OptionEntry,
            SystemStateEntry,
            AuditEntry,
        )
    ]
    isolated_metadata.drop_all(mysql_pure_engine, tables=tables, checkfirst=True)
    try:
        isolated_metadata.create_all(mysql_pure_engine, tables=tables)
        yield sessionmaker(bind=mysql_pure_engine)
    finally:
        isolated_metadata.drop_all(mysql_pure_engine, tables=tables, checkfirst=True)


def test_mysql_create_option_persists_first_revision(mysql_option_sessions):
    with mysql_option_sessions.begin() as session:
        created = create_option(
            session,
            "server",
            "name",
            schema_version=1,
            value="MySQL Server",
        )

    assert created is True
    with mysql_option_sessions() as session:
        option = read_option(session, "server", "name")
        assert option is not None
        assert option.schema_version == 1
        assert option.revision == 1
        assert option.value == "MySQL Server"


def test_mysql_duplicate_create_preserves_existing_option(mysql_option_sessions):
    with mysql_option_sessions.begin() as session:
        assert create_option(
            session,
            "server",
            "name",
            schema_version=1,
            value="Original",
        )
    with mysql_option_sessions.begin() as session:
        created = create_option(
            session,
            "server",
            "name",
            schema_version=1,
            value="Duplicate",
        )

    assert created is False
    with mysql_option_sessions() as session:
        option = read_option(session, "server", "name")
        assert option is not None
        assert option.revision == 1
        assert option.value == "Original"


def test_mysql_concurrent_option_creation_has_one_winner(mysql_option_sessions):
    ready = Barrier(4)

    def create(index):
        with mysql_option_sessions.begin() as session:
            ready.wait(timeout=10)
            return create_option(
                session,
                "server",
                "name",
                schema_version=1,
                value=f"winner-{index}",
            )

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(create, range(4)))

    assert results.count(True) == 1
    assert results.count(False) == 3
    with mysql_option_sessions() as session:
        option = read_option(session, "server", "name")
        assert option is not None
        assert option.revision == 1
        assert option.value == f"winner-{results.index(True)}"


def test_mysql_write_options_and_defaults_succeed(mysql_option_sessions):
    with mysql_option_sessions.begin() as session:
        written = write_options(
            session,
            "server",
            {"name": "First MySQL Name"},
            expected_revisions={"name": 0},
            source="maintenance_cli",
        )
        assert written["name"].revision == 1
        assert written["name"].value == "First MySQL Name"

        updated = write_options(
            session,
            "server",
            {"name": "Second MySQL Name"},
            expected_revisions={"name": 1},
            source="maintenance_cli",
        )
        assert updated["name"].revision == 2
        assert updated["name"].value == "Second MySQL Name"

        ensured = ensure_option_defaults(session, "server")
        assert ensured["name"].revision == 2
        assert ensured["name"].value == "Second MySQL Name"

    with mysql_option_sessions() as session:
        resolved = read_resolved_option(session, "server", SERVER_NAME_OPTION)
        assert resolved.revision == 2
        assert resolved.value == "Second MySQL Name"
        assert session.scalar(select(SystemStateEntry.revision)) == 2
        assert len(list(session.scalars(select(AuditEntry)))) == 2
        assert not update_option(
            session,
            "server",
            "name",
            expected_revision=1,
            schema_version=1,
            value="Stale",
        )
