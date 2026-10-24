from concurrent.futures import ThreadPoolExecutor
from threading import Barrier

import pytest
from sqlalchemy.orm import sessionmaker

from include.database.models.operations import SystemStateEntry
from include.database.system_states import (
    create_system_state,
    delete_system_state,
    read_system_state,
    update_system_state,
)

pytestmark = pytest.mark.integration


@pytest.fixture
def mysql_state_sessions(mysql_pure_engine):
    table = SystemStateEntry.__table__
    table.drop(mysql_pure_engine, checkfirst=True)
    try:
        table.create(mysql_pure_engine)
        yield sessionmaker(bind=mysql_pure_engine)
    finally:
        table.drop(mysql_pure_engine, checkfirst=True)


def test_mysql_create_state_persists_first_revision(mysql_state_sessions):
    with mysql_state_sessions.begin() as session:
        created = create_system_state(
            session, "sample_ext", "position", schema_version=2, payload={"position": 4}
        )

    assert created is True
    with mysql_state_sessions() as session:
        state = read_system_state(session, "sample_ext", "position")
        assert state is not None
        assert state.schema_version == 2
        assert state.revision == 1
        assert state.payload == {"position": 4}


def test_mysql_duplicate_create_preserves_existing_state(mysql_state_sessions):
    with mysql_state_sessions.begin() as session:
        session.add(
            SystemStateEntry(
                owner="sample_ext",
                state_key="position",
                schema_version=1,
                revision=3,
                payload={"position": 4},
                updated_at=1.0,
            )
        )
    with mysql_state_sessions.begin() as session:
        created = create_system_state(
            session, "sample_ext", "position", schema_version=2, payload={"position": 5}
        )

    assert created is False
    with mysql_state_sessions() as session:
        state = read_system_state(session, "sample_ext", "position")
        assert state is not None
        assert state.schema_version == 1
        assert state.revision == 3
        assert state.payload == {"position": 4}
        assert state.updated_at == 1.0


def test_mysql_state_creation_participates_in_caller_rollback(mysql_state_sessions):
    with mysql_state_sessions() as session:
        created = create_system_state(
            session, "sample_ext", "rolled_back", schema_version=1, payload={}
        )
        assert created is True
        assert read_system_state(session, "sample_ext", "rolled_back") is not None
        session.rollback()

    with mysql_state_sessions() as session:
        assert read_system_state(session, "sample_ext", "rolled_back") is None


def test_mysql_concurrent_state_creation_has_one_winner(mysql_state_sessions):
    ready = Barrier(4)

    def create(index):
        with mysql_state_sessions.begin() as session:
            ready.wait(timeout=10)
            return create_system_state(
                session,
                "sample_ext",
                "singleton",
                schema_version=1,
                payload={"winner": index},
            )

    with ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(create, range(4)))

    assert results.count(True) == 1
    assert results.count(False) == 3
    with mysql_state_sessions() as session:
        state = read_system_state(session, "sample_ext", "singleton")
        assert state is not None
        assert state.revision == 1
        assert state.payload == {"winner": results.index(True)}


def test_mysql_state_compare_and_swap_preserves_revisions(mysql_state_sessions):
    with mysql_state_sessions.begin() as session:
        assert create_system_state(
            session, "sample_ext", "position", schema_version=1, payload={"position": 4}
        )
    with mysql_state_sessions.begin() as session:
        assert update_system_state(
            session,
            "sample_ext",
            "position",
            expected_revision=1,
            schema_version=2,
            payload={"position": 6},
        )
        assert not update_system_state(
            session,
            "sample_ext",
            "position",
            expected_revision=1,
            schema_version=2,
            payload={"position": 7},
        )
        assert not delete_system_state(
            session, "sample_ext", "position", expected_revision=1
        )
    with mysql_state_sessions() as session:
        state = read_system_state(session, "sample_ext", "position")
        assert state is not None
        assert state.revision == 2
        assert state.schema_version == 2
        assert state.payload == {"position": 6}
    with mysql_state_sessions.begin() as session:
        assert delete_system_state(
            session, "sample_ext", "position", expected_revision=2
        )
    with mysql_state_sessions() as session:
        assert read_system_state(session, "sample_ext", "position") is None
