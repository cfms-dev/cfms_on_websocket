from concurrent.futures import ThreadPoolExecutor

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, event
from sqlalchemy.orm import sessionmaker

from include.database.models.operations import SystemStateEntry
from include.database.system_states import (
    create_system_state,
    delete_system_state,
    read_system_state,
    update_system_state,
)


@pytest.fixture
def state_database(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'system-states.db'}",
        connect_args={"timeout": 30},
    )

    @event.listens_for(engine, "connect")
    def _configure_sqlite(dbapi_connection, _connection_record) -> None:
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL")
        cursor.execute("PRAGMA busy_timeout=30000")
        cursor.close()

    SystemStateEntry.__table__.create(engine)
    sessions = sessionmaker(bind=engine)
    yield sessions
    engine.dispose()


def test_state_lifecycle_uses_revision_compare_and_swap(state_database) -> None:
    with state_database.begin() as session:
        assert create_system_state(
            session,
            "sample_ext",
            "worker.position",
            schema_version=1,
            payload={"position": 4},
        )
        assert not create_system_state(
            session,
            "sample_ext",
            "worker.position",
            schema_version=1,
            payload={"position": 5},
        )

    with state_database.begin() as session:
        state = read_system_state(session, "sample_ext", "worker.position")
        assert state is not None
        assert state.revision == 1
        assert state.payload == {"position": 4}
        assert not update_system_state(
            session,
            "sample_ext",
            "worker.position",
            expected_revision=2,
            schema_version=1,
            payload={"position": 6},
        )
        assert update_system_state(
            session,
            "sample_ext",
            "worker.position",
            expected_revision=1,
            schema_version=2,
            payload={"position": 6},
        )

    with state_database.begin() as session:
        state = read_system_state(session, "sample_ext", "worker.position")
        assert state is not None
        assert state.schema_version == 2
        assert state.revision == 2
        assert not delete_system_state(
            session,
            "sample_ext",
            "worker.position",
            expected_revision=1,
        )
        assert delete_system_state(
            session,
            "sample_ext",
            "worker.position",
            expected_revision=2,
        )

    with state_database() as session:
        assert read_system_state(session, "sample_ext", "worker.position") is None


def test_state_payloads_are_detached_copies(state_database) -> None:
    payload = {"items": [{"value": 1}]}
    with state_database.begin() as session:
        assert create_system_state(
            session,
            "sample_ext",
            "snapshot",
            schema_version=1,
            payload=payload,
        )
    payload["items"][0]["value"] = 2

    with state_database() as session:
        first = read_system_state(session, "sample_ext", "snapshot")
        assert first is not None
        assert first.payload == {"items": [{"value": 1}]}
        first.payload["items"][0]["value"] = 3
        same_session = read_system_state(session, "sample_ext", "snapshot")
        assert same_session is not None
        assert same_session.payload == {"items": [{"value": 1}]}

    with state_database() as session:
        second = read_system_state(session, "sample_ext", "snapshot")
        assert second is not None
        assert second.payload == {"items": [{"value": 1}]}


def test_state_write_participates_in_caller_transaction(state_database) -> None:
    with state_database() as session:
        assert create_system_state(
            session,
            "sample_ext",
            "rolled_back",
            schema_version=1,
            payload={},
        )
        session.rollback()

    with state_database() as session:
        assert read_system_state(session, "sample_ext", "rolled_back") is None


def test_concurrent_create_has_one_winner(state_database) -> None:
    def create(index: int) -> bool:
        with state_database.begin() as session:
            return create_system_state(
                session,
                "sample_ext",
                "singleton",
                schema_version=1,
                payload={"winner": index},
            )

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(create, range(16)))

    assert sum(results) == 1
    with state_database() as session:
        state = read_system_state(session, "sample_ext", "singleton")
        assert state is not None
        assert state.payload["winner"] in range(16)


@pytest.mark.parametrize(
    ("owner", "state_key"),
    [
        ("Invalid", "state"),
        ("sample_ext", "Invalid State"),
        ("x" * 256, "state"),
        ("sample_ext", "x" * 129),
    ],
)
def test_state_identity_is_validated(state_database, owner, state_key) -> None:
    with state_database.begin() as session:
        with pytest.raises(ValidationError):
            create_system_state(
                session,
                owner,
                state_key,
                schema_version=1,
                payload={},
            )


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {"value": object()},
        {1: "value"},
        {"value": float("inf")},
        {"value": (1, 2)},
    ],
)
def test_state_payload_must_be_a_json_object(state_database, payload) -> None:
    with state_database.begin() as session:
        with pytest.raises(ValidationError):
            create_system_state(
                session,
                "sample_ext",
                "payload",
                schema_version=1,
                payload=payload,
            )
