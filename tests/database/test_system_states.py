from concurrent.futures import ThreadPoolExecutor

import pytest
from pydantic import ValidationError
from sqlalchemy.orm import sessionmaker

from include.database.models.operations import SystemStateEntry
from include.database.system_states import (
    create_system_state,
    delete_system_state,
    read_system_state,
    update_system_state,
)

pytestmark = pytest.mark.component


@pytest.fixture
def state_database(tmp_path, sqlite_engine_factory):
    engine = sqlite_engine_factory(tmp_path / "system-states.db", timeout_seconds=30)

    SystemStateEntry.__table__.create(engine)
    sessions = sessionmaker(bind=engine)
    return sessions


@pytest.fixture
def existing_state(state_database):
    with state_database.begin() as session:
        assert create_system_state(
            session,
            "sample_ext",
            "worker.position",
            schema_version=1,
            payload={"position": 4},
        )
    return state_database


def test_create_state_persists_first_revision(state_database) -> None:
    with state_database.begin() as session:
        created = create_system_state(
            session,
            "sample_ext",
            "worker.position",
            schema_version=1,
            payload={"position": 4},
        )

    assert created is True
    with state_database() as session:
        state = read_system_state(session, "sample_ext", "worker.position")
        assert state is not None
        assert state.schema_version == state.revision == 1
        assert state.payload == {"position": 4}


def test_duplicate_create_preserves_existing_state(existing_state) -> None:
    with existing_state.begin() as session:
        created = create_system_state(
            session,
            "sample_ext",
            "worker.position",
            schema_version=1,
            payload={"position": 5},
        )

    assert created is False
    with existing_state() as session:
        state = read_system_state(session, "sample_ext", "worker.position")
        assert state is not None
        assert state.revision == 1
        assert state.payload == {"position": 4}


@pytest.mark.parametrize(
    ("expected_revision", "applied"),
    [
        pytest.param(1, True, id="matching-revision"),
        pytest.param(2, False, id="mismatched-revision"),
    ],
)
def test_state_update_uses_revision_compare_and_swap(
    existing_state,
    expected_revision,
    applied,
) -> None:
    with existing_state.begin() as session:
        updated = update_system_state(
            session,
            "sample_ext",
            "worker.position",
            expected_revision=expected_revision,
            schema_version=2,
            payload={"position": 6},
        )

    assert updated is applied
    with existing_state() as session:
        state = read_system_state(session, "sample_ext", "worker.position")
        assert state is not None
        assert state.revision == (2 if applied else 1)
        assert state.schema_version == (2 if applied else 1)
        assert state.payload == ({"position": 6} if applied else {"position": 4})


@pytest.mark.parametrize(
    ("expected_revision", "applied"),
    [
        pytest.param(1, False, id="stale-revision"),
        pytest.param(2, True, id="matching-revision"),
    ],
)
def test_state_delete_uses_revision_compare_and_swap(
    existing_state,
    expected_revision,
    applied,
) -> None:
    with existing_state.begin() as session:
        assert update_system_state(
            session,
            "sample_ext",
            "worker.position",
            expected_revision=1,
            schema_version=2,
            payload={"position": 6},
        )

    with existing_state.begin() as session:
        deleted = delete_system_state(
            session,
            "sample_ext",
            "worker.position",
            expected_revision=expected_revision,
        )

    assert deleted is applied
    with existing_state() as session:
        state = read_system_state(session, "sample_ext", "worker.position")
        if applied:
            assert state is None
        else:
            assert state is not None
            assert state.revision == 2
            assert state.payload == {"position": 6}


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
    with state_database.begin() as session, pytest.raises(ValidationError):
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
    with state_database.begin() as session, pytest.raises(ValidationError):
        create_system_state(
            session,
            "sample_ext",
            "payload",
            schema_version=1,
            payload=payload,
        )
