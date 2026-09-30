import traceback
from concurrent.futures import ThreadPoolExecutor

import pytest
from pydantic import ValidationError
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from include.config._policy import ConfigValidationError
from include.config.options import (
    CORE_SERVER_OPTIONS,
    OptionConflictError,
    ensure_option_defaults,
    read_options,
    write_options,
)
from include.database.models.operations import AuditEntry, OptionEntry
from include.database.options import create_option, read_option, update_option
from include.database.session import Base


@pytest.fixture
def option_database(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'options.db'}", connect_args={"timeout": 30}
    )
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine)
    engine.dispose()


def test_missing_options_use_defaults_without_writing(option_database):
    with option_database() as session:
        option = read_options(session, "core", CORE_SERVER_OPTIONS)
        assert option.value.name == "CFMS WebSocket Server"
        assert option.revision == 0
        assert read_option(session, "core", "server") is None


def test_defaults_do_not_overwrite_and_updates_are_visible(option_database):
    with option_database.begin() as session:
        assert (
            ensure_option_defaults(session, "core", CORE_SERVER_OPTIONS).revision == 1
        )
        changed = write_options(
            session,
            "core",
            CORE_SERVER_OPTIONS,
            {"name": "Changed"},
            expected_revision=1,
            source="maintenance_cli",
        )
        assert changed.revision == 2
        assert changed.value.name == "Changed"
        assert (
            ensure_option_defaults(session, "core", CORE_SERVER_OPTIONS).value.name
            == "Changed"
        )
    with option_database() as session:
        assert (
            read_options(session, "core", CORE_SERVER_OPTIONS).value.name == "Changed"
        )
        audit = session.scalars(select(AuditEntry)).one()
        assert audit.data["source"] == "maintenance_cli"
        assert audit.data["changed_fields"] == ["name"]


def test_conflict_and_invalid_values_do_not_change_data(option_database):
    with option_database.begin() as session:
        ensure_option_defaults(session, "core", CORE_SERVER_OPTIONS)
        with pytest.raises(OptionConflictError):
            write_options(
                session,
                "core",
                CORE_SERVER_OPTIONS,
                {"name": "Lost"},
                expected_revision=0,
            )
        with pytest.raises(ConfigValidationError):
            write_options(
                session, "core", CORE_SERVER_OPTIONS, {"name": 42}, expected_revision=1
            )
        assert read_options(session, "core", CORE_SERVER_OPTIONS).revision == 1
        assert not list(session.scalars(select(AuditEntry)))


def test_transaction_rolls_back_options_and_audit(option_database):
    with option_database() as session:
        write_options(
            session,
            "core",
            CORE_SERVER_OPTIONS,
            {"name": "Rolled back"},
            expected_revision=0,
        )
        session.flush()
        session.rollback()
    with option_database() as session:
        assert read_option(session, "core", "server") is None
        assert not list(session.scalars(select(AuditEntry)))


def test_reads_are_detached_and_unknown_version_is_preserved(option_database):
    with option_database.begin() as session:
        create_option(
            session, "sample", "policy", schema_version=1, payload={"nested": {"x": 1}}
        )
        stored = read_option(session, "sample", "policy")
        stored.payload["nested"]["x"] = 2
        assert read_option(session, "sample", "policy").payload == {"nested": {"x": 1}}
        create_option(
            session, "core", "server", schema_version=2, payload={"name": "Future"}
        )
        with pytest.raises(ConfigValidationError, match="Unsupported option schema"):
            ensure_option_defaults(session, "core", CORE_SERVER_OPTIONS)
        assert read_option(session, "core", "server").payload == {"name": "Future"}


def test_compare_and_swap_has_one_winner(option_database):
    with option_database.begin() as session:
        create_option(
            session, "sample", "policy", schema_version=1, payload={"winner": 0}
        )

    def compete(value):
        with option_database.begin() as session:
            return update_option(
                session,
                "sample",
                "policy",
                expected_revision=1,
                schema_version=1,
                payload={"winner": value},
            )

    with ThreadPoolExecutor(max_workers=2) as workers:
        outcomes = list(workers.map(compete, (1, 2)))
    assert sorted(outcomes) == [False, True]
    with option_database() as session:
        assert read_option(session, "sample", "policy").revision == 2


@pytest.mark.parametrize(
    "owner,key,version,payload",
    [
        ("core", "server", 0, {}),
        ("core", "server", 2**31, {}),
        ("CORE", "server", 1, {}),
        ("core", "server", 1, {"number": float("nan")}),
    ],
)
def test_low_level_api_rejects_invalid_rows(
    option_database, owner, key, version, payload
):
    with option_database() as session, pytest.raises(ValidationError):
        create_option(session, owner, key, schema_version=version, payload=payload)
    with option_database() as session:
        assert not list(session.scalars(select(OptionEntry)))


def test_invalid_group_errors_do_not_expose_the_original_payload(option_database):
    with option_database() as session:
        with pytest.raises(ConfigValidationError) as error:
            write_options(
                session,
                "core",
                CORE_SERVER_OPTIONS,
                {"name": ["private-marker"]},
                expected_revision=0,
            )
        assert "private-marker" not in "".join(traceback.format_exception(error.value))
