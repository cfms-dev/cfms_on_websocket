import traceback
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier, Event
from types import SimpleNamespace

import pytest
from pydantic import JsonValue, ValidationError
from sqlalchemy import create_engine, event, select
from sqlalchemy.dialects import mysql
from sqlalchemy.orm import sessionmaker

import include.config.options as option_config
import include.database.options as option_storage
from include.config._policy import ConfigValidationError
from include.config.options import (
    CORE_OPTIONS,
    SERVER_NAME_OPTION,
    OptionConflictError,
    OptionDefinition,
    acquire_options_revision,
    ensure_option_defaults,
    read_options,
    register_options,
    unregister_options,
    validate_options,
    write_options,
)
from include.config.options import (
    read_option as read_resolved_option,
)
from include.database.models.operations import (
    AuditEntry,
    OptionEntry,
    SystemStateEntry,
)
from include.database.options import (
    StoredOption,
    create_option,
    decode_option_value,
    encode_option_value,
    read_option,
    update_option,
)
from include.database.session import Base
from include.database.system_states import create_system_state


@pytest.fixture
def option_database(tmp_path):
    engine = create_engine(
        f"sqlite:///{tmp_path / 'options.db'}", connect_args={"timeout": 30}
    )
    Base.metadata.create_all(engine)
    yield sessionmaker(bind=engine)
    engine.dispose()


@pytest.fixture
def sample_options():
    definitions = (
        OptionDefinition("failure_threshold", 1, int, 50),
        OptionDefinition("distinct_account_threshold", 1, int, 10),
    )

    def validator(values):
        if values["distinct_account_threshold"] > values["failure_threshold"]:
            raise ConfigValidationError(
                "distinct_account_threshold exceeds failure_threshold"
            )

    register_options("sample", definitions, validator, owner="sample")
    yield definitions
    unregister_options("sample")


@pytest.mark.parametrize(
    ("value", "value_type", "text"),
    [
        ("", "str", ""),
        ("1", "str", "1"),
        ("null", "str", "null"),
        ('{"nested":true}', "str", '{"nested":true}'),
        ("中文\nname", "str", "中文\nname"),
        (True, "bool", "1"),
        (False, "bool", "0"),
        (1, "int", "1"),
        (-1, "int", "-1"),
        (0, "int", "0"),
        (1.0, "float", "1.0"),
        (-0.0, "float", "-0.0"),
        (None, "null", ""),
        ({"nested": [True, 1, None]}, "json", '{"nested":[true,1,null]}'),
        ([1, "x"], "json", '[1,"x"]'),
    ],
)
def test_codec_preserves_values_and_types(value, value_type, text):
    assert encode_option_value(value) == (value_type, text)
    decoded = decode_option_value(value_type, text)
    assert decoded == value
    assert type(decoded) is type(value)


pytestmark = pytest.mark.component


def test_structured_codec_preserves_large_integer_and_nested_scalar_types():
    value = {"nested": [2**64, 2**100, True, 1, 1.0]}
    value_type, text = encode_option_value(value)
    assert value_type == "json"
    decoded = decode_option_value(value_type, text)
    assert decoded == value
    assert [type(item) for item in decoded["nested"]] == [int, int, bool, int, float]


def test_structured_codec_errors_do_not_expose_invalid_json():
    malformed = '{"private-marker": invalid}'
    with pytest.raises(ValueError, match="Invalid stored option") as error:
        decode_option_value("json", malformed)
    assert "private-marker" not in "".join(traceback.format_exception(error.value))


@pytest.mark.parametrize(
    "value", [float("nan"), float("inf"), {"nested": [float("-inf")]}]
)
def test_codec_rejects_nonfinite_values(value):
    with pytest.raises(ValidationError):
        encode_option_value(value)


@pytest.mark.parametrize(
    ("value_type", "text"),
    [
        ("bool", "true"),
        ("bool", "2"),
        ("int", "01"),
        ("int", "1.0"),
        ("int", " 1"),
        ("float", "1"),
        ("float", "nan"),
        ("float", "inf"),
        ("null", "null"),
        ("json", "1"),
        ("json", "null"),
        ("json", "{invalid"),
        ("unknown", "private-marker"),
    ],
)
def test_codec_rejects_invalid_storage_without_exposing_values(value_type, text):
    with pytest.raises(ValueError, match="Invalid stored option") as error:
        decode_option_value(value_type, text)
    assert "private-marker" not in str(error.value)


def test_missing_options_use_defaults_without_writing(option_database):
    with option_database() as session:
        option = read_resolved_option(session, "server", SERVER_NAME_OPTION)
        assert option.value == "CFMS WebSocket Server"
        assert option.revision == 0
        assert read_option(session, "server", "name") is None
        assert not list(session.scalars(select(SystemStateEntry)))


def test_defaults_do_not_overwrite_and_repeated_writes_share_a_session(option_database):
    with option_database.begin() as session:
        initial = ensure_option_defaults(session, "server")
        assert initial["name"].revision == 1
        changed = write_options(
            session,
            "server",
            {"name": "Changed"},
            expected_revisions={"name": 1},
            source="maintenance_cli",
        )
        assert changed["name"].revision == 2
        assert changed["name"].value == "Changed"
        changed = write_options(
            session,
            "server",
            {"name": "Changed again"},
            expected_revisions={"name": 2},
        )
        assert changed["name"].revision == 3
        guard_revision = session.scalar(select(SystemStateEntry.revision))
        repeated = ensure_option_defaults(session, "server", CORE_OPTIONS["server"])
        assert repeated["name"].value == "Changed again"
        assert repeated["name"].revision == 3
        assert session.scalar(select(SystemStateEntry.revision)) == guard_revision
    with option_database() as session:
        assert (
            read_resolved_option(session, "server", SERVER_NAME_OPTION).value
            == "Changed again"
        )
        audits = list(session.scalars(select(AuditEntry)))
        assert len(audits) == 2
        maintenance_audit = next(
            audit for audit in audits if audit.data["source"] == "maintenance_cli"
        )
        assert maintenance_audit.data["changed_keys"] == ["name"]
        assert maintenance_audit.data["previous_revisions"] == {"name": 1}
        assert maintenance_audit.data["revisions"] == {"name": 2}
        assert "Changed" not in repr(maintenance_audit.data)


def test_conflict_and_invalid_values_do_not_change_data(option_database):
    with option_database.begin() as session:
        ensure_option_defaults(session, "server")
    with pytest.raises(OptionConflictError), option_database.begin() as session:
        write_options(
            session,
            "server",
            {"name": "Lost"},
            expected_revisions={"name": 0},
        )
    with pytest.raises(ConfigValidationError), option_database.begin() as session:
        write_options(
            session,
            "server",
            {"name": 42},
            expected_revisions={"name": 1},
        )
    with option_database() as session:
        assert read_resolved_option(session, "server", SERVER_NAME_OPTION).revision == 1
        assert session.scalar(select(SystemStateEntry.revision)) == 1
        assert not list(session.scalars(select(AuditEntry)))


def test_transaction_rolls_back_options_guard_and_audit(option_database):
    with option_database() as session:
        write_options(
            session,
            "server",
            {"name": "Rolled back"},
            expected_revisions={"name": 0},
        )
        session.flush()
        session.rollback()
    with option_database() as session:
        assert read_option(session, "server", "name") is None
        assert not list(session.scalars(select(SystemStateEntry)))
        assert not list(session.scalars(select(AuditEntry)))


def test_reads_are_detached_and_unknown_version_is_preserved(option_database):
    with option_database.begin() as session:
        create_option(
            session, "sample", "mapping", schema_version=1, value={"nested": {"x": 1}}
        )
        stored = read_option(session, "sample", "mapping")
        stored.value["nested"]["x"] = 2
        assert read_option(session, "sample", "mapping").value == {"nested": {"x": 1}}
        create_option(session, "server", "name", schema_version=2, value="Future")
    with (
        pytest.raises(ConfigValidationError, match="Unsupported option schema"),
        option_database.begin() as session,
    ):
        ensure_option_defaults(session, "server")
    with option_database() as session:
        assert read_option(session, "server", "name").value == "Future"
        assert not list(session.scalars(select(SystemStateEntry)))


def test_structured_defaults_do_not_leak_mutations(option_database):
    definition = OptionDefinition("mapping", 1, dict[str, JsonValue], {"nested": [1]})
    register_options("sample", (definition,), owner="sample")
    try:
        with option_database() as session:
            first = read_resolved_option(session, "sample", definition)
            first.value["nested"].append(2)
            assert read_resolved_option(session, "sample", definition).value == {
                "nested": [1]
            }
            assert definition.default == {"nested": [1]}
    finally:
        unregister_options("sample")


def test_compare_and_swap_has_one_winner(option_database):
    with option_database.begin() as session:
        create_option(session, "sample", "winner", schema_version=1, value=0)

    def compete(value):
        with option_database.begin() as session:
            return update_option(
                session,
                "sample",
                "winner",
                expected_revision=1,
                schema_version=1,
                value=value,
            )

    with ThreadPoolExecutor(max_workers=2) as workers:
        outcomes = list(workers.map(compete, (1, 2)))
    assert sorted(outcomes) == [False, True]
    with option_database() as session:
        assert read_option(session, "sample", "winner").revision == 2


@pytest.mark.parametrize(
    ("owner", "key", "version", "value"),
    [
        ("server", "name", 0, "name"),
        ("server", "name", 2**31, "name"),
        ("CORE", "name", 1, "name"),
        ("server", "name", 1, {"number": float("nan")}),
    ],
)
def test_low_level_api_rejects_invalid_rows(
    option_database, owner, key, version, value
):
    with option_database() as session, pytest.raises(ValidationError):
        create_option(session, owner, key, schema_version=version, value=value)
    with option_database() as session:
        assert not list(session.scalars(select(OptionEntry)))


def test_invalid_option_errors_do_not_expose_the_original_value(option_database):
    with option_database() as session:
        with pytest.raises(ConfigValidationError) as error:
            write_options(
                session,
                "server",
                {"name": ["private-marker"]},
                expected_revisions={"name": 0},
            )
        assert "private-marker" not in "".join(traceback.format_exception(error.value))


def test_scalar_storage_and_reads_never_call_json_codec(option_database, monkeypatch):
    def unexpected_json(*args, **kwargs):
        raise AssertionError("Scalar option used JSON serialization")

    monkeypatch.setattr(option_storage, "json_dumps", unexpected_json)
    monkeypatch.setattr(option_storage, "json_loads", unexpected_json)
    with option_database.begin() as session:
        write_options(
            session,
            "server",
            {"name": '{"unparsed":true}'},
            expected_revisions={"name": 0},
        )
    with option_database() as session:
        option = read_option(session, "server", "name")
        assert option.value_type == "str"
        assert option.option_value == '{"unparsed":true}'
        assert (
            read_resolved_option(session, "server", SERVER_NAME_OPTION).value
            == '{"unparsed":true}'
        )


def test_owner_reads_fetch_all_options_in_one_query(option_database, sample_options):
    with option_database.begin() as session:
        ensure_option_defaults(session, "sample")
    queries = []
    engine = option_database.kw["bind"]

    def record_query(connection, cursor, statement, parameters, context, executemany):
        queries.append(statement)

    event.listen(engine, "before_cursor_execute", record_query)
    try:
        with option_database() as session:
            options = read_options(session, "sample")
        assert {key: option.value for key, option in options.items()} == {
            "failure_threshold": 50,
            "distinct_account_threshold": 10,
        }
        assert len(queries) == 1
    finally:
        event.remove(engine, "before_cursor_execute", record_query)


def test_batch_validates_final_policy_and_updates_only_target_revisions(
    option_database, sample_options
):
    with option_database.begin() as session:
        ensure_option_defaults(session, "sample")
    with pytest.raises(ConfigValidationError), option_database.begin() as session:
        write_options(
            session,
            "sample",
            {"failure_threshold": 5},
            expected_revisions={"failure_threshold": 1},
        )
    with option_database.begin() as session:
        changed = write_options(
            session,
            "sample",
            {"failure_threshold": 5, "distinct_account_threshold": 5},
            expected_revisions={
                "failure_threshold": 1,
                "distinct_account_threshold": 1,
            },
        )
        assert set(changed) == {"failure_threshold", "distinct_account_threshold"}
        assert all(option.revision == 2 for option in changed.values())
        changed = write_options(
            session,
            "sample",
            {"failure_threshold": 6},
            expected_revisions={"failure_threshold": 2},
        )
        assert set(changed) == {"failure_threshold"}
        current = read_options(session, "sample")
        assert current["failure_threshold"].revision == 3
        assert current["distinct_account_threshold"].revision == 2


def test_concurrent_edits_of_different_keys_cannot_commit_write_skew(option_database):
    candidate_barrier = Barrier(2)
    concurrent = Event()
    definitions = (
        OptionDefinition("failure_threshold", 1, int, 50),
        OptionDefinition("distinct_account_threshold", 1, int, 10),
    )

    def validator(values):
        if values["distinct_account_threshold"] > values["failure_threshold"]:
            raise ConfigValidationError("Invalid thresholds")
        if concurrent.is_set():
            candidate_barrier.wait(timeout=10)

    register_options("sample", definitions, validator, owner="sample")
    try:
        with option_database.begin() as session:
            ensure_option_defaults(session, "sample")
        concurrent.set()

        def compete(patch):
            try:
                with option_database.begin() as session:
                    write_options(
                        session,
                        "sample",
                        patch,
                        expected_revisions={key: 1 for key in patch},
                    )
                return "applied"
            except OptionConflictError:
                return "conflict"

        with ThreadPoolExecutor(max_workers=2) as workers:
            outcomes = list(
                workers.map(
                    compete,
                    ({"failure_threshold": 15}, {"distinct_account_threshold": 20}),
                )
            )
        assert sorted(outcomes) == ["applied", "conflict"]
        concurrent.clear()
        with option_database() as session:
            current = {
                key: option.value
                for key, option in read_options(session, "sample").items()
            }
            assert current in (
                {"failure_threshold": 15, "distinct_account_threshold": 10},
                {"failure_threshold": 50, "distinct_account_threshold": 20},
            )
            validate_options("sample", current)
            assert len(list(session.scalars(select(AuditEntry)))) == 1
            assert session.scalar(select(SystemStateEntry.revision)) == 2
    finally:
        concurrent.clear()
        unregister_options("sample")


def test_defaults_reject_invalid_aggregate_and_roll_back(
    option_database, sample_options
):
    with option_database.begin() as session:
        create_option(session, "sample", "failure_threshold", schema_version=1, value=5)
    with pytest.raises(ConfigValidationError), option_database.begin() as session:
        ensure_option_defaults(session, "sample")
    with option_database() as session:
        assert read_option(session, "sample", "distinct_account_threshold") is None
        assert read_option(session, "sample", "failure_threshold").value == 5
        assert not list(session.scalars(select(SystemStateEntry)))


def test_invalid_reserved_guard_schema_fails_before_writes(option_database):
    with option_database.begin() as session:
        create_system_state(
            session,
            "core",
            "options_revision.server",
            schema_version=1,
            payload={"unexpected": True},
        )
    with (
        pytest.raises(ConfigValidationError, match="revision schema"),
        option_database.begin() as session,
    ):
        write_options(
            session,
            "server",
            {"name": "Invalid"},
            expected_revisions={"name": 0},
        )
    with option_database() as session:
        assert read_option(session, "server", "name") is None
        assert not list(session.scalars(select(AuditEntry)))


def test_failed_second_row_rolls_back_first_row_and_guard(
    option_database, sample_options, monkeypatch
):
    with option_database.begin() as session:
        ensure_option_defaults(session, "sample")
    original_update = option_config.update_option

    def conflicting_update(session, owner, option_key, **kwargs):
        if option_key == "failure_threshold":
            return False
        return original_update(session, owner, option_key, **kwargs)

    monkeypatch.setattr(option_config, "update_option", conflicting_update)
    with pytest.raises(OptionConflictError), option_database.begin() as session:
        write_options(
            session,
            "sample",
            {"failure_threshold": 20, "distinct_account_threshold": 15},
            expected_revisions={
                "failure_threshold": 1,
                "distinct_account_threshold": 1,
            },
        )
    with option_database() as session:
        assert {
            key: option.value for key, option in read_options(session, "sample").items()
        } == {
            "failure_threshold": 50,
            "distinct_account_threshold": 10,
        }
        assert session.scalar(select(SystemStateEntry.revision)) == 1
        assert not list(session.scalars(select(AuditEntry)))


def test_preparation_guard_and_option_write_can_share_one_transaction(option_database):
    with option_database.begin() as session:
        assert acquire_options_revision(session, "server") == 1
        ensure_option_defaults(session, "server")
        write_options(
            session,
            "server",
            {"name": "Prepared"},
            expected_revisions={"name": 1},
        )
    with option_database() as session:
        assert read_option(session, "server", "name").value == "Prepared"
        assert session.scalar(select(SystemStateEntry.revision)) == 3


def test_raw_snapshot_decodes_once_and_hides_value():
    option = StoredOption("sample", "sample", "key", 1, 1, "str", "private-marker", 1.0)
    assert option.value == "private-marker"
    assert "private-marker" not in repr(option)


def test_owner_and_namespace_are_independent(option_database):
    definition = OptionDefinition("threshold", 1, int, 1)
    register_options("sample.first", (definition,), owner="sample")
    register_options("sample.second", (definition,), owner="sample")
    try:
        with option_database.begin() as session:
            first = write_options(
                session,
                "sample.first",
                {"threshold": 2},
                expected_revisions={"threshold": 0},
            )["threshold"]
            second = write_options(
                session,
                "sample.second",
                {"threshold": 3},
                expected_revisions={"threshold": 0},
            )["threshold"]
            assert first.owner == second.owner == "sample"
            assert first.namespace == "sample.first"
            assert second.namespace == "sample.second"
            assert first.value == 2
            assert second.value == 3
            assert first.revision == second.revision == 1
    finally:
        unregister_options("sample")


@pytest.mark.parametrize(("rowcount", "expected"), [(1, True), (0, False)])
def test_create_option_mysql_dialect_preserves_rowcount(
    option_database, monkeypatch, rowcount, expected
):
    captured: dict[str, object] = {}

    def fake_execute(statement, execution_options=None):
        captured["sql"] = str(statement.compile(dialect=mysql.dialect()))
        captured["execution_options"] = execution_options
        return SimpleNamespace(rowcount=rowcount)

    with option_database() as session:
        monkeypatch.setattr(
            session,
            "get_bind",
            lambda: SimpleNamespace(dialect=SimpleNamespace(name="mysql")),
        )
        monkeypatch.setattr(session, "execute", fake_execute)
        created = create_option(
            session,
            "server",
            "name",
            schema_version=1,
            value="CFMS WebSocket Server",
        )

    assert created is expected
    assert captured["execution_options"] == {"preserve_rowcount": True}
    assert str(captured["sql"]).startswith("INSERT IGNORE INTO options")
