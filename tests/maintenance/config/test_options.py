from contextlib import contextmanager

import orjson
import pytest
import tomlkit
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from include.config.options import (
    CORE_SERVER_OPTIONS,
    get_option_group,
    register_option_groups,
    unregister_option_groups,
    write_options,
)
from include.config.validation import ConfigValidationError
from include.database.models.identity import User
from include.database.models.operations import AuditEntry, OptionEntry
from include.database.options import create_option
from include.database.session import Base
from include.extensions.brute_force_lockdown import _extension as detector
from include.runtime_lock import server_runtime_lock
from maintenance.operations.config import options
from maintenance.operations.exceptions import MaintenanceOperationError


@pytest.fixture
def option_runtime(tmp_path, monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(
        engine, tables=[User.__table__, AuditEntry.__table__, OptionEntry.__table__]
    )
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(options, "Session", sessions)
    monkeypatch.setattr(options, "load_database_models", lambda: None)
    monkeypatch.setattr(options, "enter_server_root", lambda: tmp_path)

    @contextmanager
    def extension_declarations(owner):
        assert owner == "brute_force_lockdown"
        added = False
        try:
            get_option_group(owner, "policy")
        except ConfigValidationError:
            register_option_groups(owner, (detector.POLICY_OPTIONS,))
            added = True
        try:
            yield detector
        finally:
            if added:
                unregister_option_groups(owner)

    monkeypatch.setattr(
        options, "maintenance_extension_context", extension_declarations
    )
    return sessions


def _legacy_config(tmp_path, *, name="Legacy Server", policy=None):
    document = tomlkit.document()
    document["server"] = {"name": name, "secret_key": "must-remain-private"}
    document["extensions"] = {"enabled": []}
    if policy is not None:
        document["extensions"]["brute_force_lockdown"] = policy
    path = tmp_path / "config.toml"
    path.write_text(tomlkit.dumps(document), encoding="utf-8")
    return path


def test_options_set_conflicts_and_reset_preserve_audit_transaction(
    option_runtime, tmp_path
):
    payload_file = tmp_path / "options.json"
    payload_file.write_bytes(orjson.dumps({"name": "Persisted Server"}))

    created = options.set_options("core", "server", payload_file, expected_revision=0)

    assert created.revision == 1
    assert options.get_options("core", "server").payload == {"name": "Persisted Server"}
    with pytest.raises(MaintenanceOperationError, match="revision conflict"):
        options.set_options("core", "server", payload_file, expected_revision=0)
    reset = options.reset_options("core", "server", expected_revision=1)

    assert reset.revision == 2
    assert reset.payload == {"name": "CFMS WebSocket Server"}
    with option_runtime() as session:
        audits = session.scalars(select(AuditEntry)).all()
        assert len(audits) == 2
        assert all(audit.data["source"] == "maintenance_cli" for audit in audits)
        assert all(audit.username is None for audit in audits)


def test_options_invalid_json_does_not_create_or_audit(option_runtime, tmp_path):
    payload_file = tmp_path / "invalid.json"
    payload_file.write_text('{"name": 123}', encoding="utf-8")

    with pytest.raises(MaintenanceOperationError, match="name"):
        options.set_options("core", "server", payload_file, expected_revision=0)

    with option_runtime() as session:
        assert session.scalar(select(OptionEntry)) is None
        assert session.scalar(select(AuditEntry)) is None


def test_raw_inspection_does_not_import_an_uninstalled_owner(
    option_runtime, monkeypatch
):
    with option_runtime.begin() as session:
        create_option(
            session,
            "removed_extension",
            "policy",
            schema_version=99,
            payload={"unknown": True},
        )
    monkeypatch.setattr(
        options,
        "maintenance_extension_context",
        lambda *_args: pytest.fail("raw inspection must not import extension code"),
    )

    stored = options.get_options("removed_extension", "policy")
    listed = options.list_options("removed_extension")

    assert stored.schema_version == 99
    assert stored.payload == {"unknown": True}
    assert listed == (stored,)


def test_migration_preview_has_no_database_or_file_effects(option_runtime, tmp_path):
    config_path = _legacy_config(tmp_path)
    original = config_path.read_bytes()

    preview = options.migrate_options()

    assert preview.changed is True
    assert preview.items[0].action == "Import"
    assert config_path.read_bytes() == original
    assert list(tmp_path.glob("config.toml.backup-*")) == []
    assert not (tmp_path / ".maintenance").exists()
    with option_runtime() as session:
        assert session.scalar(select(OptionEntry)) is None
        assert session.scalar(select(AuditEntry)) is None


def test_migration_of_disabled_extension_validates_all_groups_before_commit(
    option_runtime, tmp_path
):
    config_path = _legacy_config(
        tmp_path, policy={"failure_threshold": 1, "distinct_account_threshold": 2}
    )
    original = config_path.read_bytes()

    with pytest.raises(MaintenanceOperationError, match="distinct_account_threshold"):
        options.migrate_options(write=True)

    assert config_path.read_bytes() == original
    with option_runtime() as session:
        assert session.scalar(select(OptionEntry)) is None
        assert session.scalar(select(AuditEntry)) is None


def test_migration_keeps_different_database_values_until_explicit_discard(
    option_runtime, tmp_path
):
    config_path = _legacy_config(tmp_path)
    original = config_path.read_bytes()
    with option_runtime.begin() as session:
        write_options(
            session,
            "core",
            CORE_SERVER_OPTIONS,
            {"name": "New Database Server"},
            expected_revision=0,
        )

    with pytest.raises(MaintenanceOperationError, match="discard-legacy"):
        options.migrate_options(write=True)
    assert config_path.read_bytes() == original

    result = options.migrate_options(write=True, discard_legacy=True)

    assert result.items[0].action == "Discard legacy"
    assert options.get_options("core", "server").payload == {
        "name": "New Database Server"
    }
    stored_config = tomlkit.parse(config_path.read_text(encoding="utf-8"))
    assert "name" not in stored_config["server"]
    assert stored_config["server"]["secret_key"] == "must-remain-private"


def test_migration_cleanup_failure_can_resume_without_overwriting_database(
    option_runtime, tmp_path, monkeypatch
):
    config_path = _legacy_config(tmp_path)
    original = config_path.read_bytes()
    original_write = options.write_config_atomically

    def fail_cleanup(*_args):
        raise MaintenanceOperationError("simulated cleanup failure")

    monkeypatch.setattr(options, "write_config_atomically", fail_cleanup)
    with pytest.raises(
        MaintenanceOperationError, match="Database options were committed"
    ):
        options.migrate_options(write=True)
    assert config_path.read_bytes() == original
    assert options.get_options("core", "server").revision == 1
    monkeypatch.setattr(options, "write_config_atomically", original_write)

    resumed = options.migrate_options(write=True)

    assert resumed.items[0].action == "Already imported"
    assert resumed.backup_path.read_bytes() == original
    assert options.get_options("core", "server").revision == 1
    assert (
        "name" not in tomlkit.parse(config_path.read_text(encoding="utf-8"))["server"]
    )
    with option_runtime() as session:
        assert len(session.scalars(select(AuditEntry)).all()) == 1


def test_migration_rejects_running_runtime_before_modifying_data(
    option_runtime, tmp_path
):
    config_path = _legacy_config(tmp_path)
    original = config_path.read_bytes()

    with (
        server_runtime_lock(tmp_path),
        pytest.raises(MaintenanceOperationError, match="already using"),
    ):
        options.migrate_options(write=True)

    assert config_path.read_bytes() == original
    with option_runtime() as session:
        assert session.scalar(select(OptionEntry)) is None


def test_invalid_legacy_extension_shape_reports_configuration_error(
    option_runtime, tmp_path
):
    _legacy_config(tmp_path, policy="not a table")

    with pytest.raises(MaintenanceOperationError, match="must be a table"):
        options.migrate_options()


@pytest.mark.parametrize("has_stored_policy", [False, True])
def test_explicit_discard_ignores_malformed_legacy_policy(
    option_runtime, tmp_path, has_stored_policy
):
    config_path = _legacy_config(tmp_path, policy="not a table")
    expected = detector.POLICY_OPTIONS.default_payload()
    if has_stored_policy:
        expected["window_seconds"] = 123
        with option_runtime.begin() as session:
            write_options(
                session,
                "brute_force_lockdown",
                detector.POLICY_OPTIONS,
                expected,
                expected_revision=0,
            )

    options.migrate_options(write=True, discard_legacy=True)

    stored = options.get_options("brute_force_lockdown", "policy")
    assert stored.payload == expected
    assert stored.revision == 1
    document = tomlkit.parse(config_path.read_text(encoding="utf-8"))
    assert "brute_force_lockdown" not in document["extensions"]
