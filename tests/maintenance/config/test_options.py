import json
from contextlib import contextmanager
from functools import partial
from types import SimpleNamespace

import orjson
import pytest
import tomlkit
from pydantic import JsonValue
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from include.config.options import (
    OptionDefinition,
    get_option_definition,
    register_options,
    unregister_options,
    validate_options,
    write_options,
)
from include.config.validation import ConfigValidationError
from include.database.models.identity import User
from include.database.models.operations import AuditEntry, OptionEntry, SystemStateEntry
from include.database.options import create_option
from include.database.session import Base
from include.extensions.brute_force_lockdown import _extension as detector
from include.extensions.oidc_sso import _extension as oidc
from include.runtime_lock import server_runtime_lock
from maintenance.operations.config import options
from maintenance.operations.exceptions import MaintenanceOperationError


@pytest.fixture
def option_runtime(tmp_path, monkeypatch):
    engine = create_engine("sqlite://")
    Base.metadata.create_all(
        engine,
        tables=[
            User.__table__,
            AuditEntry.__table__,
            OptionEntry.__table__,
            SystemStateEntry.__table__,
        ],
    )
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(
        options,
        "discover_extensions",
        lambda _root: {
            "brute_force_lockdown": SimpleNamespace(
                manifest=SimpleNamespace(
                    option_namespaces=("security.brute_force_lockdown",)
                )
            ),
            "oidc_sso": SimpleNamespace(
                manifest=SimpleNamespace(option_namespaces=("identity.oidc",))
            ),
            "sample_ext": SimpleNamespace(
                manifest=SimpleNamespace(option_namespaces=("sample_ext",))
            ),
        },
    )
    monkeypatch.setattr(options, "Session", sessions)
    monkeypatch.setattr(options, "load_database_models", lambda: None)
    monkeypatch.setattr(options, "enter_server_root", lambda: tmp_path)

    @contextmanager
    def extension_declarations(owner):
        assert owner in ("brute_force_lockdown", "oidc_sso")
        namespace = (
            "security.brute_force_lockdown"
            if owner == "brute_force_lockdown"
            else "identity.oidc"
        )
        definitions = (
            detector.POLICY_OPTIONS
            if owner == "brute_force_lockdown"
            else oidc.POLICY_OPTIONS
        )
        validator = (
            partial(detector.ext_validate_options, namespace=namespace)
            if owner == "brute_force_lockdown"
            else None
        )
        added = False
        try:
            get_option_definition(namespace, definitions[0].option_key)
        except ConfigValidationError:
            register_options(namespace, definitions, validator, owner=owner)
            added = True
        try:
            yield detector
        finally:
            if added:
                unregister_options(owner)

    monkeypatch.setattr(
        options, "maintenance_extension_context", extension_declarations
    )
    return sessions


pytestmark = pytest.mark.component


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
    payload_file.write_bytes(orjson.dumps("Persisted Server"))

    created = options.set_options("server", "name", payload_file, expected_revision=0)

    assert created.revision == 1
    assert options.get_options("server", "name").value == "Persisted Server"
    with pytest.raises(MaintenanceOperationError, match="revision conflict"):
        options.set_options("server", "name", payload_file, expected_revision=0)
    reset = options.reset_options("server", "name", expected_revision=1)

    assert reset.revision == 2
    assert reset.value == "CFMS WebSocket Server"
    with option_runtime() as session:
        audits = session.scalars(select(AuditEntry)).all()
        assert len(audits) == 2
        assert all(audit.data["source"] == "maintenance_cli" for audit in audits)
        assert all(audit.user_id is None for audit in audits)


def test_options_invalid_json_does_not_create_or_audit(option_runtime, tmp_path):
    payload_file = tmp_path / "invalid.json"
    payload_file.write_text("123", encoding="utf-8")

    with pytest.raises(MaintenanceOperationError, match="name"):
        options.set_options("server", "name", payload_file, expected_revision=0)

    with option_runtime() as session:
        assert session.scalar(select(OptionEntry)) is None
        assert session.scalar(select(AuditEntry)) is None
        assert session.scalar(select(SystemStateEntry)) is None


def test_raw_inspection_does_not_import_an_uninstalled_owner(
    option_runtime, monkeypatch
):
    with option_runtime.begin() as session:
        create_option(
            session,
            "removed_extension",
            "unknown_setting",
            schema_version=99,
            value={"unknown": True},
        )
    monkeypatch.setattr(
        options,
        "maintenance_extension_context",
        lambda *_args: pytest.fail("raw inspection must not import extension code"),
    )

    stored = options.get_options("removed_extension", "unknown_setting")
    listed = options.list_options("removed_extension")

    assert stored.schema_version == 99
    assert stored.value == {"unknown": True}
    assert listed == (stored,)


@pytest.mark.parametrize(
    ("value", "annotation", "default"),
    [(2**80 + 1, int, 0), ({"nested": [2**80 + 1]}, dict[str, JsonValue], {})],
)
def test_single_set_preserves_large_integer_values(
    option_runtime, tmp_path, monkeypatch, value, annotation, default
):
    definition = OptionDefinition("setting", 1, annotation, default)

    @contextmanager
    def declarations(owner):
        assert owner == "sample_ext"
        register_options(owner, (definition,), owner=owner)
        try:
            yield
        finally:
            unregister_options(owner)

    monkeypatch.setattr(options, "maintenance_extension_context", declarations)
    value_file = tmp_path / "large-integer.json"
    value_file.write_text(json.dumps(value), encoding="utf-8")

    changed = options.set_options(
        "sample_ext", "setting", value_file, expected_revision=0
    )

    assert changed.value == value
    assert type(changed.value) is type(value)
    assert options.get_options("sample_ext", "setting").value == value


def test_missing_core_value_lists_default_without_creating_data(option_runtime):
    stored = options.get_options("server", "name")
    assert stored.value == "CFMS WebSocket Server"
    assert stored.revision == 0
    assert options.list_options("server") == (stored,)
    with option_runtime() as session:
        assert session.scalar(select(OptionEntry)) is None
        assert session.scalar(select(SystemStateEntry)) is None


def test_set_many_updates_related_thresholds_atomically(option_runtime, tmp_path):
    with (
        options.maintenance_extension_context("brute_force_lockdown"),
        option_runtime.begin() as session,
    ):
        defaults = validate_options("security.brute_force_lockdown", {})
        write_options(
            session,
            "security.brute_force_lockdown",
            defaults,
            expected_revisions={key: 0 for key in defaults},
        )
    update_file = tmp_path / "policy-update.json"
    update_file.write_bytes(
        orjson.dumps(
            {
                "failure_threshold": {"value": 1, "expected_revision": 1},
                "distinct_account_threshold": {"value": 1, "expected_revision": 1},
                "distinct_ip_threshold": {"value": 1, "expected_revision": 1},
            }
        )
    )

    updated = options.set_many_options("security.brute_force_lockdown", update_file)

    assert set(updated) == {
        "failure_threshold",
        "distinct_account_threshold",
        "distinct_ip_threshold",
    }
    assert all(
        option.value == 1 and option.revision == 2 for option in updated.values()
    )
    assert (
        options.get_options("security.brute_force_lockdown", "window_seconds").revision
        == 1
    )
    assert options.get_options("security.brute_force_lockdown", "reason").revision == 1
    with option_runtime() as session:
        audits = session.scalars(select(AuditEntry)).all()
        assert len(audits) == 2
        assert audits[-1].data["changed_keys"] == sorted(updated)


def test_set_many_conflict_rolls_back_every_setting_and_audit(option_runtime, tmp_path):
    with option_runtime.begin() as session:
        create_option(
            session,
            "security.brute_force_lockdown",
            "window_seconds",
            schema_version=1,
            value=600,
        )
    update_file = tmp_path / "conflicting.json"
    update_file.write_bytes(
        orjson.dumps(
            {
                "reason": {"value": "Changed reason", "expected_revision": 0},
                "window_seconds": {"value": 120, "expected_revision": 0},
            }
        )
    )

    with pytest.raises(MaintenanceOperationError, match="revision conflict"):
        options.set_many_options("security.brute_force_lockdown", update_file)

    stored = options.list_options("security.brute_force_lockdown")
    assert [
        (option.option_key, option.value, option.revision) for option in stored
    ] == [("window_seconds", 600, 1)]
    with option_runtime() as session:
        assert session.scalar(select(AuditEntry)) is None
        assert session.scalar(select(SystemStateEntry)) is None


@pytest.mark.parametrize(
    "payload",
    [
        [],
        {},
        {"name": {"value": "New"}},
        {"name": {"value": "New", "expected_revision": True}},
        {"name": {"value": "New", "expected_revision": "0"}},
        {"name": {"value": "New", "expected_revision": -1}},
        {"name": {"value": "New", "expected_revision": 0, "other": True}},
    ],
)
def test_set_many_rejects_invalid_entries_before_writing(
    option_runtime, tmp_path, payload
):
    update_file = tmp_path / "invalid-update.json"
    update_file.write_bytes(orjson.dumps(payload))

    with pytest.raises(MaintenanceOperationError):
        options.set_many_options("server", update_file)

    with option_runtime() as session:
        assert session.scalar(select(OptionEntry)) is None
        assert session.scalar(select(AuditEntry)) is None
        assert session.scalar(select(SystemStateEntry)) is None


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
        assert session.scalar(select(SystemStateEntry)) is None


def test_migration_of_disabled_extension_validates_all_settings_before_commit(
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
        assert session.scalar(select(SystemStateEntry)) is None


def test_migration_keeps_different_database_values_until_explicit_discard(
    option_runtime, tmp_path
):
    config_path = _legacy_config(tmp_path)
    original = config_path.read_bytes()
    with option_runtime.begin() as session:
        write_options(
            session,
            "server",
            {"name": "New Database Server"},
            expected_revisions={"name": 0},
        )

    with pytest.raises(MaintenanceOperationError, match="discard-legacy"):
        options.migrate_options(write=True)
    assert config_path.read_bytes() == original

    result = options.migrate_options(write=True, discard_legacy=True)

    assert result.items[0].action == "Discard legacy"
    assert options.get_options("server", "name").value == "New Database Server"
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
    assert options.get_options("server", "name").revision == 1
    with option_runtime() as session:
        guard_revision = session.scalar(select(SystemStateEntry.revision))
    monkeypatch.setattr(options, "write_config_atomically", original_write)

    resumed = options.migrate_options(write=True)

    assert resumed.items[0].action == "Already imported"
    assert resumed.backup_path.read_bytes() == original
    assert options.get_options("server", "name").revision == 1
    assert (
        "name" not in tomlkit.parse(config_path.read_text(encoding="utf-8"))["server"]
    )
    with option_runtime() as session:
        assert len(session.scalars(select(AuditEntry)).all()) == 1
        assert session.scalar(select(SystemStateEntry.revision)) == guard_revision


def test_partial_policy_import_preserves_equal_keys_and_imports_missing_values(
    option_runtime, tmp_path
):
    _legacy_config(
        tmp_path,
        policy={
            "failure_threshold": 1,
            "distinct_account_threshold": 1,
            "distinct_ip_threshold": 1,
        },
    )
    with option_runtime.begin() as session:
        create_option(
            session,
            "security.brute_force_lockdown",
            "failure_threshold",
            schema_version=1,
            value=1,
        )

    result = options.migrate_options(write=True)

    assert len(result.items) == 6
    stored = options.list_options("security.brute_force_lockdown")
    assert len(stored) == 5
    assert (
        options.get_options(
            "security.brute_force_lockdown", "failure_threshold"
        ).revision
        == 1
    )
    assert (
        options.get_options(
            "security.brute_force_lockdown", "distinct_account_threshold"
        ).value
        == 1
    )
    assert (
        options.get_options(
            "security.brute_force_lockdown", "distinct_ip_threshold"
        ).value
        == 1
    )
    with option_runtime() as session:
        audit = session.scalars(
            select(AuditEntry).where(
                AuditEntry.target == "security.brute_force_lockdown"
            )
        ).one()
        assert "failure_threshold" not in audit.data["revisions"]


def test_different_partial_policy_blocks_all_missing_keys(option_runtime, tmp_path):
    config_path = _legacy_config(tmp_path, policy={"window_seconds": 123})
    original = config_path.read_bytes()
    with option_runtime.begin() as session:
        create_option(
            session,
            "security.brute_force_lockdown",
            "window_seconds",
            schema_version=1,
            value=321,
        )

    with pytest.raises(MaintenanceOperationError, match="discard-legacy"):
        options.migrate_options(write=True)

    assert config_path.read_bytes() == original
    with option_runtime() as session:
        assert len(session.scalars(select(OptionEntry)).all()) == 1
        assert session.scalar(select(AuditEntry)) is None
        assert session.scalar(select(SystemStateEntry)) is None


def test_discard_partial_invalid_policy_does_not_overwrite_or_clean_toml(
    option_runtime, tmp_path
):
    config_path = _legacy_config(tmp_path, policy="malformed legacy policy")
    original = config_path.read_bytes()
    with option_runtime.begin() as session:
        create_option(
            session,
            "security.brute_force_lockdown",
            "failure_threshold",
            schema_version=1,
            value=1,
        )

    with pytest.raises(MaintenanceOperationError, match="distinct_account_threshold"):
        options.migrate_options(write=True, discard_legacy=True)

    assert config_path.read_bytes() == original
    with option_runtime() as session:
        entries = session.scalars(select(OptionEntry)).all()
        assert len(entries) == 1
        assert entries[0].option_value == "1"
        assert session.scalar(select(AuditEntry)) is None


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
    with options.maintenance_extension_context("brute_force_lockdown"):
        expected = validate_options("security.brute_force_lockdown", {})
    if has_stored_policy:
        expected["window_seconds"] = 123
        with (
            options.maintenance_extension_context("brute_force_lockdown"),
            option_runtime.begin() as session,
        ):
            write_options(
                session,
                "security.brute_force_lockdown",
                expected,
                expected_revisions={key: 0 for key in expected},
            )

    options.migrate_options(write=True, discard_legacy=True)

    stored = options.list_options("security.brute_force_lockdown")
    assert {option.option_key: option.value for option in stored} == expected
    assert all(option.revision == 1 for option in stored)
    document = tomlkit.parse(config_path.read_text(encoding="utf-8"))
    assert "security.brute_force_lockdown" not in document["extensions"]


def test_migration_covers_business_namespaces_and_preserves_deployment_settings(
    option_runtime, tmp_path
):
    path = _legacy_config(tmp_path, policy={"failure_threshold": 20})
    document = tomlkit.parse(path.read_text(encoding="utf-8"))
    document["security"] = {
        "pepper": "private",
        "passwd_min_length": 12,
        "auth_throttle": {"enabled": False},
        "request_rate_control": {"action_costs": {"core.search.query": 4}},
        "require_passwd_enforcement_changes": False,
    }
    document["access"] = {"enable_access_recursive_check": False}
    document["document"] = {
        "upload": {
            "start_timeout_seconds": 800,
            "creation_risk_control": {"mode": "observe"},
        },
        "download": {"risk_control": {"mode": "enforce"}},
    }
    document["identity"] = {"permission_retention": {"retention_days": 7}}
    document["maintenance"] = {"audit_retention": {"retention_days": 7}}
    document["scheduling"] = {
        "worker_threads": 8,
        "history_retention_days": 7,
        "misfire_grace_seconds": 30,
    }
    document["extensions"]["oidc_sso"] = {
        "issuer": "https://issuer.example",
        "client_secret": "private",
        "username_claim": "email",
        "auto_provision": True,
        "default_groups": ["user"],
    }
    path.write_text(tomlkit.dumps(document), encoding="utf-8")
    original = path.read_bytes()
    preview = options.migrate_options()
    assert path.read_bytes() == original
    assert {item.namespace for item in preview.items} >= {
        "server",
        "security.password",
        "security.auth_throttle",
        "security.request_rate_control",
        "access",
        "document.upload",
        "document.upload.creation_risk_control",
        "document.download.risk_control",
        "identity.permission_retention",
        "maintenance.audit_retention",
        "scheduling",
        "security.brute_force_lockdown",
        "identity.oidc",
    }
    options.migrate_options(write=True)
    assert options.get_options("security.password", "passwd_min_length").value == 12
    assert options.get_options("identity.oidc", "username_claim").value == "email"
    assert options.get_options("identity.oidc", "auto_provision").owner == "oidc_sso"
    assert options.get_options(
        "security.request_rate_control", "action_costs"
    ).value == {"core.search.query": 4}
    stored = tomlkit.parse(path.read_text(encoding="utf-8"))
    assert stored["security"] == {"pepper": "private"}
    assert stored["scheduling"] == {"worker_threads": 8}
    assert stored["extensions"]["oidc_sso"] == {
        "issuer": "https://issuer.example",
        "client_secret": "private",
    }
    assert not options.migrate_options().changed


def test_migration_reuses_legacy_password_and_creation_conversions(
    option_runtime, tmp_path
):
    path = _legacy_config(tmp_path)
    document = tomlkit.parse(path.read_text(encoding="utf-8"))
    document["security"] = {"passwd_must_contain": [["A", "B"], "01"]}
    document["document"] = {
        "upload": {
            "creation_rate_per_user": 50,
            "creation_rate_per_ip": 125,
            "creation_rate_window_seconds": 300,
        }
    }
    path.write_text(tomlkit.dumps(document), encoding="utf-8")
    options.migrate_options(write=True)
    assert options.get_options("security.password", "passwd_rules").value == [
        "(?:A|B)",
        "(?:0|1)",
    ]
    assert (
        options.get_options("security.password", "passwd_min_passed_count").value == 2
    )
    assert (
        options.get_options(
            "document.upload.creation_risk_control", "account_capacity"
        ).value
        == 10
    )
    assert (
        options.get_options(
            "document.upload.creation_risk_control", "ip_capacity"
        ).value
        == 25
    )
    assert (
        options.get_options(
            "document.upload.creation_risk_control", "refill_period_seconds"
        ).value
        == 300
    )
    assert not options.migrate_options().changed
