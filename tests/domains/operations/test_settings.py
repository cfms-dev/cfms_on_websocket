import uuid
from importlib import import_module
from types import SimpleNamespace

import pytest
from pydantic import TypeAdapter, ValidationError
from sqlalchemy import event, select
from sqlalchemy.orm import sessionmaker

from include.config._policy import ConfigValidationError
from include.config.options import (
    CORE_OPTIONS,
    OptionDefinition,
    SettingMetadata,
    describe_settings,
    register_options,
    unregister_options,
)
from include.database.models.identity import User, UserPermission
from include.database.models.operations import AuditEntry, OptionEntry, SystemStateEntry
from include.database.options import create_option
from include.database.session import Base
from include.domains.access.permissions import Permissions
from include.domains.identity.default_groups import DEFAULT_GROUP_PERMISSIONS
from include.domains.operations.handlers import settings
from include.transport.router import available_functions

pytestmark = pytest.mark.component


@pytest.fixture
def setting_context(monkeypatch, tmp_path, sqlite_engine_factory):
    engine = sqlite_engine_factory(tmp_path / "settings.db")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(settings, "Session", sessions)
    users = {}
    with sessions.begin() as session:
        for name, permissions in (
            ("admin", (Permissions.VIEW_SETTINGS, Permissions.MANAGE_SETTINGS)),
            ("reader", (Permissions.VIEW_SETTINGS,)),
            ("writer", (Permissions.MANAGE_SETTINGS,)),
            ("operator", (Permissions.MANAGE_SYSTEM,)),
            ("user", ()),
        ):
            user = User(id=uuid.uuid4(), username=name, created_time=0.0)
            users[name] = user.id
            user.rights.extend(
                UserPermission(permission=permission, granted=True, start_time=0.0)
                for permission in permissions
            )
            session.add(user)
    return SimpleNamespace(engine=engine, Session=sessions, users=users)


def call(context, handler_type, data, user="admin"):
    responses = []
    connection = SimpleNamespace(
        user_id=context.users[user],
        conclude_request=lambda code, data, message: responses.append((code, data)),
    )
    result = handler_type().handle(
        connection, handler_type.request_model.model_validate(data)
    )
    assert len(responses) == 1
    return result, responses[0][0], responses[0][1]


def test_all_core_options_have_useful_metadata():
    identities = {
        (namespace, definition.option_key)
        for namespace, definitions in CORE_OPTIONS.items()
        for definition in definitions
    }
    items = describe_settings()
    assert identities <= {(item["namespace"], item["option_key"]) for item in items}
    assert len(identities) == 84
    assert [(item["namespace"], item["option_key"]) for item in items] == sorted(
        (item["namespace"], item["option_key"]) for item in items
    )
    for item in items:
        assert item["title"].strip()
        assert item["description"].strip()
        assert item["schema_version"] == 1
    schema = {
        item["option_key"]: item
        for item in describe_settings("security.request_rate_control")
    }
    assert schema["mode"]["value_schema"]["enum"] == ["disabled", "observe", "enforce"]
    assert schema["action_costs"]["value_schema"] == {
        "type": "object",
        "additionalProperties": {"type": "integer", "exclusiveMinimum": 0},
    }
    assert Permissions.VIEW_SETTINGS in DEFAULT_GROUP_PERMISSIONS["sysop"]
    assert Permissions.MANAGE_SETTINGS in DEFAULT_GROUP_PERMISSIONS["sysop"]


@pytest.mark.parametrize(
    ("title", "description"), [("", "description"), ("Title", "  ")]
)
def test_metadata_rejects_blank_text(title, description):
    with pytest.raises(ConfigValidationError):
        SettingMetadata(title, description)


@pytest.mark.parametrize(
    ("extension", "namespace", "keys"),
    [
        (
            "oidc_sso",
            "identity.oidc",
            {"username_claim", "auto_provision", "default_groups"},
        ),
        (
            "brute_force_lockdown",
            "security.brute_force_lockdown",
            {
                "window_seconds",
                "failure_threshold",
                "distinct_account_threshold",
                "distinct_ip_threshold",
                "reason",
            },
        ),
    ],
)
def test_bundled_extension_settings_have_metadata_and_schemas(
    extension, namespace, keys
):
    declarations = import_module(
        f"include.extensions.{extension}._extension"
    ).ext_register_options()
    assert set(declarations) == {namespace}
    assert {definition.option_key for definition in declarations[namespace]} == keys
    for definition in declarations[namespace]:
        assert definition.setting.title.strip()
        assert definition.setting.description.strip()
        assert TypeAdapter(definition.annotation).json_schema(mode="validation")["type"]


def test_metadata_defaults_are_detached_from_option_definitions():
    items = describe_settings("security.password")
    rules = next(item for item in items if item["option_key"] == "passwd_rules")
    rules["default"].append("changed")
    fresh = describe_settings("security.password")
    assert next(
        item["default"] for item in fresh if item["option_key"] == "passwd_rules"
    ) == [r"[A-Z]", r"[a-z]", r"[0-9]", r"[!@#$%^&*()]"]


@pytest.mark.parametrize(
    ("action", "handler_type"),
    [
        ("core.setting.list", settings.RequestListSettingsHandler),
        ("core.setting.get", settings.RequestGetSettingsHandler),
        ("core.setting.update", settings.RequestUpdateSettingsHandler),
    ],
)
def test_routes_require_authentication(action, handler_type):
    assert available_functions[action] is handler_type
    assert handler_type.requires_auth is True


@pytest.mark.parametrize("user", ["reader", "writer", "operator", "user"])
def test_permissions_are_independent(setting_context, user):
    _, list_code, _ = call(
        setting_context, settings.RequestListSettingsHandler, {}, user
    )
    _, get_code, _ = call(
        setting_context,
        settings.RequestGetSettingsHandler,
        {"namespace": "server"},
        user,
    )
    _, update_code, _ = call(
        setting_context,
        settings.RequestUpdateSettingsHandler,
        {
            "namespace": "server",
            "changes": {"name": {"value": "changed", "expected_revision": 0}},
        },
        user,
    )
    assert list_code == get_code == (200 if user == "reader" else 403)
    assert update_code == (200 if user == "writer" else 403)
    with setting_context.Session() as session:
        assert (session.get(OptionEntry, ("server", "name")) is not None) == (
            user == "writer"
        )


def test_discovery_never_reads_options_or_states(setting_context):
    statements = []

    def record(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(setting_context.engine, "before_cursor_execute", record)
    try:
        _, code, data = call(
            setting_context,
            settings.RequestListSettingsHandler,
            {"namespace": "server"},
        )
    finally:
        event.remove(setting_context.engine, "before_cursor_execute", record)
    assert code == 200
    assert data["items"][0]["owner"] == "core"
    assert data["items"][0]["option_key"] == "name"
    assert not any(
        "FROM options" in sql or "FROM system_states" in sql for sql in statements
    )
    _, code, data = call(
        setting_context,
        settings.RequestListSettingsHandler,
        {"namespace": "server.child"},
    )
    assert code == 200
    assert data["items"] == []


def test_batch_read_is_one_select_and_does_not_initialize_defaults(setting_context):
    statements = []

    def record(connection, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    event.listen(setting_context.engine, "before_cursor_execute", record)
    try:
        result, code, data = call(
            setting_context,
            settings.RequestGetSettingsHandler,
            {
                "namespace": "security.password",
                "keys": ["passwd_min_length", "passwd_max_length"],
            },
        )
    finally:
        event.remove(setting_context.engine, "before_cursor_execute", record)
    assert code == 200
    assert data["settings"] == {
        "passwd_min_length": {"value": 8, "revision": 0, "updated_at": None},
        "passwd_max_length": {"value": 32, "revision": 0, "updated_at": None},
    }
    assert sum("FROM options" in sql for sql in statements) == 1
    assert result.data == {
        "revisions": {"passwd_min_length": 0, "passwd_max_length": 0}
    }
    with setting_context.Session() as session:
        assert session.scalars(select(OptionEntry)).all() == []
        assert session.scalars(select(SystemStateEntry)).all() == []


def test_unexposed_options_and_unloaded_extension_rows_are_inaccessible(
    setting_context,
):
    register_options(
        "setting_test",
        (
            OptionDefinition(
                "visible",
                1,
                int,
                1,
                setting=SettingMetadata("Visible", "Test setting."),
            ),
            OptionDefinition("hidden", 1, int, 2),
        ),
        owner="setting_test",
    )
    try:
        _, code, data = call(
            setting_context,
            settings.RequestGetSettingsHandler,
            {"namespace": "setting_test"},
        )
        assert code == 200
        assert set(data["settings"]) == {"visible"}
        with setting_context.Session.begin() as session:
            create_option(
                session,
                "setting_test",
                "hidden",
                schema_version=1,
                value=2,
                owner="setting_test",
            )
        for keys in (["hidden"], ["visible", "missing"]):
            _, code, data = call(
                setting_context,
                settings.RequestGetSettingsHandler,
                {"namespace": "setting_test", "keys": keys},
            )
            assert code == 404
        _, code, data = call(
            setting_context,
            settings.RequestUpdateSettingsHandler,
            {
                "namespace": "setting_test",
                "changes": {
                    "visible": {"value": 4, "expected_revision": 0},
                    "hidden": {"value": 5, "expected_revision": 1},
                },
            },
        )
        assert code == 404
        with setting_context.Session() as session:
            assert session.get(OptionEntry, ("setting_test", "visible")) is None
    finally:
        unregister_options("setting_test")
    assert describe_settings("setting_test") == []
    _, code, data = call(
        setting_context,
        settings.RequestGetSettingsHandler,
        {"namespace": "setting_test"},
    )
    assert code == 404


def test_batch_update_validates_final_policy_and_audits_revisions(setting_context):
    change = lambda value, revision=0: {"value": value, "expected_revision": revision}
    _, code, data = call(
        setting_context,
        settings.RequestUpdateSettingsHandler,
        {
            "namespace": "security.password",
            "changes": {"passwd_min_length": change(40)},
        },
    )
    assert code == 400
    with setting_context.Session() as session:
        assert session.scalars(select(OptionEntry)).all() == []
        assert session.scalars(select(SystemStateEntry)).all() == []
        assert session.scalars(select(AuditEntry)).all() == []
    result, code, data = call(
        setting_context,
        settings.RequestUpdateSettingsHandler,
        {
            "namespace": "security.password",
            "changes": {
                "passwd_min_length": change(40),
                "passwd_max_length": change(64),
            },
        },
    )
    assert code == 200
    assert set(data["settings"]) == {"passwd_min_length", "passwd_max_length"}
    assert data["settings"]["passwd_min_length"]["value"] == 40
    assert all(
        item["revision"] == 1 and item["updated_at"] > 0
        for item in data["settings"].values()
    )
    assert result.user_id == setting_context.users["admin"]
    assert result.target == "security.password"
    assert result.data == {
        "keys": ["passwd_max_length", "passwd_min_length"],
        "previous_revisions": {"passwd_min_length": 0, "passwd_max_length": 0},
        "revisions": {"passwd_min_length": 1, "passwd_max_length": 1},
    }
    with setting_context.Session() as session:
        audit = session.scalars(select(AuditEntry)).one()
        assert audit.data["source"] == "setting_api"
        assert set(audit.data) == {
            "source",
            "namespace",
            "previous_revisions",
            "revisions",
            "changed_keys",
        }
        assert session.get(OptionEntry, ("security.password", "passwd_rules")) is None
    _, code, data = call(
        setting_context,
        settings.RequestUpdateSettingsHandler,
        {
            "namespace": "security.password",
            "changes": {
                "passwd_min_length": change(41, 1),
                "passwd_max_length": change(65, 0),
            },
        },
    )
    assert code == 409
    _, _, data = call(
        setting_context,
        settings.RequestGetSettingsHandler,
        {"namespace": "security.password"},
    )
    assert data["settings"]["passwd_min_length"]["value"] == 40
    assert data["settings"]["passwd_max_length"]["revision"] == 1
    assert data["settings"]["passwd_rules"]["revision"] == 0


@pytest.mark.parametrize(
    ("namespace", "key", "initial", "replacement"),
    [
        ("security.password", "passwd_rules", ["[A-Z]", "[0-9]"], ["[a-z]"]),
        (
            "security.request_rate_control",
            "action_costs",
            {"first": 2, "second": 3},
            {"first": 4},
        ),
    ],
)
def test_structured_values_are_replaced_as_a_whole(
    setting_context, namespace, key, initial, replacement
):
    for revision, value in enumerate((initial, replacement)):
        _, code, data = call(
            setting_context,
            settings.RequestUpdateSettingsHandler,
            {
                "namespace": namespace,
                "changes": {key: {"value": value, "expected_revision": revision}},
            },
        )
        assert code == 200
        assert data["settings"][key]["value"] == value
        assert data["settings"][key]["revision"] == revision + 1


@pytest.mark.parametrize("value", [True, "10", 0, None])
def test_invalid_values_do_not_write(setting_context, value):
    _, code, _ = call(
        setting_context,
        settings.RequestUpdateSettingsHandler,
        {
            "namespace": "security.password",
            "changes": {"passwd_min_length": {"value": value, "expected_revision": 0}},
        },
    )
    assert code == 400
    with setting_context.Session() as session:
        assert session.scalars(select(OptionEntry)).all() == []


def test_invalid_stored_policy_is_a_server_error(setting_context):
    with setting_context.Session.begin() as session:
        create_option(session, "server", "name", schema_version=1, value=42)
    for handler_type, data in (
        (settings.RequestGetSettingsHandler, {"namespace": "server"}),
        (
            settings.RequestUpdateSettingsHandler,
            {
                "namespace": "server",
                "changes": {"name": {"value": "fixed", "expected_revision": 1}},
            },
        ),
    ):
        with pytest.raises(ConfigValidationError) as error:
            call(setting_context, handler_type, data)
        assert type(error.value) is ConfigValidationError


def test_failure_after_writing_rolls_back_options_guard_and_audit(setting_context):
    def reject_audit(connection, cursor, statement, parameters, context, executemany):
        if statement.startswith("INSERT INTO audit_entries"):
            raise RuntimeError("unavailable audit storage")

    event.listen(setting_context.engine, "before_cursor_execute", reject_audit)
    try:
        with pytest.raises(RuntimeError):
            call(
                setting_context,
                settings.RequestUpdateSettingsHandler,
                {
                    "namespace": "server",
                    "changes": {"name": {"value": "new", "expected_revision": 0}},
                },
            )
    finally:
        event.remove(setting_context.engine, "before_cursor_execute", reject_audit)
    with setting_context.Session() as session:
        assert session.scalars(select(OptionEntry)).all() == []
        assert session.scalars(select(SystemStateEntry)).all() == []
        assert session.scalars(select(AuditEntry)).all() == []


@pytest.mark.parametrize(
    ("handler_type", "data", "location"),
    [
        (
            settings.RequestGetSettingsHandler,
            {"namespace": "server", "keys": []},
            ("keys",),
        ),
        (
            settings.RequestGetSettingsHandler,
            {"namespace": "server", "keys": ["name", "name"]},
            ("keys",),
        ),
        (
            settings.RequestGetSettingsHandler,
            {"namespace": "server", "keys": None},
            ("keys",),
        ),
        (
            settings.RequestUpdateSettingsHandler,
            {"namespace": "server", "changes": {}},
            ("changes",),
        ),
        *[
            (
                settings.RequestUpdateSettingsHandler,
                {
                    "namespace": "server",
                    "changes": {
                        "name": {"value": "new", "expected_revision": revision}
                    },
                },
                ("changes", "name", "expected_revision"),
            )
            for revision in (-1, True, "0", 0.5)
        ],
    ],
)
def test_request_boundaries(handler_type, data, location):
    with pytest.raises(ValidationError) as error:
        handler_type.request_model.model_validate(data)
    assert error.value.errors()[0]["loc"][: len(location)] == location
