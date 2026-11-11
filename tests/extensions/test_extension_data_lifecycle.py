import builtins
import sys

import pluggy
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from include.config import options as option_config
from include.database.models.operations import OptionEntry, SystemStateEntry
from include.database.session import Base
from include.extensions import manager
from tests.maintenance.extensions.support import (
    _prepare_src,
    _write_installed_extension,
)

OPTION_DECLARATION = """
from include.config.options import OptionDefinition
from include.extensions.manager import hookimpl

OPTIONS = OptionDefinition("threshold", 1, int, 7)

@hookimpl
def ext_register_options():
    return {__name__: (OPTIONS,)}
"""


@pytest.fixture
def extension_data_context(tmp_path, monkeypatch):
    src, root = _prepare_src(tmp_path, monkeypatch)
    monkeypatch.setattr(manager, "EXTENSION_ROOT", root)
    plugin_manager = pluggy.PluginManager("cfms")
    plugin_manager.add_hookspecs(manager.ServerHookSpecs)
    monkeypatch.setattr(manager, "pm", plugin_manager)
    monkeypatch.setattr(manager, "_loaded_extension_metadata", {})
    monkeypatch.setattr(manager, "_loaded_extension_order", ())
    monkeypatch.setattr(manager, "_started_extensions", [])
    monkeypatch.setattr(
        option_config,
        "_option_definitions",
        {
            ("server", "name"): option_config.SERVER_NAME_OPTION,
        },
    )
    monkeypatch.setattr(option_config, "_option_validators", {})
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    sessions = sessionmaker(bind=engine)
    monkeypatch.setattr(manager, "Session", sessions)
    events = []
    monkeypatch.setattr(builtins, "_cfms_lifecycle_events", events, raising=False)
    names = ("builtin", "sample_ext", "dependency", "consumer")
    original_modules = {
        name: module
        for name, module in sys.modules.items()
        if any(name == owner or name.startswith(f"{owner}.") for owner in names)
    }
    yield src, root, sessions, events
    for name in tuple(sys.modules):
        if any(name == owner or name.startswith(f"{owner}.") for owner in names):
            sys.modules.pop(name, None)
    sys.modules.update(original_modules)
    engine.dispose()


pytestmark = pytest.mark.component


def test_setting_metadata_follows_extension_registration_and_rollback(
    extension_data_context,
):
    _, root, _, _ = extension_data_context
    target = _write_installed_extension(root, "sample_ext")
    declaration = OPTION_DECLARATION.replace(
        "import OptionDefinition", "import OptionDefinition, SettingMetadata"
    ).replace(
        'OptionDefinition("threshold", 1, int, 7)',
        'OptionDefinition("threshold", 1, int, 7, setting=SettingMetadata("Threshold", "Applies to subsequent decisions."))',
    )
    target.joinpath("_extension.py").write_text(declaration, encoding="utf-8")
    assert option_config.describe_settings("sample_ext") == []
    with manager.maintenance_extension_context("sample_ext"):
        (item,) = option_config.describe_settings("sample_ext")
        assert item["owner"] == "sample_ext"
        assert item["default"] == 7
        assert item["value_schema"] == {"type": "integer"}
    assert option_config.describe_settings("sample_ext") == []
    target.joinpath("_extension.py").write_text(
        declaration
        + '\n@hookimpl\ndef ext_register_options():\n    return {"sample_ext": (OPTIONS, OPTIONS)}\n',
        encoding="utf-8",
    )
    with (
        pytest.raises(manager.ExtensionLoadError),
        manager.maintenance_extension_context("sample_ext"),
    ):
        pytest.fail("Duplicate definitions must prevent extension registration")
    assert option_config.describe_settings("sample_ext") == []
    assert not manager.pm.has_plugin("sample_ext")


def test_maintenance_load_registers_disabled_options_without_validation_or_startup(
    extension_data_context,
):
    _, root, sessions, _ = extension_data_context
    target = _write_installed_extension(
        root, "sample_ext", dependencies={"dependency": "1.0.0"}
    )
    dependency = _write_installed_extension(root, "dependency")
    dependency.joinpath("_extension.py").write_text(
        "VALUE = 'dependency available'\n", encoding="utf-8"
    )
    target.joinpath("_extension.py").write_text(
        OPTION_DECLARATION
        + """
import dependency

@hookimpl
def ext_validate_config(config):
    raise RuntimeError("invalid settings must not block maintenance")

@hookimpl
def ext_prepare_data(session):
    raise RuntimeError("maintenance must not prepare")

@hookimpl
def ext_on_startup():
    raise RuntimeError("maintenance must not start")
""",
        encoding="utf-8",
    )

    with manager.maintenance_extension_context("sample_ext") as plugin:
        definition = option_config.get_option_definition("sample_ext", "threshold")
        assert plugin.dependency.VALUE == "dependency available"
        with sessions() as session:
            assert (
                option_config.read_option(session, "sample_ext", definition).value == 7
            )
            assert session.get(OptionEntry, ("sample_ext", "threshold")) is None
        assert manager.pm.has_plugin("dependency")

    assert not manager.pm.has_plugin("sample_ext")
    assert not manager.pm.has_plugin("dependency")
    assert option_config.iter_options("sample_ext") == ()


def test_maintenance_load_preserves_preexisting_registration(extension_data_context):
    _, root, _, _ = extension_data_context
    target = _write_installed_extension(
        root, "sample_ext", dependencies={"dependency": "1.0.0"}
    )
    _write_installed_extension(root, "dependency")
    target.joinpath("_extension.py").write_text(OPTION_DECLARATION, encoding="utf-8")
    existing = object()
    manager.pm.register(existing, "dependency")

    with manager.maintenance_extension_context("sample_ext"):
        assert manager.pm.get_plugin("dependency") is existing

    assert manager.pm.get_plugin("dependency") is existing
    assert option_config.iter_options("sample_ext") == ()


def test_maintenance_import_failure_removes_temporary_declarations_and_submodules(
    extension_data_context,
):
    _, root, _, _ = extension_data_context
    dependency = _write_installed_extension(root, "dependency")
    dependency.joinpath("_extension.py").write_text(
        OPTION_DECLARATION + "\nfrom . import helper\n", encoding="utf-8"
    )
    dependency.joinpath("helper.py").write_text("VALUE = 1\n", encoding="utf-8")
    target = _write_installed_extension(
        root, "sample_ext", dependencies={"dependency": "1.0.0"}
    )
    target.joinpath("_extension.py").write_text(
        "raise RuntimeError('broken')\n", encoding="utf-8"
    )

    with (
        pytest.raises(manager.ExtensionLoadError, match="sample_ext"),
        manager.maintenance_extension_context("sample_ext"),
    ):
        pytest.fail("failed load must not enter maintenance body")

    assert manager.pm.get_plugins() == set()
    assert option_config.iter_options("dependency") == ()
    assert "dependency.helper" not in sys.modules


def test_prepare_defaults_does_not_replace_existing_options(extension_data_context):
    _, root, sessions, _ = extension_data_context
    target = _write_installed_extension(root, "sample_ext")
    target.joinpath("_extension.py").write_text(
        OPTION_DECLARATION.replace(
            "return {__name__: (OPTIONS,)}",
            'return {__name__: (OPTIONS, OptionDefinition("enabled", 1, bool, True))}',
        ),
        encoding="utf-8",
    )
    manager.load_extensions_from_directory(root, ["sample_ext"], config={})
    manager.prepare_extension_data()
    with sessions.begin() as session:
        entry = session.get(OptionEntry, ("sample_ext", "threshold"))
        assert entry.option_value == "7"
        option_config.write_options(
            session,
            "sample_ext",
            {"threshold": 19},
            expected_revisions={"threshold": 1},
        )
    with sessions() as session:
        before = session.execute(
            select(OptionEntry.__table__)
            .where(OptionEntry.owner == "sample_ext")
            .order_by(OptionEntry.option_key)
        ).all()
    manager.prepare_extension_data()
    manager.prepare_extension_data()

    with sessions() as session:
        entry = session.get(OptionEntry, ("sample_ext", "threshold"))
        assert entry.option_value == "19"
        assert entry.revision == 2
        enabled = session.get(OptionEntry, ("sample_ext", "enabled"))
        assert enabled.option_value == "1"
        assert enabled.revision == 1
        assert (
            session.execute(
                select(OptionEntry.__table__)
                .where(OptionEntry.owner == "sample_ext")
                .order_by(OptionEntry.option_key)
            ).all()
            == before
        )


@pytest.mark.parametrize(
    "validator_declaration",
    [
        "@hookimpl\ndef ext_validate_options(values):",
        '@hookimpl(specname="ext_validate_options")\ndef validate_settings(values):',
        (
            '@hookimpl(specname="ext_validate_options", wrapper=True)\n'
            "def validate_settings(values):\n"
            "    yield"
        ),
    ],
    ids=["canonical", "alias", "wrapper"],
)
def test_prepare_validates_final_aggregate_and_rolls_back_owner_changes(
    extension_data_context, validator_declaration
):
    _, root, sessions, events = extension_data_context
    target = _write_installed_extension(root, "sample_ext")
    target.joinpath("_extension.py").write_text(
        """
import builtins
from include.config.options import ConfigValidationError, OptionDefinition
from include.database.models.operations import OptionEntry, SystemStateEntry
from include.extensions.manager import hookimpl

@hookimpl
def ext_register_options():
    return {__name__: (
        OptionDefinition("threshold", 1, int, 7),
        OptionDefinition("ceiling", 1, int, 12),
    )}

@hookimpl
def ext_prepare_data(session):
    entry = session.get(OptionEntry, ("sample_ext", "threshold"))
    entry.option_value = "20"
    entry.revision = 6
    session.add(SystemStateEntry(owner="sample_ext", state_key="prepared",
        schema_version=1, revision=1, payload={"done": True}, updated_at=2.0))
    builtins._cfms_lifecycle_events.append("prepared")

"""
        + validator_declaration
        + """
    if values["threshold"] > values["ceiling"]:
        raise ConfigValidationError("threshold exceeds ceiling")
""",
        encoding="utf-8",
    )
    with sessions.begin() as session:
        session.add(
            OptionEntry(
                namespace="sample_ext",
                owner="sample_ext",
                option_key="threshold",
                schema_version=1,
                revision=5,
                value_type="int",
                option_value="3",
                updated_at=1.0,
            )
        )
    manager.load_extensions_from_directory(root, ["sample_ext"], config={})

    with pytest.raises(manager.ExtensionLoadError, match="prepare") as error:
        manager.prepare_extension_data()

    assert isinstance(error.value.__cause__, option_config.ConfigValidationError)
    assert "threshold exceeds ceiling" in str(error.value.__cause__)
    assert events == ["prepared"]
    with sessions() as session:
        existing = session.get(OptionEntry, ("sample_ext", "threshold"))
        assert existing.option_value == "3"
        assert existing.revision == 5
        assert existing.updated_at == 1.0
        assert session.get(OptionEntry, ("sample_ext", "ceiling")) is None
        assert session.get(SystemStateEntry, ("sample_ext", "prepared")) is None
        assert (
            session.get(SystemStateEntry, ("core", "options_revision.sample_ext"))
            is None
        )


def test_prepare_rejects_invalid_raw_scalar_and_rolls_back_defaults(
    extension_data_context,
):
    _, root, sessions, events = extension_data_context
    target = _write_installed_extension(root, "sample_ext")
    target.joinpath("_extension.py").write_text(
        OPTION_DECLARATION
        + """
import builtins
from include.database.models.operations import OptionEntry, SystemStateEntry

@hookimpl
def ext_prepare_data(session):
    session.get(OptionEntry, ("sample_ext", "threshold")).option_value = "invalid integer"
    session.add(SystemStateEntry(owner="sample_ext", state_key="prepared",
        schema_version=1, revision=1, payload={}, updated_at=1.0))
    builtins._cfms_lifecycle_events.append("prepared")
""",
        encoding="utf-8",
    )
    manager.load_extensions_from_directory(root, ["sample_ext"], config={})

    with pytest.raises(manager.ExtensionLoadError, match="prepare"):
        manager.prepare_extension_data()

    assert events == ["prepared"]
    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "threshold")) is None
        assert session.get(SystemStateEntry, ("sample_ext", "prepared")) is None
        assert (
            session.get(SystemStateEntry, ("core", "options_revision.sample_ext"))
            is None
        )


def test_later_owner_prepare_failure_preserves_completed_dependency(
    extension_data_context,
):
    _, root, sessions, _ = extension_data_context
    dependency = _write_installed_extension(root, "dependency")
    dependency.joinpath("_extension.py").write_text(
        OPTION_DECLARATION
        + """
from include.database.models.operations import SystemStateEntry

@hookimpl
def ext_prepare_data(session):
    session.add(SystemStateEntry(owner="dependency", state_key="prepared",
        schema_version=1, revision=1, payload={"done": True}, updated_at=1.0))
""",
        encoding="utf-8",
    )
    consumer = _write_installed_extension(
        root, "consumer", dependencies={"dependency": "1.0.0"}
    )
    consumer.joinpath("_extension.py").write_text(
        OPTION_DECLARATION
        + """
from include.database.models.operations import SystemStateEntry

@hookimpl
def ext_prepare_data(session):
    session.add(SystemStateEntry(owner="consumer", state_key="prepared",
        schema_version=1, revision=1, payload={}, updated_at=1.0))
    raise RuntimeError("consumer prepare failed")
""",
        encoding="utf-8",
    )
    manager.load_extensions_from_directory(root, ["consumer", "dependency"], config={})

    with pytest.raises(manager.ExtensionLoadError, match="consumer"):
        manager.prepare_extension_data()

    with sessions() as session:
        dependency_option = session.get(OptionEntry, ("dependency", "threshold"))
        assert dependency_option.option_value == "7"
        assert dependency_option.revision == 1
        assert session.get(SystemStateEntry, ("dependency", "prepared")).payload == {
            "done": True
        }
        assert (
            session.get(SystemStateEntry, ("core", "options_revision.dependency"))
            is not None
        )
        assert session.get(OptionEntry, ("consumer", "threshold")) is None
        assert session.get(SystemStateEntry, ("consumer", "prepared")) is None
        assert (
            session.get(SystemStateEntry, ("core", "options_revision.consumer")) is None
        )


def test_failed_prepare_rolls_back_defaults_and_extension_data(extension_data_context):
    _, root, sessions, _ = extension_data_context
    target = _write_installed_extension(root, "sample_ext")
    target.joinpath("_extension.py").write_text(
        OPTION_DECLARATION
        + """
from include.database.models.operations import SystemStateEntry

@hookimpl
def ext_prepare_data(session):
    session.add(SystemStateEntry(owner="sample_ext", state_key="prepared", schema_version=1,
        revision=1, payload={}, updated_at=1.0))
    raise RuntimeError("prepare failed")
""",
        encoding="utf-8",
    )
    manager.load_extensions_from_directory(root, ["sample_ext"], config={})

    with pytest.raises(manager.ExtensionLoadError, match="prepare") as error:
        manager.prepare_extension_data()

    assert isinstance(error.value.__cause__, RuntimeError)
    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "threshold")) is None
        assert session.get(SystemStateEntry, ("sample_ext", "prepared")) is None
        assert (
            session.get(SystemStateEntry, ("core", "options_revision.sample_ext"))
            is None
        )


def test_prepare_rejects_unknown_existing_option_schema(extension_data_context):
    _, root, sessions, _ = extension_data_context
    target = _write_installed_extension(root, "sample_ext")
    target.joinpath("_extension.py").write_text(OPTION_DECLARATION, encoding="utf-8")
    manager.load_extensions_from_directory(root, ["sample_ext"], config={})
    with sessions.begin() as session:
        session.add(
            OptionEntry(
                namespace="sample_ext",
                owner="sample_ext",
                option_key="threshold",
                schema_version=2,
                revision=1,
                option_value="19",
                value_type="int",
                updated_at=1.0,
            )
        )

    with pytest.raises(manager.ExtensionLoadError, match="prepare"):
        manager.prepare_extension_data()

    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "threshold")).schema_version == 2


def test_dependency_order_controls_prepare_start_and_reverse_shutdown(
    extension_data_context,
):
    _, root, _, events = extension_data_context
    dependency = _write_installed_extension(root, "dependency")
    consumer = _write_installed_extension(
        root, "consumer", dependencies={"dependency": "1.0.0"}
    )
    for name, directory in (("dependency", dependency), ("consumer", consumer)):
        directory.joinpath("_extension.py").write_text(
            f"""
import builtins
from include.extensions.manager import hookimpl

@hookimpl
def ext_prepare_data(session):
    builtins._cfms_lifecycle_events.append("prepare:{name}")

@hookimpl
def ext_on_startup():
    builtins._cfms_lifecycle_events.append("start:{name}")

@hookimpl
def ext_on_shutdown():
    builtins._cfms_lifecycle_events.append("stop:{name}")
""",
            encoding="utf-8",
        )
    manager.load_extensions_from_directory(root, ["consumer", "dependency"], config={})
    manager.prepare_extension_data()
    manager.start_extensions(object())
    manager.shutdown_extensions()
    manager.shutdown_extensions()

    assert events == [
        "prepare:dependency",
        "prepare:consumer",
        "start:dependency",
        "start:consumer",
        "stop:consumer",
        "stop:dependency",
    ]


def test_shutdown_attempts_other_extensions_after_failure(extension_data_context):
    _, root, _, events = extension_data_context
    dependency = _write_installed_extension(root, "dependency")
    consumer = _write_installed_extension(
        root, "consumer", dependencies={"dependency": "1.0.0"}
    )
    dependency.joinpath("_extension.py").write_text(
        """
import builtins
from include.extensions.manager import hookimpl

@hookimpl
def ext_on_shutdown():
    builtins._cfms_lifecycle_events.append("dependency stopped")
""",
        encoding="utf-8",
    )
    consumer.joinpath("_extension.py").write_text(
        """
import builtins
from include.extensions.manager import hookimpl

@hookimpl
def ext_on_shutdown():
    builtins._cfms_lifecycle_events.append("consumer stop failed")
    raise RuntimeError("stop failed")
""",
        encoding="utf-8",
    )
    manager.load_extensions_from_directory(root, ["consumer", "dependency"], config={})
    manager.start_extensions(object())

    with pytest.raises(ExceptionGroup, match="shutdown") as error:
        manager.shutdown_extensions()

    assert events == ["consumer stop failed", "dependency stopped"]
    assert len(error.value.exceptions) == 1
    assert isinstance(error.value.exceptions[0], RuntimeError)


def test_startup_failure_cleans_attempted_targets_in_reverse_order(
    extension_data_context,
):
    _, root, _, events = extension_data_context
    target = _write_installed_extension(root, "sample_ext")
    target.joinpath("_extension.py").write_text(
        """
import builtins
from include.extensions.manager import hookimpl

@hookimpl
def ext_on_startup():
    raise RuntimeError("startup failed")

@hookimpl
def ext_on_shutdown():
    builtins._cfms_lifecycle_events.append("failed target cleaned")
""",
        encoding="utf-8",
    )
    manager.load_extensions_from_directory(root, ["sample_ext"], config={})
    with pytest.raises(manager.ExtensionLoadError, match="start"):
        manager.start_extensions(object())
    manager.shutdown_extensions()

    assert events == ["failed target cleaned"]
