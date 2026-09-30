import builtins
import sys

import pluggy
import pytest
from sqlalchemy import create_engine
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
from pydantic import BaseModel, ConfigDict
from include.config.options import OptionGroupDefinition
from include.extensions.manager import hookimpl

class Settings(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid")
    threshold: int = 7

OPTIONS = OptionGroupDefinition("settings", 1, Settings)

@hookimpl
def ext_register_options():
    return (OPTIONS,)
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
        "_option_groups",
        {
            ("core", "server"): option_config.CORE_SERVER_OPTIONS,
        },
    )
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
        definition = option_config.get_option_group("sample_ext", "settings")
        assert plugin.dependency.VALUE == "dependency available"
        with sessions() as session:
            assert (
                option_config.read_options(
                    session, "sample_ext", definition
                ).value.threshold
                == 7
            )
            assert session.get(OptionEntry, ("sample_ext", "settings")) is None
        assert manager.pm.has_plugin("dependency")

    assert not manager.pm.has_plugin("sample_ext")
    assert not manager.pm.has_plugin("dependency")
    assert option_config.iter_option_groups("sample_ext") == ()


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
    assert option_config.iter_option_groups("sample_ext") == ()


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
    assert option_config.iter_option_groups("dependency") == ()
    assert "dependency.helper" not in sys.modules


def test_prepare_defaults_does_not_replace_existing_options(extension_data_context):
    _, root, sessions, _ = extension_data_context
    target = _write_installed_extension(root, "sample_ext")
    target.joinpath("_extension.py").write_text(OPTION_DECLARATION, encoding="utf-8")
    manager.load_extensions_from_directory(root, ["sample_ext"], config={})
    manager.prepare_extension_data()
    with sessions.begin() as session:
        entry = session.get(OptionEntry, ("sample_ext", "settings"))
        assert entry.payload == {"threshold": 7}
        entry.payload = {"threshold": 19}
        entry.revision = 2
    manager.prepare_extension_data()

    with sessions() as session:
        entry = session.get(OptionEntry, ("sample_ext", "settings"))
        assert entry.payload == {"threshold": 19}
        assert entry.revision == 2


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
        assert session.get(OptionEntry, ("sample_ext", "settings")) is None
        assert session.get(SystemStateEntry, ("sample_ext", "prepared")) is None


def test_prepare_rejects_unknown_existing_option_schema(extension_data_context):
    _, root, sessions, _ = extension_data_context
    target = _write_installed_extension(root, "sample_ext")
    target.joinpath("_extension.py").write_text(OPTION_DECLARATION, encoding="utf-8")
    manager.load_extensions_from_directory(root, ["sample_ext"], config={})
    with sessions.begin() as session:
        session.add(
            OptionEntry(
                owner="sample_ext",
                option_key="settings",
                schema_version=2,
                revision=1,
                payload={"threshold": 19},
                updated_at=1.0,
            )
        )

    with pytest.raises(manager.ExtensionLoadError, match="prepare"):
        manager.prepare_extension_data()

    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "settings")).schema_version == 2


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
