import sys

import pluggy
import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import sessionmaker

from include.config import options as option_config
from include.database.models.operations import AuditEntry, OptionEntry, SystemStateEntry
from include.database.session import Base
from include.extensions import manager
from include.runtime_lock import server_runtime_lock
from maintenance.operations import extensions as operations
from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.operations.extensions import data as extension_data
from maintenance.operations.extensions import lifecycle as extension_lifecycle

from .support import _enabled, _prepare_src, _write_installed_extension


@pytest.fixture
def purge_context(tmp_path, monkeypatch):
    src, root = _prepare_src(tmp_path, monkeypatch)
    monkeypatch.setattr(manager, "EXTENSION_ROOT", root)
    plugin_manager = pluggy.PluginManager("cfms")
    plugin_manager.add_hookspecs(manager.ServerHookSpecs)
    monkeypatch.setattr(manager, "pm", plugin_manager)
    monkeypatch.setattr(manager, "_loaded_extension_metadata", {})
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
    monkeypatch.setattr(extension_data, "Session", sessions)
    for owner in ("core", "sample_ext", "dependency", "brute_force_lockdown"):
        with sessions.begin() as session:
            session.add(
                OptionEntry(
                    owner=owner,
                    option_key="settings",
                    schema_version=1,
                    revision=1,
                    payload={"sentinel": owner},
                    updated_at=1.0,
                )
            )
            session.add(
                SystemStateEntry(
                    owner=owner,
                    state_key="state",
                    schema_version=1,
                    revision=1,
                    payload={"sentinel": owner},
                    updated_at=1.0,
                )
            )
    names = ("sample_ext", "dependency", "brute_force_lockdown")
    saved = {
        name: module
        for name, module in sys.modules.items()
        if any(name == owner or name.startswith(f"{owner}.") for owner in names)
    }
    yield src, root, sessions
    for name in tuple(sys.modules):
        if any(name == owner or name.startswith(f"{owner}.") for owner in names):
            sys.modules.pop(name, None)
    sys.modules.update(saved)
    engine.dispose()


def test_full_purge_runs_only_target_and_removes_only_its_owner(purge_context):
    src, root, sessions = purge_context
    dependency = _write_installed_extension(root, "dependency")
    dependency.joinpath("_extension.py").write_text(
        """
from include.extensions.manager import hookimpl

@hookimpl
def ext_purge_data(session):
    raise RuntimeError("dependency must not be purged")

@hookimpl
def ext_prepare_data(session):
    raise RuntimeError("maintenance must not prepare")

@hookimpl
def ext_on_startup():
    raise RuntimeError("maintenance must not start")
""",
        encoding="utf-8",
    )
    target = _write_installed_extension(
        root, "sample_ext", dependencies={"dependency": "1.0.0"}
    )
    target.joinpath("_extension.py").write_text(
        """
from include.extensions.manager import hookimpl

@hookimpl
def ext_purge_data(session):
    pass

@hookimpl
def ext_validate_config(config):
    raise RuntimeError("invalid runtime settings must not block cleanup")
""",
        encoding="utf-8",
    )
    result = operations.purge_extension_data("sample_ext", write=True)

    assert result.option_entries == result.state_entries == 1
    assert result.applied is True
    assert target.is_dir()
    assert _enabled(src) == ()
    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "settings")) is None
        assert session.get(SystemStateEntry, ("sample_ext", "state")) is None
        for owner in ("core", "dependency", "brute_force_lockdown"):
            assert session.get(OptionEntry, (owner, "settings")) is not None
            assert session.get(SystemStateEntry, (owner, "state")) is not None
        audit = session.scalars(select(AuditEntry)).one()
        assert audit.action == "purge_extension_data"
        assert audit.target == "sample_ext"
        assert audit.data == {
            "owner": "sample_ext",
            "options_only": False,
            "option_entries": 1,
            "state_entries": 1,
        }
    assert manager.pm.get_plugins() == set()


def test_options_only_purge_removes_owner_rows_without_importing_broken_code(
    purge_context,
):
    _, root, sessions = purge_context
    target = _write_installed_extension(root, "sample_ext")
    target.joinpath("_extension.py").write_text(
        "raise RuntimeError('broken')\n", encoding="utf-8"
    )
    root.joinpath("broken_manifest").mkdir()
    root.joinpath("broken_manifest", "manifest.toml").write_text(
        "broken = [", encoding="utf-8"
    )
    result = operations.purge_extension_data(
        "sample_ext", options_only=True, write=True
    )

    assert result.option_entries == 1
    assert result.state_entries == 1
    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "settings")) is None
        assert session.get(SystemStateEntry, ("sample_ext", "state")) is None
        assert session.get(SystemStateEntry, ("core", "state")) is not None


def test_options_only_purges_orphaned_options_without_installed_code(purge_context):
    _, _, sessions = purge_context
    result = operations.purge_extension_data(
        "sample_ext", options_only=True, write=True
    )
    repeated = operations.purge_extension_data(
        "sample_ext", options_only=True, write=True
    )

    assert result.option_entries == 1
    assert repeated.option_entries == 0
    with sessions() as session:
        assert session.get(SystemStateEntry, ("sample_ext", "state")) is None


def test_preview_never_executes_extension_code_or_deletes_rows(purge_context):
    _, root, sessions = purge_context
    target = _write_installed_extension(root, "sample_ext")
    target.joinpath("_extension.py").write_text(
        "raise RuntimeError('must not execute during preview')\n", encoding="utf-8"
    )
    result = operations.purge_extension_data("sample_ext", write=False)

    assert result.option_entries == result.state_entries == 1
    assert result.applied is False
    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "settings")) is not None
        assert session.get(SystemStateEntry, ("sample_ext", "state")) is not None
        assert session.scalars(select(AuditEntry)).all() == []


def test_failed_purge_hook_rolls_back_all_data_and_preserves_code(purge_context):
    _, root, sessions = purge_context
    target = _write_installed_extension(root, "sample_ext")
    target.joinpath("_extension.py").write_text(
        """
from include.database.models.operations import SystemStateEntry
from include.extensions.manager import hookimpl

@hookimpl
def ext_purge_data(session):
    session.get(SystemStateEntry, ("sample_ext", "state")).payload = {"changed": True}
    session.flush()
    raise RuntimeError("cleanup failed")
""",
        encoding="utf-8",
    )
    with pytest.raises(MaintenanceOperationError, match="rolled back") as error:
        operations.purge_extension_data("sample_ext", write=True)

    assert isinstance(error.value.__cause__, RuntimeError)
    assert target.is_dir()
    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "settings")) is not None
        assert session.get(SystemStateEntry, ("sample_ext", "state")).payload == {
            "sentinel": "sample_ext"
        }
        assert session.scalars(select(AuditEntry)).all() == []
    assert manager.pm.get_plugins() == set()


def test_missing_dependency_leaves_data_untouched_and_options_only_recovers(
    purge_context,
):
    _, root, sessions = purge_context
    _write_installed_extension(
        root, "sample_ext", dependencies={"missing_dependency": "1.0.0"}
    )
    with pytest.raises(MaintenanceOperationError, match="rolled back"):
        operations.purge_extension_data("sample_ext", write=True)
    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "settings")) is not None

    operations.purge_extension_data("sample_ext", options_only=True, write=True)
    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "settings")) is None


@pytest.mark.parametrize("identifier", ["core", "builtin"])
@pytest.mark.parametrize("options_only", [True, False])
def test_core_and_builtin_data_are_protected(purge_context, identifier, options_only):
    _, _, sessions = purge_context
    with pytest.raises(MaintenanceOperationError, match="cannot be purged"):
        operations.purge_extension_data(
            identifier, options_only=options_only, write=True
        )
    with sessions() as session:
        assert session.get(OptionEntry, ("core", "settings")) is not None
        assert session.get(SystemStateEntry, ("core", "state")) is not None


def test_enabled_target_must_be_disabled_before_purge(purge_context):
    _, root, sessions = purge_context
    _write_installed_extension(root, "sample_ext")
    operations.enable_extension("sample_ext", write=True)

    with pytest.raises(MaintenanceOperationError, match="Disable extension"):
        operations.purge_extension_data("sample_ext", write=True)

    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "settings")) is not None


def test_running_server_lock_blocks_purge(purge_context):
    src, _, sessions = purge_context
    with (
        server_runtime_lock(src),
        pytest.raises(MaintenanceOperationError, match="already using"),
    ):
        operations.purge_extension_data("sample_ext", options_only=True, write=True)

    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "settings")) is not None


def test_uninstall_with_purge_removes_data_before_code(purge_context):
    _, root, sessions = purge_context
    target = _write_installed_extension(root, "sample_ext")
    result = operations.uninstall_extension("sample_ext", purge_data=True, write=True)

    assert result.data_purge.option_entries == result.data_purge.state_entries == 1
    assert not target.exists()
    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "settings")) is None
        assert session.get(SystemStateEntry, ("sample_ext", "state")) is None


def test_uninstall_with_purge_disables_dependents_and_preserves_their_data(
    purge_context,
):
    src, root, sessions = purge_context
    target = _write_installed_extension(root, "sample_ext")
    _write_installed_extension(root, "dependency", dependencies={"sample_ext": "1.0.0"})
    operations.enable_extension("dependency", write=True)
    preview = operations.uninstall_extension("sample_ext", purge_data=True, write=False)
    assert preview.enabled_removed == ("sample_ext", "dependency")
    assert _enabled(src) == ("sample_ext", "dependency")

    result = operations.uninstall_extension("sample_ext", purge_data=True, write=True)

    assert result.enabled_removed == ("sample_ext", "dependency")
    assert _enabled(src) == ()
    assert not target.exists()
    assert root.joinpath("dependency").is_dir()
    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "settings")) is None
        assert session.get(OptionEntry, ("dependency", "settings")) is not None
        assert session.get(SystemStateEntry, ("dependency", "state")) is not None


def test_failed_combined_cleanup_keeps_disables_and_code_for_retry(purge_context):
    src, root, sessions = purge_context
    target = _write_installed_extension(root, "sample_ext")
    target.joinpath("_extension.py").write_text(
        "raise RuntimeError('broken')\n", encoding="utf-8"
    )
    operations.enable_extension("sample_ext", write=True)

    with pytest.raises(
        MaintenanceOperationError, match="cleanup failed and code was preserved"
    ):
        operations.uninstall_extension("sample_ext", purge_data=True, write=True)

    assert _enabled(src) == ()
    assert target.is_dir()
    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "settings")) is not None
    target.joinpath("_extension.py").write_text("VALUE = 1\n", encoding="utf-8")
    operations.uninstall_extension("sample_ext", purge_data=True, write=True)
    assert not target.exists()


def test_failed_purge_prevents_uninstall_from_removing_code(purge_context):
    _, root, sessions = purge_context
    target = _write_installed_extension(root, "sample_ext")
    target.joinpath("_extension.py").write_text(
        "raise RuntimeError('broken')\n", encoding="utf-8"
    )
    with pytest.raises(MaintenanceOperationError, match="rolled back"):
        operations.uninstall_extension("sample_ext", purge_data=True, write=True)

    assert target.is_dir()
    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "settings")) is not None


def test_code_removal_failure_after_purge_is_reported_and_can_be_retried(
    purge_context, monkeypatch
):
    src, root, sessions = purge_context
    target = _write_installed_extension(root, "sample_ext")
    target.joinpath("_extension.py").write_text(
        """
from include.database.models.operations import SystemStateEntry
from include.extensions.manager import hookimpl

@hookimpl
def ext_purge_data(session):
    state = session.get(SystemStateEntry, ("sample_ext", "state"))
    if state is not None:
        session.delete(state)
""",
        encoding="utf-8",
    )
    original_replace = extension_lifecycle.os.replace

    def fail_replace(source, destination):
        raise OSError("simulated rename failure")

    monkeypatch.setattr(extension_lifecycle.os, "replace", fail_replace)
    with pytest.raises(MaintenanceOperationError, match="data purge already committed"):
        operations.uninstall_extension("sample_ext", purge_data=True, write=True)

    assert target.is_dir()
    assert _enabled(src) == ()
    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "settings")) is None
        assert session.get(SystemStateEntry, ("sample_ext", "state")) is None
    monkeypatch.setattr(extension_lifecycle.os, "replace", original_replace)
    operations.uninstall_extension("sample_ext", purge_data=True, write=True)
    assert not target.exists()
    with sessions() as session:
        assert len(session.scalars(select(AuditEntry)).all()) == 2


def test_packaged_extension_can_purge_data_but_cannot_uninstall(purge_context):
    src, root, sessions = purge_context
    _write_installed_extension(root, "brute_force_lockdown")
    src.parent.joinpath("release-manifest.json").write_text(
        '{"managed_extensions": ["builtin", "brute_force_lockdown"]}', encoding="utf-8"
    )
    operations.purge_extension_data("brute_force_lockdown", write=True)
    with pytest.raises(MaintenanceOperationError, match="cannot be uninstalled"):
        operations.uninstall_extension(
            "brute_force_lockdown", purge_data=True, write=True
        )

    with sessions() as session:
        assert session.get(OptionEntry, ("brute_force_lockdown", "settings")) is None
        assert session.get(SystemStateEntry, ("core", "state")) is not None


def test_default_disable_and_uninstall_preserve_data_without_importing_code(
    purge_context,
):
    _, root, sessions = purge_context
    target = _write_installed_extension(root, "sample_ext")
    target.joinpath("_extension.py").write_text(
        "raise RuntimeError('must not execute')\n", encoding="utf-8"
    )
    operations.enable_extension("sample_ext", write=True)
    operations.disable_extension("sample_ext", write=True)
    operations.uninstall_extension("sample_ext", write=True)

    with sessions() as session:
        assert session.get(OptionEntry, ("sample_ext", "settings")) is not None
        assert session.get(SystemStateEntry, ("sample_ext", "state")) is not None
