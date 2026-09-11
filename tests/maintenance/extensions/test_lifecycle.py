import pytest
import tomlkit

import maintenance.operations.extensions as extension_operations
from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.operations.extensions import lifecycle as extension_lifecycle

from .support import _enabled, _prepare_src, _write_installed_extension, _write_package


def test_enable_adds_dependencies_and_disable_cascades_to_dependents(
    tmp_path, monkeypatch
):
    src, root = _prepare_src(tmp_path, monkeypatch)
    _write_installed_extension(root, "dependency")
    _write_installed_extension(root, "consumer", dependencies={"dependency": "1.0.0"})
    _write_installed_extension(root, "unrelated")

    enabled = extension_operations.enable_extension("consumer", write=True)

    assert enabled.enabled_added == ("dependency", "consumer")
    assert _enabled(src) == ("dependency", "consumer")
    assert enabled.config_backup_path is not None

    extension_operations.enable_extension("unrelated", write=True)
    disabled = extension_operations.disable_extension("dependency", write=True)

    assert disabled.enabled_removed == ("dependency", "consumer")
    assert _enabled(src) == ("unrelated",)
    assert disabled.config_backup_path is not None


def test_enable_is_idempotent_without_creating_a_backup(tmp_path, monkeypatch):
    src, root = _prepare_src(tmp_path, monkeypatch, enabled=("sample_ext",))
    _write_installed_extension(root, "sample_ext")

    result = extension_operations.enable_extension("sample_ext", write=True)

    assert result.changed is False
    assert result.config_backup_path is None
    assert list(src.glob("config.toml.backup-*")) == []


def test_enable_rejects_missing_low_version_cycles_and_core_incompatibility(
    tmp_path, monkeypatch
):
    _, root = _prepare_src(tmp_path, monkeypatch)
    _write_installed_extension(
        root, "missing_consumer", dependencies={"missing_dependency": "1.0.0"}
    )
    _write_installed_extension(root, "old_dependency", version="1.0.0")
    _write_installed_extension(
        root, "version_consumer", dependencies={"old_dependency": "2.0.0"}
    )
    _write_installed_extension(root, "cycle_a", dependencies={"cycle_b": "1.0.0"})
    _write_installed_extension(root, "cycle_b", dependencies={"cycle_a": "1.0.0"})
    _write_installed_extension(root, "future_ext", minimum_server_version="99.0.0")

    with pytest.raises(MaintenanceOperationError, match="not installed"):
        extension_operations.enable_extension("missing_consumer")
    with pytest.raises(MaintenanceOperationError, match="2.0.0 or newer"):
        extension_operations.enable_extension("version_consumer")
    with pytest.raises(
        MaintenanceOperationError, match="cycle_a -> cycle_b -> cycle_a"
    ):
        extension_operations.enable_extension("cycle_a")
    with pytest.raises(
        MaintenanceOperationError, match="requires server version 99.0.0"
    ):
        extension_operations.enable_extension("future_ext")


def test_upgrade_is_strict_preserves_directory_and_enables_new_dependencies(
    tmp_path, monkeypatch
):
    src, root = _prepare_src(tmp_path, monkeypatch, enabled=("sample_ext",))
    installed = _write_installed_extension(
        root,
        "sample_ext",
        directory_name="stable_folder_name",
        version="1.0.0",
    )
    _write_installed_extension(root, "dependency")
    package = _write_package(
        tmp_path / "upgrade.zip",
        version="2.0.0",
        dependencies={"dependency": "1.0.0"},
    )

    preview = extension_operations.upgrade_extension(package, write=False)
    assert preview.enabled_added == ("dependency",)

    result = extension_operations.upgrade_extension(
        package, expected_sha256=preview.package_sha256, write=True
    )

    assert result.extension.directory == installed
    assert "must not execute" in (installed / "_extension.py").read_text("utf-8")
    assert _enabled(src) == ("sample_ext", "dependency")
    assert result.config_backup_path is not None
    assert list(root.glob(".cfms-extension-*")) == []


def test_upgrade_restores_old_code_when_config_update_fails(tmp_path, monkeypatch):
    _, root = _prepare_src(tmp_path, monkeypatch, enabled=("sample_ext",))
    installed = _write_installed_extension(root, "sample_ext", version="1.0.0")
    _write_installed_extension(root, "dependency")
    package = _write_package(
        tmp_path / "upgrade-failure.zip",
        version="2.0.0",
        dependencies={"dependency": "1.0.0"},
    )

    def fail_config_update(*_args):
        raise MaintenanceOperationError("simulated config failure")

    monkeypatch.setattr(
        extension_lifecycle, "write_config_atomically", fail_config_update
    )

    with pytest.raises(MaintenanceOperationError, match="simulated config failure"):
        extension_operations.upgrade_extension(package, write=True)

    assert 'EXTENSION_VERSION = "1.0.0"' in (installed / "_extension.py").read_text(
        encoding="utf-8"
    )
    assert list(root.glob(".cfms-extension-*")) == []


@pytest.mark.parametrize("version", ["1.0.0", "0.9.0"])
def test_upgrade_rejects_same_version_and_downgrade(tmp_path, monkeypatch, version):
    _, root = _prepare_src(tmp_path, monkeypatch)
    _write_installed_extension(root, "sample_ext", version="1.0.0")
    package = _write_package(tmp_path / "replacement.zip", version=version)

    with pytest.raises(MaintenanceOperationError, match="newer than 1.0.0"):
        extension_operations.upgrade_extension(package, write=False)


def test_upgrade_rejects_incomparable_manifest_v2_versions(tmp_path, monkeypatch):
    _, root = _prepare_src(tmp_path, monkeypatch)
    _write_installed_extension(root, "sample_ext", version="release-one")
    package = _write_package(tmp_path / "replacement.zip", version="2.0.0")

    with pytest.raises(MaintenanceOperationError, match="PEP 440-comparable"):
        extension_operations.upgrade_extension(package, write=False)


def test_uninstall_disables_dependents_and_preserves_configuration_and_database(
    tmp_path, monkeypatch
):
    src, root = _prepare_src(tmp_path, monkeypatch, enabled=("dependency", "consumer"))
    _write_installed_extension(root, "dependency")
    _write_installed_extension(root, "consumer", dependencies={"dependency": "1.0.0"})
    config = tomlkit.parse((src / "config.toml").read_text(encoding="utf-8"))
    config["extensions"]["dependency"] = {"setting": "preserve-me"}
    (src / "config.toml").write_text(tomlkit.dumps(config), encoding="utf-8")
    database = src / "app.db"
    database.write_bytes(b"database sentinel")

    result = extension_operations.uninstall_extension("dependency", write=True)

    assert result.enabled_removed == ("dependency", "consumer")
    assert not (root / "dependency").exists()
    assert (root / "consumer").is_dir()
    updated = tomlkit.parse((src / "config.toml").read_text(encoding="utf-8"))
    assert updated["extensions"]["dependency"]["setting"] == "preserve-me"
    assert tuple(updated["extensions"]["enabled"]) == ()
    assert database.read_bytes() == b"database sentinel"


def test_uninstall_restores_code_when_config_update_fails(tmp_path, monkeypatch):
    _, root = _prepare_src(tmp_path, monkeypatch, enabled=("sample_ext",))
    installed = _write_installed_extension(root, "sample_ext")

    def fail_config_update(*_args):
        raise MaintenanceOperationError("simulated config failure")

    monkeypatch.setattr(
        extension_lifecycle, "write_config_atomically", fail_config_update
    )

    with pytest.raises(MaintenanceOperationError, match="simulated config failure"):
        extension_operations.uninstall_extension("sample_ext", write=True)

    assert installed.is_dir()
    assert list(root.glob(".cfms-extension-*")) == []


def test_builtin_is_immutable_and_stale_transactions_block_mutations(
    tmp_path, monkeypatch
):
    _, root = _prepare_src(tmp_path, monkeypatch)

    with pytest.raises(MaintenanceOperationError, match="always enabled"):
        extension_operations.disable_extension("builtin")
    with pytest.raises(MaintenanceOperationError, match="cannot be uninstalled"):
        extension_operations.uninstall_extension("builtin")

    stale = root / ".cfms-extension-rollback-sample-deadbeef"
    stale.mkdir()
    assert extension_operations.inspect_extensions().extensions
    with pytest.raises(MaintenanceOperationError, match="manual review"):
        extension_operations.enable_extension("builtin")
