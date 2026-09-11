import json

import pytest
import tomlkit

import maintenance.operations.extensions as extension_operations
from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.operations.extensions import catalog as extension_catalog

from .support import (
    _SAMPLE_CONFIG,
    _prepare_src,
    _write_installed_extension,
    _write_package,
)


def test_catalog_reports_invalid_activation_without_importing(tmp_path, monkeypatch):
    _, _ = _prepare_src(tmp_path, monkeypatch, enabled=("missing_ext",))

    inspection = extension_operations.inspect_extensions()

    assert inspection.activation_error == (
        "Configured extensions were not found: missing_ext"
    )


def test_release_manifest_protects_packaged_extensions(tmp_path, monkeypatch):
    src, root = _prepare_src(tmp_path, monkeypatch)
    _write_installed_extension(root, "packaged_ext")
    (src.parent / "release-manifest.json").write_text(
        json.dumps({"managed_extensions": ["builtin", "packaged_ext"]}),
        encoding="utf-8",
    )
    package = _write_package(
        tmp_path / "packaged-ext.zip",
        "packaged_ext",
        version="2.0.0",
    )

    with pytest.raises(MaintenanceOperationError, match="upgraded with the server"):
        extension_operations.upgrade_extension(package)
    with pytest.raises(MaintenanceOperationError, match="cannot be uninstalled"):
        extension_operations.uninstall_extension("packaged_ext")


def test_catalog_uses_flat_application_extension_root(tmp_path, monkeypatch):
    _, root = _prepare_src(tmp_path, monkeypatch)
    unrelated = tmp_path / "unrelated"
    unrelated_extensions = unrelated / "extensions"
    unrelated_extensions.mkdir(parents=True)
    _write_installed_extension(unrelated_extensions, "unrelated_only")
    config = tomlkit.parse(_SAMPLE_CONFIG)
    config["extensions"]["enabled"] = ["unrelated_only"]
    (unrelated / "config.toml").write_text(tomlkit.dumps(config), encoding="utf-8")
    monkeypatch.setattr(extension_catalog, "enter_server_root", lambda: unrelated)

    inspection = extension_operations.inspect_extensions()

    assert {record.directory.parent for record in inspection.extensions} == {root}
    assert inspection.activation_error == (
        "Configured extensions were not found: unrelated_only"
    )
