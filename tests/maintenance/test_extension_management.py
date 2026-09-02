import hashlib
import json
import stat
import zipfile
from pathlib import Path

import pytest
import tomlkit

import maintenance.operations.extensions as extension_operations
from maintenance.operations.exceptions import MaintenanceOperationError

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SAMPLE_CONFIG = (_PROJECT_ROOT / "src" / "config.toml.sample").read_text(
    encoding="utf-8"
)


def _manifest_source(
    identifier: str,
    *,
    version: str = "1.0.0",
    dependencies: dict[str, str] | None = None,
    minimum_server_version: str | None = None,
) -> str:
    manifest_version = 3 if dependencies is not None else 2
    lines = [
        f"manifest_version = {manifest_version}",
        "",
        "[extension]",
        f'identifier = "{identifier}"',
        f'name = "{identifier} extension"',
        f'version = "{version}"',
        'authors = ["Test Author"]',
        'license = "Apache-2.0"',
    ]
    if minimum_server_version is not None:
        lines.extend(
            [
                "",
                "[compatibility]",
                f'minimum_server_version = "{minimum_server_version}"',
            ]
        )
    if dependencies is not None:
        lines.extend(["", "[dependencies.extensions]"])
        lines.extend(
            f'{dependency} = "{minimum}"'
            for dependency, minimum in dependencies.items()
        )
    return "\n".join(lines) + "\n"


def _write_installed_extension(
    root: Path,
    identifier: str,
    *,
    directory_name: str | None = None,
    version: str = "1.0.0",
    dependencies: dict[str, str] | None = None,
    minimum_server_version: str | None = None,
) -> Path:
    directory = root / (directory_name or identifier)
    directory.mkdir()
    (directory / "manifest.toml").write_text(
        _manifest_source(
            identifier,
            version=version,
            dependencies=dependencies,
            minimum_server_version=minimum_server_version,
        ),
        encoding="utf-8",
    )
    (directory / "_extension.py").write_text(
        f'EXTENSION_VERSION = "{version}"\n', encoding="utf-8"
    )
    return directory


def _prepare_src(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    enabled: tuple[str, ...] = (),
) -> tuple[Path, Path]:
    src = tmp_path / "src"
    root = src / "include" / "extensions"
    root.mkdir(parents=True)
    (src / "main.py").write_text("", encoding="utf-8")
    config = tomlkit.parse(_SAMPLE_CONFIG)
    config["extensions"]["enabled"] = list(enabled)
    (src / "config.toml").write_text(tomlkit.dumps(config), encoding="utf-8")
    _write_installed_extension(root, "builtin")
    monkeypatch.setattr(extension_operations.paths, "EXECUTEABLE_ABSPATH", src)
    monkeypatch.setattr(extension_operations.paths, "PROJECT_ABSPATH", src.parent)
    monkeypatch.setattr(extension_operations.paths, "EXTENSION_ROOT", root)
    monkeypatch.chdir(src)
    return src, root


def _write_package(
    path: Path,
    identifier: str = "sample_ext",
    *,
    version: str = "1.0.0",
    dependencies: dict[str, str] | None = None,
    minimum_server_version: str | None = None,
    extra_members: dict[str, str] | None = None,
    compression: int = zipfile.ZIP_DEFLATED,
) -> Path:
    with zipfile.ZipFile(path, "w", compression=compression) as archive:
        archive.writestr(
            "manifest.toml",
            _manifest_source(
                identifier,
                version=version,
                dependencies=dependencies,
                minimum_server_version=minimum_server_version,
            ),
        )
        archive.writestr(
            "_extension.py",
            "raise RuntimeError('extension code must not execute during maintenance')\n",
        )
        for name, contents in (extra_members or {}).items():
            archive.writestr(name, contents)
    return path


def _enabled(src: Path) -> tuple[str, ...]:
    document = tomlkit.parse((src / "config.toml").read_text(encoding="utf-8"))
    return tuple(document["extensions"]["enabled"])


def test_install_validates_package_without_importing_and_leaves_it_disabled(
    tmp_path, monkeypatch
):
    src, root = _prepare_src(tmp_path, monkeypatch)
    package = _write_package(tmp_path / "sample.zip")
    expected_sha256 = hashlib.sha256(package.read_bytes()).hexdigest()

    preview = extension_operations.install_extension(
        package, expected_sha256=expected_sha256, write=False
    )

    assert preview.package_sha256 == expected_sha256
    assert preview.extension.enabled is False
    assert not (root / "sample_ext").exists()

    result = extension_operations.install_extension(
        package, expected_sha256=preview.package_sha256, write=True
    )

    assert result.extension.manifest.extension.identifier == "sample_ext"
    assert (root / "sample_ext" / "_extension.py").is_file()
    assert _enabled(src) == ()
    assert list(root.glob(".cfms-extension-*")) == []
    with pytest.raises(MaintenanceOperationError, match="use upgrade"):
        extension_operations.install_extension(package, write=False)


def test_install_allows_a_disabled_extension_for_a_newer_server(tmp_path, monkeypatch):
    _, root = _prepare_src(tmp_path, monkeypatch)
    package = _write_package(
        tmp_path / "future.zip",
        identifier="future_ext",
        minimum_server_version="99.0.0",
    )

    result = extension_operations.install_extension(package, write=True)

    assert result.extension.compatible is False
    assert result.extension.enabled is False
    assert (root / "future_ext").is_dir()


@pytest.mark.parametrize(
    "unsafe_name",
    [
        "../escape.py",
        "/absolute.py",
        "C:/drive.py",
        "folder\\child.py",
        "folder//child.py",
        "asset.txt:stream",
        "trailing. ",
    ],
)
def test_package_rejects_unsafe_paths(tmp_path, monkeypatch, unsafe_name):
    _, _ = _prepare_src(tmp_path, monkeypatch)
    package = _write_package(
        tmp_path / "unsafe.zip",
        extra_members={
            "folder/child.py" if "\\" in unsafe_name else unsafe_name: "unsafe"
        },
    )
    if "\\" in unsafe_name:
        package.write_bytes(
            package.read_bytes().replace(b"folder/child.py", b"folder\\child.py")
        )

    with pytest.raises(MaintenanceOperationError, match="Unsafe extension archive"):
        extension_operations.install_extension(package, write=False)


def test_package_rejects_casefold_duplicates_and_links(tmp_path, monkeypatch):
    _, root = _prepare_src(tmp_path, monkeypatch)
    duplicate = _write_package(
        tmp_path / "duplicate.zip",
        extra_members={"assets/Name.txt": "a", "assets/name.TXT": "b"},
    )

    with pytest.raises(MaintenanceOperationError, match="Duplicate"):
        extension_operations.install_extension(duplicate, write=False)

    conflict = _write_package(
        tmp_path / "conflict.zip",
        extra_members={"asset": "file", "asset/child.txt": "child"},
    )
    with pytest.raises(MaintenanceOperationError, match="file/directory conflict"):
        extension_operations.install_extension(conflict, write=False)

    linked = tmp_path / "linked.zip"
    with zipfile.ZipFile(linked, "w") as archive:
        archive.writestr("manifest.toml", _manifest_source("linked_ext"))
        archive.writestr("_extension.py", "")
        info = zipfile.ZipInfo("linked.py")
        info.create_system = 3
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(info, "target.py")

    with pytest.raises(MaintenanceOperationError, match="member type"):
        extension_operations.install_extension(linked, write=False)
    assert list(root.glob(".cfms-extension-*")) == []


def test_package_rejects_missing_entrypoint_builtin_and_self_dependency(
    tmp_path, monkeypatch
):
    _prepare_src(tmp_path, monkeypatch)
    missing = tmp_path / "missing.zip"
    with zipfile.ZipFile(missing, "w") as archive:
        archive.writestr("manifest.toml", _manifest_source("missing_entrypoint"))
    with pytest.raises(MaintenanceOperationError, match="_extension.py"):
        extension_operations.install_extension(missing, write=False)

    builtin = _write_package(tmp_path / "builtin.zip", identifier="builtin")
    with pytest.raises(MaintenanceOperationError, match="cannot be managed"):
        extension_operations.install_extension(builtin, write=False)

    self_dependent = _write_package(
        tmp_path / "self.zip",
        identifier="self_ext",
        dependencies={"self_ext": "1.0.0"},
    )
    with pytest.raises(MaintenanceOperationError, match="depend on itself"):
        extension_operations.install_extension(self_dependent, write=False)


def test_package_rejects_unsupported_compression_and_encryption(tmp_path, monkeypatch):
    _prepare_src(tmp_path, monkeypatch)
    compressed = _write_package(tmp_path / "bzip2.zip", compression=zipfile.ZIP_BZIP2)
    with pytest.raises(MaintenanceOperationError, match="Unsupported compression"):
        extension_operations.install_extension(compressed, write=False)

    encrypted = _write_package(tmp_path / "encrypted.zip")
    data = bytearray(encrypted.read_bytes())
    central_offset = data.index(b"PK\x01\x02")
    local_flags = int.from_bytes(data[6:8], "little") | 0x1
    central_flags = (
        int.from_bytes(data[central_offset + 8 : central_offset + 10], "little") | 0x1
    )
    data[6:8] = local_flags.to_bytes(2, "little")
    data[central_offset + 8 : central_offset + 10] = central_flags.to_bytes(2, "little")
    encrypted.write_bytes(data)

    with pytest.raises(MaintenanceOperationError, match="Encrypted"):
        extension_operations.install_extension(encrypted, write=False)


def test_package_enforces_digest_size_and_member_limits(tmp_path, monkeypatch):
    _prepare_src(tmp_path, monkeypatch)
    package = _write_package(
        tmp_path / "limits.zip", extra_members={"asset.txt": "content"}
    )

    with pytest.raises(MaintenanceOperationError, match="SHA-256 mismatch"):
        extension_operations.install_extension(
            package, expected_sha256="0" * 64, write=False
        )

    monkeypatch.setattr(extension_operations, "MAX_PACKAGE_BYTES", 1)
    with pytest.raises(MaintenanceOperationError, match="64 MiB"):
        extension_operations.install_extension(package, write=False)
    monkeypatch.setattr(extension_operations, "MAX_PACKAGE_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(extension_operations, "MAX_ARCHIVE_MEMBERS", 2)
    with pytest.raises(MaintenanceOperationError, match="more than 2"):
        extension_operations.install_extension(package, write=False)
    monkeypatch.setattr(extension_operations, "MAX_ARCHIVE_MEMBERS", 4096)
    monkeypatch.setattr(extension_operations, "MAX_UNCOMPRESSED_BYTES", 3)
    with pytest.raises(MaintenanceOperationError, match="uncompressed limit"):
        extension_operations.install_extension(package, write=False)


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
        extension_operations, "write_config_atomically", fail_config_update
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
        extension_operations, "write_config_atomically", fail_config_update
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
    monkeypatch.setattr(extension_operations, "enter_server_root", lambda: unrelated)

    inspection = extension_operations.inspect_extensions()

    assert {record.directory.parent for record in inspection.extensions} == {root}
    assert inspection.activation_error == (
        "Configured extensions were not found: unrelated_only"
    )
