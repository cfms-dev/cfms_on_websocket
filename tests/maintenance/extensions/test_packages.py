import hashlib
import stat
import zipfile

import pytest

import maintenance.operations.extensions as extension_operations
from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.operations.extensions import packages as extension_packages

from .support import (
    _enabled,
    _manifest_source,
    _prepare_src,
    _write_package,
)


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

    monkeypatch.setattr(extension_packages, "MAX_PACKAGE_BYTES", 1)
    with pytest.raises(MaintenanceOperationError, match="64 MiB"):
        extension_operations.install_extension(package, write=False)
    monkeypatch.setattr(extension_packages, "MAX_PACKAGE_BYTES", 64 * 1024 * 1024)
    monkeypatch.setattr(extension_packages, "MAX_ARCHIVE_MEMBERS", 2)
    with pytest.raises(MaintenanceOperationError, match="more than 2"):
        extension_operations.install_extension(package, write=False)
    monkeypatch.setattr(extension_packages, "MAX_ARCHIVE_MEMBERS", 4096)
    monkeypatch.setattr(extension_packages, "MAX_UNCOMPRESSED_BYTES", 3)
    with pytest.raises(MaintenanceOperationError, match="uncompressed limit"):
        extension_operations.install_extension(package, write=False)
