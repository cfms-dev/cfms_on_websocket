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
    _write_installed_extension,
    _write_package,
)


def test_install_preview_validates_digest_without_importing_or_writing(
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
    assert _enabled(src) == ()
    assert list(root.glob(".cfms-extension-*")) == []


def test_install_writes_code_without_importing_or_enabling_it(tmp_path, monkeypatch):
    src, root = _prepare_src(tmp_path, monkeypatch)
    package = _write_package(tmp_path / "sample.zip")
    expected_sha256 = hashlib.sha256(package.read_bytes()).hexdigest()

    result = extension_operations.install_extension(
        package, expected_sha256=expected_sha256, write=True
    )

    assert result.extension.manifest.extension.identifier == "sample_ext"
    assert (root / "sample_ext" / "_extension.py").is_file()
    assert _enabled(src) == ()
    assert list(root.glob(".cfms-extension-*")) == []


def test_install_rejects_an_already_installed_extension(tmp_path, monkeypatch):
    _, root = _prepare_src(tmp_path, monkeypatch)
    installed = _write_installed_extension(root, "sample_ext")
    original_code = (installed / "_extension.py").read_bytes()
    package = _write_package(tmp_path / "sample.zip")

    with pytest.raises(MaintenanceOperationError, match="use upgrade"):
        extension_operations.install_extension(package, write=False)

    assert (installed / "_extension.py").read_bytes() == original_code
    assert list(root.glob(".cfms-extension-*")) == []


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


@pytest.mark.parametrize(
    ("members", "message"),
    [
        pytest.param(
            {"assets/Name.txt": "a", "assets/name.TXT": "b"},
            "Duplicate",
            id="casefold-duplicate",
        ),
        pytest.param(
            {"asset": "file", "asset/child.txt": "child"},
            "file/directory conflict",
            id="file-directory-conflict",
        ),
    ],
)
def test_package_rejects_conflicting_archive_paths(
    tmp_path, monkeypatch, members, message
):
    _, root = _prepare_src(tmp_path, monkeypatch)
    package = _write_package(tmp_path / "conflict.zip", extra_members=members)

    with pytest.raises(MaintenanceOperationError, match=message):
        extension_operations.install_extension(package, write=False)

    assert list(root.glob(".cfms-extension-*")) == []


def test_package_rejects_link_members_and_removes_staging(tmp_path, monkeypatch):
    _, root = _prepare_src(tmp_path, monkeypatch)
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


def test_package_rejects_missing_entrypoint(tmp_path, monkeypatch):
    _, root = _prepare_src(tmp_path, monkeypatch)
    missing = tmp_path / "missing.zip"
    with zipfile.ZipFile(missing, "w") as archive:
        archive.writestr("manifest.toml", _manifest_source("missing_entrypoint"))

    with pytest.raises(MaintenanceOperationError, match="_extension.py"):
        extension_operations.install_extension(missing, write=False)

    assert list(root.glob(".cfms-extension-*")) == []


def test_package_rejects_builtin_extension(tmp_path, monkeypatch):
    _, root = _prepare_src(tmp_path, monkeypatch)
    builtin = _write_package(tmp_path / "builtin.zip", identifier="builtin")

    with pytest.raises(MaintenanceOperationError, match="cannot be managed"):
        extension_operations.install_extension(builtin, write=False)

    assert list(root.glob(".cfms-extension-*")) == []


def test_package_rejects_self_dependency(tmp_path, monkeypatch):
    _, root = _prepare_src(tmp_path, monkeypatch)
    self_dependent = _write_package(
        tmp_path / "self.zip",
        identifier="self_ext",
        dependencies={"self_ext": "1.0.0"},
    )

    with pytest.raises(MaintenanceOperationError, match="depend on itself"):
        extension_operations.install_extension(self_dependent, write=False)

    assert list(root.glob(".cfms-extension-*")) == []


def test_package_rejects_unsupported_compression(tmp_path, monkeypatch):
    _, root = _prepare_src(tmp_path, monkeypatch)
    compressed = _write_package(tmp_path / "bzip2.zip", compression=zipfile.ZIP_BZIP2)

    with pytest.raises(MaintenanceOperationError, match="Unsupported compression"):
        extension_operations.install_extension(compressed, write=False)

    assert list(root.glob(".cfms-extension-*")) == []


def test_package_rejects_encrypted_members(tmp_path, monkeypatch):
    _, root = _prepare_src(tmp_path, monkeypatch)
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

    assert list(root.glob(".cfms-extension-*")) == []


def test_package_rejects_digest_mismatch_before_installation(tmp_path, monkeypatch):
    _, root = _prepare_src(tmp_path, monkeypatch)
    package = _write_package(
        tmp_path / "limits.zip", extra_members={"asset.txt": "content"}
    )

    with pytest.raises(MaintenanceOperationError, match="SHA-256 mismatch"):
        extension_operations.install_extension(
            package, expected_sha256="0" * 64, write=False
        )

    assert not (root / "sample_ext").exists()
    assert list(root.glob(".cfms-extension-*")) == []


@pytest.mark.parametrize(
    ("setting", "limit", "message"),
    [
        pytest.param("MAX_PACKAGE_BYTES", 1, "64 MiB", id="package-bytes"),
        pytest.param("MAX_ARCHIVE_MEMBERS", 2, "more than 2", id="archive-members"),
        pytest.param(
            "MAX_UNCOMPRESSED_BYTES", 3, "uncompressed limit", id="uncompressed-bytes"
        ),
    ],
)
def test_package_enforces_resource_limits_and_cleans_staging(
    tmp_path, monkeypatch, setting, limit, message
):
    _, root = _prepare_src(tmp_path, monkeypatch)
    package = _write_package(
        tmp_path / "limits.zip", extra_members={"asset.txt": "content"}
    )
    monkeypatch.setattr(extension_packages, setting, limit)

    with pytest.raises(MaintenanceOperationError, match=message):
        extension_operations.install_extension(package, write=False)

    assert not (root / "sample_ext").exists()
    assert list(root.glob(".cfms-extension-*")) == []


def test_extension_root_limit_counts_non_directory_entries(tmp_path, monkeypatch):
    _, root = _prepare_src(tmp_path, monkeypatch)
    for index in range(3):
        (root / f"entry-{index}.txt").write_text("entry", encoding="utf-8")
    monkeypatch.setattr(extension_packages, "MAX_INSTALLED_EXTENSIONS", 2)

    with pytest.raises(MaintenanceOperationError, match="more than 2 entries"):
        extension_operations.inspect_extensions()


def test_extension_root_rejects_oversized_installed_manifest(
    tmp_path,
    monkeypatch,
):
    _, root = _prepare_src(tmp_path, monkeypatch)
    manifest = root / "sample_ext" / "manifest.toml"
    manifest.parent.mkdir(parents=True)
    limit = (root / "builtin" / "manifest.toml").stat().st_size + 1
    manifest.write_bytes(b"x" * (limit + 1))
    monkeypatch.setattr(extension_packages, "MAX_EXTENSION_MANIFEST_BYTES", limit)

    with pytest.raises(MaintenanceOperationError, match="manifest exceeds.*sample_ext"):
        extension_operations.inspect_extensions()
