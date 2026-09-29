import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

from include.database.models import files as file_models
from include.database.models.documents import DocumentRevision
from include.database.models.files import File
from include.platform.win32.constants import (
    FILE_SHARE_READ,
    INVALID_HANDLE_VALUE,
    OPEN_ALWAYS,
    GenericAccess,
)
from include.providers.storage import LocalStorageProvider


@pytest.fixture
def local_storage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(
        file_models,
        "ProviderManager",
        lambda: SimpleNamespace(storage=LocalStorageProvider()),
    )


def test_win32_file_access_constants_match_sdk_values() -> None:
    assert GenericAccess.READ == 0x80000000
    assert GenericAccess.WRITE == 0x40000000
    assert GenericAccess.READ | GenericAccess.WRITE == 0xC0000000
    assert isinstance(GenericAccess.READ | GenericAccess.WRITE, GenericAccess)
    assert FILE_SHARE_READ == 0x00000001
    assert OPEN_ALWAYS == 4
    assert INVALID_HANDLE_VALUE == -1


def test_nonlocal_file_is_writeable_without_filesystem_check(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(
        file_models,
        "ProviderManager",
        lambda: SimpleNamespace(storage=object()),
    )

    file = File(path=str(tmp_path / "missing"))

    assert file.writeable is True


@pytest.mark.skipif(sys.platform != "win32", reason="Windows file sharing semantics")
def test_windows_file_writeable_releases_handle_and_detects_writer(
    local_storage: None, tmp_path: Path
) -> None:
    path = tmp_path / "document.bin"
    path.write_bytes(b"document")
    file = File(path=str(path))
    revision = DocumentRevision(file=file)

    assert file.writeable is True
    with path.open("r+b"):
        assert file.writeable is False
        assert revision.writeable is False
    assert revision.writeable is True


@pytest.mark.skipif(sys.platform != "win32", reason="Windows file attributes")
def test_windows_readonly_file_is_not_writeable(
    local_storage: None, tmp_path: Path
) -> None:
    path = tmp_path / "readonly.bin"
    path.write_bytes(b"document")
    path.chmod(stat.S_IREAD)
    try:
        assert File(path=str(path)).writeable is False
    finally:
        path.chmod(stat.S_IREAD | stat.S_IWRITE)


@pytest.mark.skipif(sys.platform != "win32", reason="Windows Unicode paths")
def test_windows_unicode_path_is_writeable(local_storage: None, tmp_path: Path) -> None:
    path = tmp_path / "文件😀.bin"
    path.write_bytes(b"document")

    assert File(path=str(path)).writeable is True


@pytest.mark.skipif(sys.platform != "win32", reason="Windows file existence check")
def test_windows_missing_file_is_writeable_without_creating_it(
    local_storage: None, tmp_path: Path
) -> None:
    path = tmp_path / "missing.bin"

    assert File(path=str(path)).writeable is True
    assert not path.exists()


@pytest.mark.skipif(
    sys.platform == "win32", reason="Non-Windows local storage behavior"
)
def test_non_windows_readonly_local_file_is_writeable(
    local_storage: None, tmp_path: Path
) -> None:
    path = tmp_path / "document.bin"
    path.write_bytes(b"document")
    path.chmod(stat.S_IREAD)
    try:
        assert File(path=str(path)).writeable is True
    finally:
        path.chmod(stat.S_IREAD | stat.S_IWRITE)
