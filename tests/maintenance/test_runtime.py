from pathlib import Path

import pytest

from include.config import paths
from maintenance.runtime import MaintenanceRuntimeError, enter_server_root


@pytest.fixture(autouse=True)
def _restore_application_paths(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(paths, "APPLICATION_ABSPATH", paths.APPLICATION_ABSPATH)
    monkeypatch.setattr(paths, "PROJECT_ABSPATH", paths.PROJECT_ABSPATH)
    monkeypatch.setattr(paths, "EXTENSION_ROOT", paths.EXTENSION_ROOT)


def _make_server_root(path: Path) -> Path:
    path.mkdir(parents=True)
    (path / "main.py").write_text("", encoding="utf-8")
    (path / "config.toml").write_text("", encoding="utf-8")
    return path.resolve()


@pytest.mark.parametrize("relative_start", [Path(), Path("content/logs")])
def test_enter_server_root_supports_flat_layout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    relative_start: Path,
) -> None:
    server_root = _make_server_root(tmp_path / "release-bundle")
    start = server_root / relative_start
    start.mkdir(parents=True, exist_ok=True)
    monkeypatch.chdir(start)

    located = enter_server_root()

    assert located == server_root
    assert Path.cwd() == server_root
    assert paths.APPLICATION_ABSPATH == server_root
    assert paths.PROJECT_ABSPATH == server_root.parent
    assert paths.EXTENSION_ROOT == server_root / "include" / "extensions"


def test_enter_server_root_finds_compatible_src_layout(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    deployment_root = tmp_path / "deployment"
    server_root = _make_server_root(deployment_root / "src")
    start = deployment_root / "docs" / "operations"
    start.mkdir(parents=True)
    monkeypatch.chdir(start)

    located = enter_server_root()

    assert located == server_root
    assert Path.cwd() == server_root


def test_enter_server_root_prefers_nearest_direct_ancestor(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    outer_root = _make_server_root(tmp_path / "outer")
    inner_root = _make_server_root(outer_root / "instances" / "inner")
    start = inner_root / "content"
    start.mkdir()
    monkeypatch.chdir(start)

    assert enter_server_root() == inner_root


def test_direct_ancestor_precedes_compatible_src_candidate(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    direct_root = _make_server_root(tmp_path / "server")
    _make_server_root(direct_root / "workspace" / "src")
    start = direct_root / "workspace" / "docs"
    start.mkdir(parents=True)
    monkeypatch.chdir(start)

    assert enter_server_root() == direct_root


def test_enter_server_root_is_idempotent(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_root = _make_server_root(tmp_path / "server")
    start = server_root / "content"
    start.mkdir()
    monkeypatch.chdir(start)

    assert enter_server_root() == server_root
    assert enter_server_root() == server_root
    assert Path.cwd() == server_root


def test_enter_server_root_reports_unrelated_directory(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    start = tmp_path / "unrelated"
    start.mkdir()
    monkeypatch.chdir(start)

    with pytest.raises(MaintenanceRuntimeError, match="main.py and config.toml"):
        enter_server_root()

    assert Path.cwd() == start.resolve()


def test_enter_server_root_does_not_use_legacy_environment_override(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    server_root = _make_server_root(tmp_path / "shared")
    unrelated = tmp_path / "elsewhere"
    unrelated.mkdir()
    monkeypatch.chdir(unrelated)
    monkeypatch.setenv("CFMS_SERVER_ROOT", str(server_root))

    with pytest.raises(MaintenanceRuntimeError, match="main.py and config.toml"):
        enter_server_root()

    assert Path.cwd() == unrelated.resolve()
