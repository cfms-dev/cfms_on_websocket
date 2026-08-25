import subprocess
import tomllib
from pathlib import Path

import pytest

from tools import manage_release


def _write_project(project_root: Path) -> None:
    files = {
        "pyproject.toml": '[project]\nname = "cfms-on-websocket"\nversion = "0.6.0"\n',
        "uv.lock": (
            "version = 1\n\n"
            "[[package]]\n"
            'name = "cfms-on-websocket"\n'
            'version = "0.6.0"\n'
            'source = { editable = "." }\n'
        ),
        "CHANGELOG.md": (
            "# Changelog\n\n"
            "## Unreleased\n\n"
            "<small>[Compare with latest]"
            "(https://github.com/cfms-dev/cfms_on_websocket/compare/"
            "v0.6.0...HEAD)</small>\n\n"
            "<!-- towncrier release notes start -->\n\n"
            "## [v0.6.0]"
            "(https://github.com/cfms-dev/cfms_on_websocket/releases/tag/"
            "v0.6.0) - 2026-08-25\n\n"
            "<small>[Compare with previous release]"
            "(https://github.com/cfms-dev/cfms_on_websocket/compare/"
            "v0.2.0...v0.6.0)</small>\n\n"
            "### Added\n\n- Previous feature.\n\n"
            "## [v0.2.0]"
            "(https://github.com/cfms-dev/cfms_on_websocket/releases/tag/"
            "v0.2.0) - 2026-05-17\n\n"
            "### Fixed\n\n- Previous fix.\n"
        ),
        "src/include/config/constants.py": (
            'CORE_VERSION = Version("0.6.0")\nPROTOCOL_VERSION = 25\n'
        ),
        "src/include/extensions/builtin/manifest.toml": (
            "manifest_version = 2\n\n"
            "[extension]\n"
            'identifier = "builtin"\n'
            'version = "0.6.0"\n\n'
            "[compatibility]\n"
            'minimum_server_version = "0.6.0"\n'
        ),
        "src/include/extensions/oidc_sso/manifest.toml": (
            "manifest_version = 2\n\n"
            "[extension]\n"
            'identifier = "oidc_sso"\n'
            'version = "1.0.0"\n\n'
            "[compatibility]\n"
            'minimum_server_version = "0.5.1"\n'
        ),
        "changelog.d/README.md": "# Fragments\n",
        "changelog.d/+release.added.md": "Add a release feature.\n",
    }
    for relative_path, contents in files.items():
        path = project_root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8", newline="\n")


def _successful_commands(project_root: Path, command: list[str]):
    if command[:3] == ["git", "status", "--porcelain"]:
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
    if command[0] == "uv":
        version = tomllib.loads(
            (project_root / "pyproject.toml").read_text(encoding="utf-8")
        )["project"]["version"]
        lock_path = project_root / "uv.lock"
        lock_path.write_text(
            lock_path.read_text(encoding="utf-8").replace(
                'version = "0.6.0"', f'version = "{version}"'
            ),
            encoding="utf-8",
            newline="\n",
        )
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")
    if "--draft" in command:
        return subprocess.CompletedProcess(
            command, 0, stdout="### Added\n\n- Add a release feature.\n", stderr=""
        )

    version = command[command.index("--version") + 1]
    release_date = command[command.index("--date") + 1]
    changelog_path = project_root / "CHANGELOG.md"
    release = (
        f"## [v{version}]"
        "(https://github.com/cfms-dev/cfms_on_websocket/releases/tag/"
        f"v{version}) - {release_date}\n\n"
        "### Added\n\n- Add a release feature.\n"
    )
    changelog_path.write_text(
        changelog_path.read_text(encoding="utf-8").replace(
            manage_release.TOWNCRIER_MARKER,
            f"{manage_release.TOWNCRIER_MARKER}\n\n{release}",
            1,
        ),
        encoding="utf-8",
        newline="\n",
    )
    return subprocess.CompletedProcess(command, 0, stdout="", stderr="")


@pytest.mark.parametrize(
    ("version", "bump", "expected"),
    [
        ("0.7.0", None, "0.7.0"),
        (None, "major", "1.0.0"),
        (None, "minor", "0.7.0"),
        (None, "patch", "0.6.1"),
    ],
)
def test_prepare_release_synchronizes_managed_versions(
    tmp_path, monkeypatch, version, bump, expected
):
    _write_project(tmp_path)
    optional_manifest = tmp_path / "src/include/extensions/oidc_sso/manifest.toml"
    optional_before = optional_manifest.read_bytes()
    monkeypatch.setattr(manage_release, "_run_command", _successful_commands)

    target = manage_release.prepare_release(
        tmp_path,
        version=version,
        bump=bump,
        release_date="2026-09-01",
    )

    assert target == expected
    constants = (tmp_path / "src/include/config/constants.py").read_text(
        encoding="utf-8"
    )
    assert f'CORE_VERSION = Version("{expected}")' in constants
    assert "PROTOCOL_VERSION = 25" in constants
    assert (
        tomllib.loads((tmp_path / "pyproject.toml").read_text(encoding="utf-8"))[
            "project"
        ]["version"]
        == expected
    )
    builtin_manifest = tomllib.loads(
        (tmp_path / "src/include/extensions/builtin/manifest.toml").read_text(
            encoding="utf-8"
        )
    )
    assert builtin_manifest["extension"]["version"] == expected
    assert builtin_manifest["compatibility"]["minimum_server_version"] == expected
    locked_package = tomllib.loads((tmp_path / "uv.lock").read_text(encoding="utf-8"))[
        "package"
    ][0]
    assert locked_package["version"] == expected
    assert optional_manifest.read_bytes() == optional_before
    assert not (tmp_path / "changelog.d/+release.added.md").exists()
    changelog = (tmp_path / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"compare/v{expected}...HEAD" in changelog
    assert f"compare/v0.6.0...v{expected}" in changelog
    assert manage_release.extract_release_notes(tmp_path, expected) == (
        "### Added\n\n- Add a release feature.\n"
    )


@pytest.mark.parametrize("version", ["0.6.0", "0.5.9", "v0.7.0", "0.7"])
def test_prepare_release_rejects_invalid_or_non_increasing_version(
    tmp_path, monkeypatch, version
):
    _write_project(tmp_path)
    monkeypatch.setattr(manage_release, "_run_command", _successful_commands)

    with pytest.raises(manage_release.ReleaseError):
        manage_release.prepare_release(tmp_path, version=version)


def test_prepare_release_requires_clean_worktree(tmp_path, monkeypatch):
    _write_project(tmp_path)

    def dirty_worktree(project_root, command):
        return subprocess.CompletedProcess(
            command, 0, stdout=" M pyproject.toml\n", stderr=""
        )

    monkeypatch.setattr(manage_release, "_run_command", dirty_worktree)

    with pytest.raises(manage_release.ReleaseError, match="clean Git worktree"):
        manage_release.prepare_release(tmp_path, version="0.7.0")


def test_prepare_release_requires_fragments(tmp_path, monkeypatch):
    _write_project(tmp_path)
    (tmp_path / "changelog.d/+release.added.md").unlink()
    monkeypatch.setattr(manage_release, "_run_command", _successful_commands)

    with pytest.raises(manage_release.ReleaseError, match="fragment is required"):
        manage_release.prepare_release(tmp_path, version="0.7.0")


def test_prepare_release_rejects_unsynchronized_start(tmp_path, monkeypatch):
    _write_project(tmp_path)
    manifest_path = tmp_path / "src/include/extensions/builtin/manifest.toml"
    manifest_path.write_text(
        manifest_path.read_text(encoding="utf-8").replace(
            'minimum_server_version = "0.6.0"',
            'minimum_server_version = "0.5.1"',
        ),
        encoding="utf-8",
        newline="\n",
    )
    monkeypatch.setattr(manage_release, "_run_command", _successful_commands)

    with pytest.raises(manage_release.ReleaseError, match="not synchronized"):
        manage_release.prepare_release(tmp_path, version="0.7.0")


@pytest.mark.parametrize("failing_command", ["uv", "towncrier"])
def test_prepare_release_rolls_back_managed_files_and_fragments(
    tmp_path, monkeypatch, failing_command
):
    _write_project(tmp_path)
    managed_before = {
        path: (tmp_path / path).read_bytes() for path in manage_release.MANAGED_PATHS
    }
    fragment = tmp_path / "changelog.d/+release.added.md"
    fragment_before = fragment.read_bytes()

    def failing_commands(project_root, command):
        if command[0] == failing_command and (
            failing_command != "towncrier" or "--keep" in command
        ):
            raise manage_release.ReleaseError(f"{failing_command} failed")
        return _successful_commands(project_root, command)

    monkeypatch.setattr(manage_release, "_run_command", failing_commands)

    with pytest.raises(manage_release.ReleaseError, match=f"{failing_command} failed"):
        manage_release.prepare_release(
            tmp_path, version="0.7.0", release_date="2026-09-01"
        )

    assert {
        path: (tmp_path / path).read_bytes() for path in manage_release.MANAGED_PATHS
    } == managed_before
    assert fragment.read_bytes() == fragment_before


def test_check_release_exports_towncrier_notes(tmp_path):
    _write_project(tmp_path)
    (tmp_path / "changelog.d/+release.added.md").unlink()
    notes_path = tmp_path / "artifacts/release-notes.md"

    manage_release.check_release(tmp_path, "0.6.0", notes_path)

    assert notes_path.read_text(encoding="utf-8") == (
        "### Added\n\n- Previous feature.\n"
    )


def test_check_release_rejects_unconsumed_fragments(tmp_path):
    _write_project(tmp_path)

    with pytest.raises(manage_release.ReleaseError, match="unconsumed"):
        manage_release.check_release(tmp_path, "0.6.0")
