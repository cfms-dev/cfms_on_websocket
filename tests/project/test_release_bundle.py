import hashlib
import json
import re
import tarfile
import tomllib
import zipfile
from pathlib import Path, PurePosixPath

import pytest

from tools.build_release import build_release

PROJECT_ROOT = Path(__file__).resolve().parents[2]
SOURCE_DATE_EPOCH = 1_788_000_000


def _project_version(project_root: Path) -> str:
    with (project_root / "pyproject.toml").open("rb") as pyproject_file:
        return tomllib.load(pyproject_file)["project"]["version"]


def _zip_members(path: Path) -> set[str]:
    with zipfile.ZipFile(path) as archive:
        return {info.filename for info in archive.infolist() if not info.is_dir()}


def _tar_members(path: Path) -> set[str]:
    with tarfile.open(path, "r:gz") as archive:
        return {member.name for member in archive.getmembers() if member.isfile()}


def _create_minimal_project(project_root: Path, version: str = "1.2.3") -> None:
    files = {
        "CHANGELOG.md": "# Changelog\n",
        "README.md": "# Project\n",
        "SECURITY.md": "# Security\n",
        "pyproject.toml": f'[project]\nname = "example"\nversion = "{version}"\n',
        "uv.lock": "version = 1\n",
        "src/LICENSE": "license\n",
        "src/alembic.ini": "[alembic]\n",
        "src/config.toml.sample": "debug = false\n",
        "src/content/hello": "hello\n",
        "src/main.py": "pass\n",
        "src/alembic/README": "migrations\n",
        "src/alembic/versions/base.py": (
            'revision: str = "base"\ndown_revision: str | None = None\n'
        ),
        "src/include/__init__.py": "",
        "src/include/extensions/builtin/_extension.py": "",
        "src/include/extensions/builtin/manifest.toml": (
            "manifest_version = 2\n"
            "[extension]\n"
            'identifier = "builtin"\n'
            'name = "Built-in"\n'
            'version = "1.2.3"\n'
            'authors = ["Test"]\n'
            'license = "Apache-2.0"\n'
        ),
        "src/maintenance/__init__.py": "",
        "src/content/ssl/client/8a5a09f0.0": "certificate\n",
        "src/content/ssl/client/.git": "gitdir: elsewhere\n",
    }
    for relative_name, contents in files.items():
        path = project_root / relative_name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")


def test_release_archives_contain_only_deployable_files(tmp_path):
    version = _project_version(PROJECT_ROOT)
    zip_path, tar_path, checksums_path = build_release(
        PROJECT_ROOT,
        tmp_path,
        version,
        SOURCE_DATE_EPOCH,
    )

    zip_members = _zip_members(zip_path)
    tar_members = _tar_members(tar_path)
    top_level = f"cfms-on-websocket-{version}"
    assert zip_members == tar_members
    assert all(PurePosixPath(member).parts[0] == top_level for member in zip_members)

    relative_members = {
        PurePosixPath(member).relative_to(top_level).as_posix()
        for member in zip_members
    }
    assert {
        "pyproject.toml",
        "release-manifest.json",
        "uv.lock",
        "src/main.py",
        "src/alembic.ini",
        "src/alembic/env.py",
        "src/config.toml.sample",
        "src/content/hello",
        "src/include/extensions/builtin/manifest.toml",
        "src/maintenance/cli.py",
    } <= relative_members
    assert any(
        member.startswith("src/content/ssl/client/")
        and re.fullmatch(r"[0-9a-fA-F]{8}\.[0-9]+", PurePosixPath(member).name)
        for member in relative_members
    )

    with zipfile.ZipFile(zip_path) as archive:
        manifest = json.loads(archive.read(f"{top_level}/release-manifest.json"))
    assert manifest["version"] == version
    assert "alembic_head" not in manifest
    assert "minimum_upgrade_version" not in manifest
    assert manifest["managed_extensions"] == [
        "brute_force_lockdown",
        "builtin",
        "http_api",
        "oidc_sso",
        "scheduling",
    ]
    assert "release-manifest.json" not in manifest["files"]
    assert not any(
        path.startswith(("src/content/files/", "src/content/logs/"))
        for path in manifest["files"]
    )

    forbidden_prefixes = (
        ".codex/",
        ".git/",
        ".github/",
        "docs/",
        "src/certtools/",
        "tests/",
        "tools/",
    )
    assert not any(member.startswith(forbidden_prefixes) for member in relative_members)
    assert not any(
        ".git" in PurePosixPath(member).parts
        or "__pycache__" in PurePosixPath(member).parts
        for member in relative_members
    )
    assert (
        not {
            "src/admin_password.txt",
            "src/app.db",
            "src/config.toml",
            "src/init",
        }
        & relative_members
    )

    checksum_lines = checksums_path.read_text(encoding="utf-8").splitlines()
    expected_checksums = {
        f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.name}"
        for path in (zip_path, tar_path)
    }
    assert set(checksum_lines) == expected_checksums


def test_release_archives_are_reproducible(tmp_path):
    version = _project_version(PROJECT_ROOT)
    first_artifacts = build_release(
        PROJECT_ROOT,
        tmp_path / "first",
        version,
        SOURCE_DATE_EPOCH,
    )
    second_artifacts = build_release(
        PROJECT_ROOT,
        tmp_path / "second",
        version,
        SOURCE_DATE_EPOCH,
    )

    assert [path.name for path in first_artifacts] == [
        path.name for path in second_artifacts
    ]
    assert [path.read_bytes() for path in first_artifacts] == [
        path.read_bytes() for path in second_artifacts
    ]


@pytest.mark.parametrize("version", ["v1.2.3", "1.2", "1.2.3-alpha"])
def test_release_rejects_non_stable_versions(tmp_path, version):
    project_root = tmp_path / "project"
    _create_minimal_project(project_root)

    with pytest.raises(ValueError, match="X.Y.Z format"):
        build_release(project_root, tmp_path / "dist", version, SOURCE_DATE_EPOCH)


def test_release_rejects_project_version_mismatch(tmp_path):
    project_root = tmp_path / "project"
    _create_minimal_project(project_root)

    with pytest.raises(ValueError, match="does not match project version"):
        build_release(project_root, tmp_path / "dist", "2.0.0", SOURCE_DATE_EPOCH)


@pytest.mark.parametrize(
    ("missing_path", "message"),
    [
        ("src/main.py", "Required release file is missing"),
        (
            "src/content/ssl/client/8a5a09f0.0",
            "client CA submodule is missing",
        ),
    ],
)
def test_release_rejects_missing_runtime_assets(tmp_path, missing_path, message):
    project_root = tmp_path / "project"
    _create_minimal_project(project_root)
    (project_root / missing_path).unlink()

    with pytest.raises(ValueError, match=message):
        build_release(project_root, tmp_path / "dist", "1.2.3", SOURCE_DATE_EPOCH)
