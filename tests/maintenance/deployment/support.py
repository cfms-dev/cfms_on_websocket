import datetime as dt
import hashlib
import io
import json
import shutil
from pathlib import Path

from alembic.script import ScriptDirectory

from maintenance.operations.deployment import (
    online as deployment_online,
)
from maintenance.operations.deployment import (
    repository as deployment_repository,
)
from maintenance.operations.deployment.models import _Release

PROJECT_ROOT = Path(__file__).resolve().parents[3]


def _write_extension(
    root: Path,
    directory_name: str,
    identifier: str,
    marker: str,
) -> None:
    extension = root / "src" / "include" / "extensions" / directory_name
    extension.mkdir(parents=True, exist_ok=True)
    (extension / "manifest.toml").write_text(
        "\n".join(
            (
                "manifest_version = 2",
                "",
                "[extension]",
                f'identifier = "{identifier}"',
                f'name = "{identifier}"',
                'version = "1.0.0"',
                'authors = ["Test"]',
                'license = "MIT"',
                "",
            )
        ),
        encoding="utf-8",
    )
    (extension / "_extension.py").write_text(marker, encoding="utf-8")


def _write_release(
    root: Path,
    version: str,
    marker: str,
    *,
    managed_extensions: tuple[str, ...] = ("builtin",),
    with_migrations: bool = False,
    migration: tuple[str, str] | None = None,
) -> _Release:
    files = {
        "pyproject.toml": (
            f'[project]\nname = "cfms-on-websocket"\nversion = "{version}"\n'
            'requires-python = ">=3.14"\n'
        ),
        "uv.lock": f"# {marker}\n",
        "src/alembic.ini": "[alembic]\nscript_location = alembic\n",
        "src/config.toml.sample": f"# {marker}\n",
        "src/content/hello": f"{marker}\n",
        "src/main.py": f"# {marker}\n",
    }
    for relative_path, contents in files.items():
        path = root / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")
    if with_migrations:
        shutil.copy2(PROJECT_ROOT / "src" / "alembic.ini", root / "src")
        shutil.copytree(
            PROJECT_ROOT / "src" / "alembic",
            root / "src" / "alembic",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )
        shutil.copy2(
            PROJECT_ROOT / "src" / "config.toml.sample",
            root / "src" / "config.toml.sample",
        )
    if migration is not None:
        revision, down_revision = migration
        migration_path = root / "src" / "alembic" / "versions" / f"{revision}.py"
        migration_path.write_text(
            "\n".join(
                (
                    f'revision = "{revision}"',
                    f'down_revision = "{down_revision}"',
                    "branch_labels = None",
                    "depends_on = None",
                    "",
                    "def upgrade():",
                    "    pass",
                    "",
                    "def downgrade():",
                    "    pass",
                    "",
                )
            ),
            encoding="utf-8",
        )
    for identifier in managed_extensions:
        _write_extension(root, identifier, identifier, f"# {marker} {identifier}\n")

    release_files = {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }
    manifest = {
        "files": release_files,
        "format_version": 1,
        "managed_extensions": list(managed_extensions),
        "product": "cfms-on-websocket",
        "requires_python": ">=3.14",
        "version": version,
    }
    (root / "release-manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return deployment_repository._release_from_tree(root, exact=True)


def _prepare_deployment(root: Path) -> _Release:
    release = _write_release(root, "1.0.0", "old")
    (root / "src" / "config.toml").write_text("old config\n", encoding="utf-8")
    _write_extension(root, "custom-dir", "custom", "# original custom\n")
    persistent = root / "src" / "content"
    (persistent / "files").mkdir()
    (persistent / "logs").mkdir()
    (persistent / "files" / "production.dat").write_text("data\n", encoding="utf-8")
    (persistent / "logs" / "server.log").write_text("log\n", encoding="utf-8")
    return release


class _HTTPResponse:
    def __init__(
        self,
        contents: bytes,
        url: str,
        *,
        content_length: int | None = None,
    ) -> None:
        self._stream = io.BytesIO(contents)
        self._url = url
        self.headers = {}
        if content_length is not None:
            self.headers["Content-Length"] = str(content_length)

    def read(self, size: int = -1) -> bytes:
        return self._stream.read(size)

    def geturl(self) -> str:
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        pass


def _online_release(
    version: str,
    package_contents: bytes = b"package",
    checksum_contents: bytes = b"checksums",
) -> deployment_online._OnlineRelease:
    package_name = f"cfms-on-websocket-{version}.zip"
    base_url = (
        f"https://github.com/cfms-dev/cfms_on_websocket/releases/download/v{version}"
    )
    return deployment_online._OnlineRelease(
        version,
        dt.datetime(2026, 9, 10, tzinfo=dt.UTC),
        f"https://github.com/cfms-dev/cfms_on_websocket/releases/tag/v{version}",
        deployment_online._ReleaseAsset(
            package_name,
            f"{base_url}/{package_name}",
            len(package_contents),
            hashlib.sha256(package_contents).hexdigest(),
        ),
        deployment_online._ReleaseAsset(
            "SHA256SUMS.txt",
            f"{base_url}/SHA256SUMS.txt",
            len(checksum_contents),
            hashlib.sha256(checksum_contents).hexdigest(),
        ),
    )


def _online_metadata(release: deployment_online._OnlineRelease) -> dict:
    return {
        "tag_name": f"v{release.version}",
        "draft": False,
        "prerelease": False,
        "published_at": release.published_at.isoformat().replace("+00:00", "Z"),
        "html_url": release.release_url,
        "assets": [
            {
                "name": asset.name,
                "state": "uploaded",
                "size": asset.size,
                "digest": f"sha256:{asset.digest}",
                "browser_download_url": asset.url,
            }
            for asset in (release.package, release.checksums)
        ],
    }


def _prepare_database_releases(
    tmp_path: Path,
) -> tuple[Path, _Release, _Release, str, str]:
    project_root = tmp_path / "deployment"
    source_root = tmp_path / "source"
    target_root = tmp_path / "target"
    for release_root in (source_root, target_root):
        (release_root / "src").mkdir(parents=True)
        shutil.copy2(PROJECT_ROOT / "src" / "alembic.ini", release_root / "src")
        shutil.copytree(
            PROJECT_ROOT / "src" / "alembic",
            release_root / "src" / "alembic",
            ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo"),
        )

    source_scripts = ScriptDirectory(str(source_root / "src" / "alembic"))
    source_head = source_scripts.get_current_head()
    target_revision = "deployment_test_head"
    (target_root / "src" / "alembic" / "versions" / f"{target_revision}.py").write_text(
        "\n".join(
            (
                '"""deployment test revision"""',
                f'revision = "{target_revision}"',
                f'down_revision = "{source_head}"',
                "branch_labels = None",
                "depends_on = None",
                "",
                "def upgrade():",
                "    pass",
                "",
                "def downgrade():",
                "    pass",
                "",
            )
        ),
        encoding="utf-8",
    )
    source = _Release(source_root, {}, b"source", "1" * 64)
    target = _Release(target_root, {}, b"target", "2" * 64)
    (project_root / "src").mkdir(parents=True)
    sample = (PROJECT_ROOT / "src" / "config.toml.sample").read_text(encoding="utf-8")
    (project_root / "src" / "config.toml").write_text(sample, encoding="utf-8")
    return project_root, source, target, source_head, target_revision
