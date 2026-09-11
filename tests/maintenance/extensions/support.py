import zipfile
from pathlib import Path

import pytest
import tomlkit

from maintenance.operations.extensions import catalog as extension_catalog

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
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
    monkeypatch.setattr(extension_catalog.paths, "EXECUTABLE_ABSPATH", src)
    monkeypatch.setattr(extension_catalog.paths, "PROJECT_ABSPATH", src.parent)
    monkeypatch.setattr(extension_catalog.paths, "EXTENSION_ROOT", root)
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
