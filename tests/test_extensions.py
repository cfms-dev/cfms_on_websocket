import sys
from pathlib import Path
from types import SimpleNamespace

import pluggy
import pytest

import include.extensions.manager as extension_manager

EXTENSION_MODULE_NAMES = {
    "builtin",
    "missing_entry_ext",
    "root_file_ext",
    "sample_ext",
}


def _manifest_source(default_identifier: str, **overrides) -> str:
    values = {
        "manifest_version": 1,
        "identifier": default_identifier,
        "name": "Sample Extension",
        "version": "1.0.0",
        "authors": ["Test Author"],
        "license": "Apache-2.0",
    }
    values.update(overrides)
    lines = []
    for key, value in values.items():
        if isinstance(value, str):
            lines.append(f"{key} = {value!r}")
        elif isinstance(value, list):
            rendered = ", ".join(repr(item) for item in value)
            lines.append(f"{key} = [{rendered}]")
        else:
            lines.append(f"{key} = {value}")
    return "\n".join(lines) + "\n"


def _write_extension(root: Path, name: str, source: str = "VALUE = 1\n") -> Path:
    extension_dir = root / name
    extension_dir.mkdir()
    (extension_dir / "_extension.py").write_text(source, encoding="utf-8")
    return extension_dir


def _write_manifest(extension_dir: Path, identifier: str, **overrides) -> Path:
    manifest_path = extension_dir / "extension.toml"
    manifest_path.write_text(
        _manifest_source(identifier, **overrides), encoding="utf-8"
    )
    return manifest_path


def _fresh_plugin_manager() -> pluggy.PluginManager:
    pm = pluggy.PluginManager("cfms")
    pm.add_hookspecs(extension_manager.ServerHookSpecs)
    return pm


@pytest.fixture(autouse=True)
def restore_extension_modules():
    saved_modules = {
        name: sys.modules.get(name)
        for name in EXTENSION_MODULE_NAMES
        if name in sys.modules
    }
    yield
    for name in EXTENSION_MODULE_NAMES:
        if name in saved_modules:
            sys.modules[name] = saved_modules[name]
        else:
            sys.modules.pop(name, None)


def test_root_python_files_are_ignored(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)

    (tmp_path / "root_file_ext.py").write_text(
        "raise RuntimeError('root file should not be loaded')\n",
        encoding="utf-8",
    )

    extension_manager.load_extensions_from_directory(tmp_path)

    assert not pm.has_plugin("root_file_ext")
    assert "root_file_ext" not in sys.modules


def test_directory_extension_entrypoint_is_loaded(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_extension(tmp_path, "sample_ext", "VALUE = 42\n")

    extension_manager.load_extensions_from_directory(tmp_path)

    assert pm.has_plugin("sample_ext")
    assert pm.get_plugin("sample_ext").VALUE == 42


def test_directory_without_entrypoint_is_skipped(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    (tmp_path / "missing_entry_ext").mkdir()

    extension_manager.load_extensions_from_directory(tmp_path)

    assert not pm.has_plugin("missing_entry_ext")
    assert "missing_entry_ext" not in sys.modules


def test_extension_manifest_is_parsed(tmp_path):
    extension_dir = _write_extension(tmp_path, "different_folder")
    manifest_path = _write_manifest(
        extension_dir,
        "sample_ext",
        description="A sample extension",
        homepage="https://example.test/sample",
    )

    manifest = extension_manager.parse_extension_manifest(manifest_path)

    assert manifest.identifier == "sample_ext"
    assert manifest.name == "Sample Extension"
    assert manifest.authors == ("Test Author",)
    assert manifest.description == "A sample extension"


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"manifest_version": 2}, "unsupported manifest_version"),
        ({"identifier": "Invalid-Identifier"}, "invalid extension identifier"),
        ({"authors": []}, "authors"),
        ({"unknown_field": "value"}, "unknown fields"),
    ],
)
def test_invalid_extension_manifest_is_rejected(tmp_path, overrides, message):
    manifest_path = tmp_path / "extension.toml"
    manifest_path.write_text(
        _manifest_source("sample_ext", **overrides), encoding="utf-8"
    )

    with pytest.raises(extension_manager.ExtensionManifestError, match=message):
        extension_manager.parse_extension_manifest(manifest_path)


def test_extension_manifest_requires_core_fields(tmp_path):
    manifest_path = tmp_path / "extension.toml"
    manifest_path.write_text("manifest_version = 1\n", encoding="utf-8")

    with pytest.raises(
        extension_manager.ExtensionManifestError, match="missing required fields"
    ):
        extension_manager.parse_extension_manifest(manifest_path)


@pytest.mark.parametrize("missing", ["manifest", "entrypoint"])
def test_incomplete_extension_candidate_is_rejected(tmp_path, missing):
    extension_dir = _write_extension(tmp_path, "sample")
    _write_manifest(extension_dir, "sample_ext")
    if missing == "manifest":
        (extension_dir / "extension.toml").unlink()
    else:
        (extension_dir / "_extension.py").unlink()

    with pytest.raises(extension_manager.ExtensionDiscoveryError, match="is missing"):
        extension_manager.discover_extensions(tmp_path)


def test_duplicate_extension_identifiers_are_rejected(tmp_path):
    first = _write_extension(tmp_path, "first")
    second = _write_extension(tmp_path, "second")
    _write_manifest(first, "sample_ext")
    _write_manifest(second, "sample_ext")

    with pytest.raises(
        extension_manager.ExtensionDiscoveryError,
        match="Duplicate extension identifier 'sample_ext'",
    ):
        extension_manager.discover_extensions(tmp_path)


def test_builtin_extension_loads_quietly_and_is_not_loaded_twice(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)

    info_messages = []
    monkeypatch.setattr(
        extension_manager,
        "logger",
        SimpleNamespace(
            error=lambda *_args, **_kwargs: None,
            exception=lambda *_args, **_kwargs: None,
            info=lambda message, *_args, **_kwargs: info_messages.append(message),
            warning=lambda *_args, **_kwargs: None,
        ),
    )

    counter_path = tmp_path / "counter.txt"
    _write_extension(
        tmp_path,
        "builtin",
        "\n".join(
            [
                "from pathlib import Path",
                f"counter_path = Path({str(counter_path)!r})",
                "count = int(counter_path.read_text()) if counter_path.exists() else 0",
                "counter_path.write_text(str(count + 1))",
                "",
            ]
        ),
    )

    extension_manager.load_builtin_extension(tmp_path)
    extension_manager.load_extensions_from_directory(tmp_path)

    assert pm.has_plugin("builtin")
    assert counter_path.read_text(encoding="utf-8") == "1"
    assert info_messages == []


def test_collect_extension_flags_returns_sorted_unique_strings(monkeypatch):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)

    class FirstExtension:
        @extension_manager.hookimpl
        def ext_register_extension_flags(self):
            return {"zeta", "alpha"}

    class SecondExtension:
        @extension_manager.hookimpl
        def ext_register_extension_flags(self):
            return {"alpha", "beta"}

    pm.register(FirstExtension())
    pm.register(SecondExtension())

    assert extension_manager.collect_extension_flags() == ["alpha", "beta", "zeta"]


def test_collect_extension_flags_with_no_plugins(monkeypatch):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)

    assert extension_manager.collect_extension_flags() == []


def test_collect_extension_flags_ignores_non_string_flags(monkeypatch):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)

    class Extension:
        @extension_manager.hookimpl
        def ext_register_extension_flags(self):
            return {"alpha", 123}

    pm.register(Extension())

    assert extension_manager.collect_extension_flags() == ["alpha"]


def test_collect_extension_flags_skips_none_results(monkeypatch):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)

    class SetReturningExtension:
        @extension_manager.hookimpl
        def ext_register_extension_flags(self):
            return {"delta", "alpha"}

    class NoneReturningExtension:
        @extension_manager.hookimpl
        def ext_register_extension_flags(self):
            return None

    pm.register(SetReturningExtension())
    pm.register(NoneReturningExtension())

    assert extension_manager.collect_extension_flags() == ["alpha", "delta"]
