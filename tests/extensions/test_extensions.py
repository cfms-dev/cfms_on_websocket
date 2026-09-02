import sys
from pathlib import Path
from types import SimpleNamespace

import pluggy
import pytest

import include.extensions.manager as extension_manager
from include.config.constants import CORE_VERSION
from include.config.version import Version

EXTENSION_MODULE_NAMES = {
    "builtin",
    "compatible_ext",
    "consumer_ext",
    "cycle_a",
    "cycle_b",
    "dependency_ext",
    "disabled_ext",
    "first_ext",
    "http_api",
    "incompatible_ext",
    "missing_entry_ext",
    "plain_validator_ext",
    "root_file_ext",
    "sample_ext",
    "second_ext",
    "validated_ext",
}


def _toml_value(value) -> str:
    if isinstance(value, str):
        return repr(value)
    if isinstance(value, list):
        return f"[{', '.join(repr(item) for item in value)}]"
    return str(value)


def _manifest_source(
    default_identifier: str,
    *,
    manifest_version: int = 2,
    compatibility: dict | None = None,
    dependencies: dict | None = None,
    **overrides,
) -> str:
    values = {
        "identifier": default_identifier,
        "name": "Sample Extension",
        "version": "1.0.0",
        "authors": ["Test Author"],
        "license": "Apache-2.0",
    }
    values.update(overrides)
    lines = [f"manifest_version = {manifest_version}", "", "[extension]"]
    for key, value in values.items():
        lines.append(f"{key} = {_toml_value(value)}")
    if compatibility is not None:
        lines.extend(("", "[compatibility]"))
        for key, value in compatibility.items():
            lines.append(f"{key} = {_toml_value(value)}")
    if dependencies is not None:
        lines.extend(("", "[dependencies.extensions]"))
        for key, value in dependencies.items():
            lines.append(f"{key} = {_toml_value(value)}")
    return "\n".join(lines) + "\n"


def _write_extension(root: Path, name: str, source: str = "VALUE = 1\n") -> Path:
    extension_dir = root / name
    extension_dir.mkdir()
    (extension_dir / "_extension.py").write_text(source, encoding="utf-8")
    return extension_dir


def _write_manifest(extension_dir: Path, identifier: str, **overrides) -> Path:
    manifest_path = extension_dir / "manifest.toml"
    manifest_path.write_text(
        _manifest_source(identifier, **overrides), encoding="utf-8"
    )
    return manifest_path


def _write_builtin(
    root: Path, source: str = "VALUE = 1\n", **manifest_overrides
) -> Path:
    extension_dir = _write_extension(root, "builtin", source)
    _write_manifest(extension_dir, "builtin", **manifest_overrides)
    return extension_dir


def _fresh_plugin_manager() -> pluggy.PluginManager:
    pm = pluggy.PluginManager("cfms")
    pm.add_hookspecs(extension_manager.ServerHookSpecs)
    return pm


def _load_extensions(root: Path, enabled: list[str]) -> None:
    extension_manager.load_extensions_from_directory(
        root,
        enabled,
        config={"extensions": {"enabled": enabled}},
    )


@pytest.fixture(autouse=True)
def restore_extension_modules():
    saved_modules = {
        name: sys.modules.get(name)
        for name in EXTENSION_MODULE_NAMES
        if name in sys.modules
    }
    saved_metadata = extension_manager._loaded_extension_metadata.copy()
    extension_manager._loaded_extension_metadata.clear()
    yield
    extension_manager._loaded_extension_metadata.clear()
    extension_manager._loaded_extension_metadata.update(saved_metadata)
    for name in EXTENSION_MODULE_NAMES:
        if name in saved_modules:
            sys.modules[name] = saved_modules[name]
        else:
            sys.modules.pop(name, None)


def test_root_python_files_are_ignored(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_builtin(tmp_path)

    (tmp_path / "root_file_ext.py").write_text(
        "raise RuntimeError('root file should not be loaded')\n",
        encoding="utf-8",
    )

    _load_extensions(tmp_path, [])

    assert not pm.has_plugin("root_file_ext")
    assert "root_file_ext" not in sys.modules


def test_directory_extension_entrypoint_is_loaded(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_builtin(tmp_path)
    extension_dir = _write_extension(tmp_path, "different_folder", "VALUE = 42\n")
    _write_manifest(extension_dir, "sample_ext")

    _load_extensions(tmp_path, ["sample_ext"])

    assert pm.has_plugin("sample_ext")
    assert pm.get_plugin("sample_ext").VALUE == 42


@pytest.mark.parametrize("minimum_version", ["1.2.2", "1.2.3"])
def test_compatible_extension_minimum_version_loads(
    monkeypatch, tmp_path, minimum_version
):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    monkeypatch.setattr(extension_manager, "CORE_VERSION", Version("1.2.3"))
    _write_builtin(tmp_path)
    extension_dir = _write_extension(tmp_path, "compatible_folder")
    _write_manifest(
        extension_dir,
        "compatible_ext",
        compatibility={"minimum_server_version": minimum_version},
    )

    _load_extensions(tmp_path, ["compatible_ext"])

    assert pm.has_plugin("builtin")
    assert pm.has_plugin("compatible_ext")


def test_directory_without_entrypoint_is_skipped(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_builtin(tmp_path)
    (tmp_path / "missing_entry_ext").mkdir()

    _load_extensions(tmp_path, [])

    assert not pm.has_plugin("missing_entry_ext")
    assert "missing_entry_ext" not in sys.modules


def test_extension_manifest_is_parsed(tmp_path):
    extension_dir = _write_extension(tmp_path, "different_folder")
    manifest_path = _write_manifest(
        extension_dir,
        "sample_ext",
        description="A sample extension",
        homepage="https://example.test/sample",
        compatibility={"minimum_server_version": "0.4.1.260811_alpha"},
    )

    manifest = extension_manager.parse_extension_manifest(manifest_path)

    assert manifest.extension.identifier == "sample_ext"
    assert manifest.extension.name == "Sample Extension"
    assert manifest.extension.authors == ("Test Author",)
    assert manifest.extension.description == "A sample extension"
    assert str(manifest.compatibility.minimum_server_version) == ("0.4.1.260811_alpha")


def test_extension_manifest_compatibility_is_optional(tmp_path):
    manifest_path = tmp_path / "manifest.toml"
    manifest_path.write_text(_manifest_source("sample_ext"), encoding="utf-8")

    manifest = extension_manager.parse_extension_manifest(manifest_path)

    assert manifest.compatibility.minimum_server_version is None


def test_manifest_version_three_parses_pep440_dependencies(tmp_path):
    manifest_path = tmp_path / "manifest.toml"
    manifest_path.write_text(
        _manifest_source(
            "consumer_ext",
            manifest_version=3,
            version="1.0.0rc1",
            dependencies={"dependency_ext": "2.1"},
        ),
        encoding="utf-8",
    )

    manifest = extension_manager.parse_extension_manifest(manifest_path)

    assert manifest.manifest_version == 3
    assert manifest.dependencies.extensions == {"dependency_ext": "2.1"}


@pytest.mark.parametrize(
    "source",
    [
        _manifest_source(
            "consumer_ext",
            manifest_version=3,
            version="not a version",
        ),
        _manifest_source(
            "consumer_ext",
            manifest_version=3,
            dependencies={"dependency_ext": "not a version"},
        ),
        _manifest_source(
            "consumer_ext",
            dependencies={"dependency_ext": "1.0.0"},
        ),
    ],
)
def test_invalid_manifest_dependency_versions_are_rejected(tmp_path, source):
    manifest_path = tmp_path / "manifest.toml"
    manifest_path.write_text(source, encoding="utf-8")

    with pytest.raises(extension_manager.ExtensionManifestError):
        extension_manager.parse_extension_manifest(manifest_path)


@pytest.mark.parametrize(
    ("overrides", "field"),
    [
        ({"manifest_version": 4}, "manifest_version"),
        ({"identifier": 1}, "identifier"),
        ({"identifier": "Invalid-Identifier"}, "identifier"),
        ({"identifier": " sample_ext "}, "identifier"),
        ({"identifier": "core"}, "identifier"),
        ({"identifier": "x" * 256}, "identifier"),
        ({"authors": []}, "authors"),
        ({"unknown_field": "value"}, "unknown_field"),
    ],
)
def test_invalid_extension_manifest_is_rejected(tmp_path, overrides, field):
    manifest_path = tmp_path / "manifest.toml"
    manifest_path.write_text(
        _manifest_source("sample_ext", **overrides), encoding="utf-8"
    )

    with pytest.raises(extension_manager.ExtensionManifestError) as error:
        extension_manager.parse_extension_manifest(manifest_path)

    message = str(error.value)
    assert field in message
    assert "\n" not in message
    assert "errors.pydantic.dev" not in message


def test_maximum_length_extension_identifier_is_accepted(tmp_path):
    identifier = "a" + "x" * 254
    manifest_path = tmp_path / "manifest.toml"
    manifest_path.write_text(_manifest_source(identifier), encoding="utf-8")

    manifest = extension_manager.parse_extension_manifest(manifest_path)

    assert manifest.extension.identifier == identifier


@pytest.mark.parametrize(
    ("source", "field"),
    [
        (
            _manifest_source(
                "sample_ext",
                compatibility={"minimum_server_version": "1.2.3junk"},
            ),
            "compatibility.minimum_server_version",
        ),
        (_manifest_source("sample_ext") + "\n[unknown]\nvalue = 1\n", "unknown"),
        (
            _manifest_source(
                "sample_ext",
                compatibility={"unknown_field": "value"},
            ),
            "compatibility.unknown_field",
        ),
    ],
)
def test_invalid_manifest_sections_are_rejected(tmp_path, source, field):
    manifest_path = tmp_path / "manifest.toml"
    manifest_path.write_text(source, encoding="utf-8")

    with pytest.raises(extension_manager.ExtensionManifestError) as error:
        extension_manager.parse_extension_manifest(manifest_path)

    assert field in str(error.value)


def test_flat_manifest_version_one_is_rejected(tmp_path):
    manifest_path = tmp_path / "manifest.toml"
    manifest_path.write_text(
        "\n".join(
            [
                "manifest_version = 1",
                "identifier = 'sample_ext'",
                "name = 'Sample Extension'",
                "version = '1.0.0'",
                "authors = ['Test Author']",
                "license = 'Apache-2.0'",
                "",
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(extension_manager.ExtensionManifestError) as error:
        extension_manager.parse_extension_manifest(manifest_path)

    message = str(error.value)
    assert "manifest_version" in message
    assert "extension" in message


def test_extension_manifest_requires_core_fields(tmp_path):
    manifest_path = tmp_path / "manifest.toml"
    manifest_path.write_text("manifest_version = 2\n\n[extension]\n", encoding="utf-8")

    with pytest.raises(extension_manager.ExtensionManifestError) as error:
        extension_manager.parse_extension_manifest(manifest_path)

    message = str(error.value)
    for field in ("identifier", "name", "version", "authors", "license"):
        assert field in message


def test_bundled_extension_catalog_is_valid():
    extension_root = Path(extension_manager.__file__).parent

    discovered = extension_manager.discover_extensions(extension_root)

    assert set(discovered) == {
        "builtin",
        "brute_force_lockdown",
        "http_api",
        "oidc_sso",
        "scheduling",
    }


def test_builtin_extension_manifest_matches_core_version():
    extension_root = Path(extension_manager.__file__).parent

    manifest = extension_manager.discover_extensions(extension_root)["builtin"].manifest

    assert manifest.extension.version == CORE_VERSION.original
    assert manifest.compatibility.minimum_server_version == CORE_VERSION


@pytest.mark.parametrize("missing", ["manifest", "entrypoint"])
def test_incomplete_extension_candidate_is_rejected(tmp_path, missing):
    extension_dir = _write_extension(tmp_path, "sample")
    _write_manifest(extension_dir, "sample_ext")
    if missing == "manifest":
        (extension_dir / "manifest.toml").unlink()
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
    _write_builtin(
        tmp_path,
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

    _load_extensions(tmp_path, [])
    _load_extensions(tmp_path, [])

    assert pm.has_plugin("builtin")
    assert counter_path.read_text(encoding="utf-8") == "1"
    assert info_messages == []


def test_disabled_extension_is_not_imported(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    monkeypatch.setattr(extension_manager, "CORE_VERSION", Version("1.2.3"))
    _write_builtin(tmp_path)
    extension_dir = _write_extension(
        tmp_path, "disabled_folder", "raise RuntimeError('must not import')\n"
    )
    _write_manifest(
        extension_dir,
        "disabled_ext",
        compatibility={"minimum_server_version": "2.0.0"},
    )

    _load_extensions(tmp_path, [])

    assert not pm.has_plugin("disabled_ext")
    assert "disabled_ext" not in sys.modules


def test_incompatible_builtin_is_rejected_before_import(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    monkeypatch.setattr(extension_manager, "CORE_VERSION", Version("1.2.3"))
    _write_builtin(
        tmp_path,
        "raise RuntimeError('must not import')\n",
        compatibility={"minimum_server_version": "2.0.0"},
    )

    with pytest.raises(
        extension_manager.ExtensionLoadError,
        match=(
            "Extension 'builtin' requires server version 2.0.0 or newer; "
            "current server version is 1.2.3"
        ),
    ):
        _load_extensions(tmp_path, [])

    assert not pm.has_plugin("builtin")
    assert "builtin" not in sys.modules


def test_extensions_are_registered_in_configuration_order(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_builtin(tmp_path)
    first = _write_extension(tmp_path, "z_folder")
    second = _write_extension(tmp_path, "a_folder")
    _write_manifest(first, "first_ext")
    _write_manifest(second, "second_ext")

    _load_extensions(tmp_path, ["first_ext", "second_ext"])

    registered = [name for name, _plugin in pm.list_name_plugin()]
    assert registered == ["builtin", "first_ext", "second_ext"]
    metadata = extension_manager.get_loaded_extension_metadata()
    assert [entry.identifier for entry in metadata] == [
        "builtin",
        "first_ext",
        "second_ext",
    ]
    assert [entry.version for entry in metadata] == ["1.0.0", "1.0.0", "1.0.0"]


def test_dependencies_load_first_with_stable_configuration_order(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_builtin(tmp_path)
    consumer = _write_extension(tmp_path, "consumer")
    dependency = _write_extension(tmp_path, "dependency")
    unrelated = _write_extension(tmp_path, "unrelated")
    _write_manifest(
        consumer,
        "consumer_ext",
        manifest_version=3,
        dependencies={"dependency_ext": "1.0.0"},
    )
    _write_manifest(dependency, "dependency_ext", manifest_version=3)
    _write_manifest(unrelated, "first_ext")

    _load_extensions(
        tmp_path,
        ["consumer_ext", "dependency_ext", "first_ext"],
    )

    assert [name for name, _plugin in pm.list_name_plugin()] == [
        "builtin",
        "dependency_ext",
        "consumer_ext",
        "first_ext",
    ]


def test_dependency_can_add_hook_spec_before_consumer_registration(
    monkeypatch, tmp_path
):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_builtin(tmp_path)
    framework = _write_extension(
        tmp_path,
        "http_framework",
        "\n".join(
            [
                "from include.extensions.manager import hookimpl, hookspec, pm",
                "class HttpHookSpecs:",
                "    @hookspec",
                "    def ext_register_http_routers(self):",
                "        pass",
                "pm.add_hookspecs(HttpHookSpecs)",
                "http_hookimpl = hookimpl",
                "",
            ]
        ),
    )
    consumer = _write_extension(
        tmp_path,
        "consumer",
        "\n".join(
            [
                "from http_api import http_hookimpl",
                "@http_hookimpl",
                "def ext_register_http_routers():",
                "    return ('consumer',)",
                "",
            ]
        ),
    )
    _write_manifest(framework, "http_api", manifest_version=3)
    _write_manifest(
        consumer,
        "consumer_ext",
        manifest_version=3,
        dependencies={"http_api": "1.0.0"},
    )

    _load_extensions(tmp_path, ["consumer_ext", "http_api"])

    assert hasattr(pm.hook, "ext_register_http_routers")
    assert pm.hook.ext_register_http_routers() == [("consumer",)]


@pytest.mark.parametrize(
    ("install_dependency", "enabled", "message"),
    [
        (False, ["consumer_ext"], "but it is not installed"),
        (True, ["consumer_ext"], "but it is not enabled"),
    ],
)
def test_missing_or_disabled_dependency_prevents_all_imports(
    monkeypatch,
    tmp_path,
    install_dependency,
    enabled,
    message,
):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    imported_marker = tmp_path / "builtin-imported"
    _write_builtin(
        tmp_path,
        f"open({str(imported_marker)!r}, 'w').close()\n",
    )
    consumer = _write_extension(tmp_path, "consumer")
    _write_manifest(
        consumer,
        "consumer_ext",
        manifest_version=3,
        dependencies={"dependency_ext": "1.0.0"},
    )
    if install_dependency:
        dependency = _write_extension(tmp_path, "dependency")
        _write_manifest(dependency, "dependency_ext", manifest_version=3)

    with pytest.raises(extension_manager.ExtensionLoadError, match=message):
        _load_extensions(tmp_path, enabled)

    assert pm.list_name_plugin() == []
    assert not imported_marker.exists()


def test_dependency_minimum_version_is_enforced_before_import(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    imported_marker = tmp_path / "builtin-imported"
    _write_builtin(
        tmp_path,
        f"open({str(imported_marker)!r}, 'w').close()\n",
    )
    consumer = _write_extension(tmp_path, "consumer")
    dependency = _write_extension(tmp_path, "dependency")
    _write_manifest(
        consumer,
        "consumer_ext",
        manifest_version=3,
        dependencies={"dependency_ext": "2.0.0"},
    )
    _write_manifest(
        dependency,
        "dependency_ext",
        manifest_version=3,
        version="1.9.9",
    )

    with pytest.raises(
        extension_manager.ExtensionLoadError,
        match="version 2.0.0 or newer; installed version is 1.9.9",
    ):
        _load_extensions(tmp_path, ["consumer_ext", "dependency_ext"])

    assert pm.list_name_plugin() == []
    assert not imported_marker.exists()


def test_transitive_dependencies_must_all_be_explicitly_enabled(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_builtin(tmp_path)
    consumer = _write_extension(tmp_path, "consumer")
    dependency = _write_extension(tmp_path, "dependency")
    transitive = _write_extension(tmp_path, "transitive")
    _write_manifest(
        consumer,
        "consumer_ext",
        manifest_version=3,
        dependencies={"dependency_ext": "1.0.0"},
    )
    _write_manifest(
        dependency,
        "dependency_ext",
        manifest_version=3,
        dependencies={"second_ext": "1.0.0"},
    )
    _write_manifest(transitive, "second_ext", manifest_version=3)

    with pytest.raises(
        extension_manager.ExtensionLoadError,
        match="requires extension 'second_ext', but it is not enabled",
    ):
        _load_extensions(tmp_path, ["consumer_ext", "dependency_ext"])

    assert pm.list_name_plugin() == []


def test_self_dependency_is_rejected_before_import(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_builtin(tmp_path)
    consumer = _write_extension(tmp_path, "consumer")
    _write_manifest(
        consumer,
        "consumer_ext",
        manifest_version=3,
        dependencies={"consumer_ext": "1.0.0"},
    )

    with pytest.raises(
        extension_manager.ExtensionLoadError,
        match="cannot depend on itself",
    ):
        _load_extensions(tmp_path, ["consumer_ext"])

    assert pm.list_name_plugin() == []


def test_dependency_cycle_is_rejected_before_import(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_builtin(tmp_path)
    first = _write_extension(tmp_path, "cycle_a")
    second = _write_extension(tmp_path, "cycle_b")
    _write_manifest(
        first,
        "cycle_a",
        manifest_version=3,
        dependencies={"cycle_b": "1.0.0"},
    )
    _write_manifest(
        second,
        "cycle_b",
        manifest_version=3,
        dependencies={"cycle_a": "1.0.0"},
    )

    with pytest.raises(
        extension_manager.ExtensionLoadError,
        match="cycle_a -> cycle_b -> cycle_a",
    ):
        _load_extensions(tmp_path, ["cycle_a", "cycle_b"])

    assert pm.list_name_plugin() == []


def test_builtin_extension_cannot_declare_dependencies(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_builtin(
        tmp_path,
        manifest_version=3,
        dependencies={"dependency_ext": "1.0.0"},
    )
    dependency = _write_extension(tmp_path, "dependency")
    _write_manifest(dependency, "dependency_ext", manifest_version=3)

    with pytest.raises(
        extension_manager.ExtensionLoadError,
        match="built-in extension cannot declare extension dependencies",
    ):
        _load_extensions(tmp_path, ["dependency_ext"])

    assert pm.list_name_plugin() == []


def test_duplicate_enabled_extension_identifiers_are_rejected(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_builtin(tmp_path)
    extension_dir = _write_extension(tmp_path, "sample_folder")
    _write_manifest(extension_dir, "sample_ext")

    with pytest.raises(
        extension_manager.ExtensionDiscoveryError,
        match="Enabled extension identifiers must be unique",
    ):
        _load_extensions(tmp_path, ["sample_ext", "sample_ext"])

    assert not pm.has_plugin("builtin")
    assert not pm.has_plugin("sample_ext")


def test_missing_configured_extension_is_rejected(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_builtin(tmp_path)

    with pytest.raises(
        extension_manager.ExtensionDiscoveryError,
        match="Configured extensions were not found: missing_ext",
    ):
        _load_extensions(tmp_path, ["missing_ext"])


def test_enabled_extension_import_failure_is_fatal(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_builtin(tmp_path)
    extension_dir = _write_extension(
        tmp_path, "broken_folder", "raise RuntimeError('broken extension')\n"
    )
    _write_manifest(extension_dir, "sample_ext")

    with pytest.raises(
        extension_manager.ExtensionLoadError,
        match="Failed to load extension 'sample_ext'",
    ):
        _load_extensions(tmp_path, ["sample_ext"])

    assert not pm.has_plugin("sample_ext")
    assert "sample_ext" not in sys.modules


def test_extension_batch_rolls_back_when_later_import_fails(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_builtin(tmp_path)
    first = _write_extension(tmp_path, "first_folder")
    second = _write_extension(
        tmp_path, "second_folder", "raise RuntimeError('broken second extension')\n"
    )
    _write_manifest(first, "first_ext")
    _write_manifest(second, "second_ext")

    with pytest.raises(
        extension_manager.ExtensionLoadError,
        match="Failed to load extension 'second_ext'",
    ):
        _load_extensions(tmp_path, ["first_ext", "second_ext"])

    assert not pm.has_plugin("builtin")
    assert not pm.has_plugin("first_ext")
    assert not pm.has_plugin("second_ext")
    assert "builtin" not in sys.modules
    assert "first_ext" not in sys.modules
    assert "second_ext" not in sys.modules
    assert extension_manager.get_loaded_extension_metadata() == ()


def test_incompatible_extension_prevents_entire_batch_import(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    monkeypatch.setattr(extension_manager, "CORE_VERSION", Version("1.2.3"))

    builtin_marker = tmp_path / "builtin-imported"
    compatible_marker = tmp_path / "compatible-imported"
    incompatible_marker = tmp_path / "incompatible-imported"
    _write_builtin(tmp_path, f"open({str(builtin_marker)!r}, 'w').close()\n")
    compatible = _write_extension(
        tmp_path,
        "compatible_folder",
        f"open({str(compatible_marker)!r}, 'w').close()\n",
    )
    incompatible = _write_extension(
        tmp_path,
        "incompatible_folder",
        f"open({str(incompatible_marker)!r}, 'w').close()\n",
    )
    _write_manifest(compatible, "compatible_ext")
    _write_manifest(
        incompatible,
        "incompatible_ext",
        compatibility={"minimum_server_version": "2.0.0"},
    )

    with pytest.raises(
        extension_manager.ExtensionLoadError,
        match=(
            "Extension 'incompatible_ext' requires server version 2.0.0 or newer; "
            "current server version is 1.2.3"
        ),
    ):
        _load_extensions(tmp_path, ["compatible_ext", "incompatible_ext"])

    assert pm.list_name_plugin() == []
    assert not builtin_marker.exists()
    assert not compatible_marker.exists()
    assert not incompatible_marker.exists()
    assert "builtin" not in sys.modules
    assert "compatible_ext" not in sys.modules
    assert "incompatible_ext" not in sys.modules


def test_enabled_extension_config_failure_is_fatal(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_builtin(tmp_path)
    extension_dir = _write_extension(
        tmp_path,
        "validated_folder",
        "\n".join(
            [
                "from include.config.validation import ConfigValidationError",
                "from include.extensions.manager import hookimpl",
                "@hookimpl",
                "def ext_validate_config(config):",
                "    raise ConfigValidationError('invalid extension config')",
                "",
            ]
        ),
    )
    _write_manifest(extension_dir, "validated_ext")

    with pytest.raises(
        extension_manager.ExtensionLoadError,
        match=(
            "Failed to validate loaded extension configuration: "
            "invalid extension config"
        ),
    ):
        _load_extensions(tmp_path, ["validated_ext"])

    assert not pm.has_plugin("builtin")
    assert not pm.has_plugin("validated_ext")
    assert "builtin" not in sys.modules
    assert "validated_ext" not in sys.modules


def test_undecorated_config_validator_is_not_called(monkeypatch, tmp_path):
    pm = _fresh_plugin_manager()
    monkeypatch.setattr(extension_manager, "pm", pm)
    _write_builtin(tmp_path)
    extension_dir = _write_extension(
        tmp_path,
        "plain_validator_folder",
        "\n".join(
            [
                "def ext_validate_config(config):",
                "    raise RuntimeError('must only run as a Pluggy hook')",
                "",
            ]
        ),
    )
    _write_manifest(extension_dir, "plain_validator_ext")

    _load_extensions(tmp_path, ["plain_validator_ext"])

    assert pm.has_plugin("plain_validator_ext")


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
