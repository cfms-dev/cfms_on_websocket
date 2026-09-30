from pathlib import Path

import pytest
import tomlkit

from include.config.settings import GlobalConfig
from include.config.validation import ConfigValidationError

_SAMPLE_PATH = Path(__file__).resolve().parents[2] / "src" / "config.toml.sample"


@pytest.fixture
def bootstrap_config(tmp_path, monkeypatch):
    config_path = tmp_path / "config.toml"
    document = tomlkit.parse(_SAMPLE_PATH.read_text(encoding="utf-8"))
    config_path.write_text(tomlkit.dumps(document), encoding="utf-8")
    monkeypatch.setattr(GlobalConfig, "_start_watching", lambda _self: None)
    config = object.__new__(GlobalConfig)
    config._initialized = False
    return config, config_path, document


def test_bootstrap_loading_does_not_generate_or_write_secrets(bootstrap_config):
    config, config_path, _document = bootstrap_config
    original = config_path.read_bytes()

    config.__init__(str(config_path))

    assert config_path.read_bytes() == original
    assert config["server"]["secret_key"] == ""
    assert config["security"]["pepper"] == ""
    assert not (config_path.parent / "app.db").exists()


def test_legacy_options_are_available_for_maintenance_but_block_startup(
    bootstrap_config,
):
    config, config_path, document = bootstrap_config
    document["server"]["name"] = "Legacy Server"
    document["extensions"]["brute_force_lockdown"] = {"failure_threshold": 12}
    config_path.write_text(tomlkit.dumps(document), encoding="utf-8")

    config.__init__(str(config_path))

    assert "name" not in config["server"]
    assert "brute_force_lockdown" not in config["extensions"]
    with pytest.raises(ConfigValidationError, match="migrate-options"):
        config.require_migrated_options()
    assert "Legacy Server" in config_path.read_text(encoding="utf-8")


@pytest.mark.parametrize("legacy_path", ["name", "brute_force_lockdown"])
def test_reintroducing_database_options_rejects_file_reload(
    bootstrap_config, legacy_path
):
    config, config_path, document = bootstrap_config
    config.__init__(str(config_path))
    previous = config._data
    if legacy_path == "name":
        document["server"]["name"] = "Reintroduced name"
    else:
        document["extensions"]["brute_force_lockdown"] = {}
    config_path.write_text(tomlkit.dumps(document), encoding="utf-8")

    assert config.reload() is False
    assert config._data is previous
    config.require_migrated_options()


def test_explicit_secret_initialization_updates_loaded_bootstrap(bootstrap_config):
    config, config_path, _document = bootstrap_config
    config.__init__(str(config_path))

    config.initialize_secrets()

    stored = tomlkit.parse(config_path.read_text(encoding="utf-8"))
    assert len(stored["server"]["secret_key"]) == 64
    assert len(stored["security"]["pepper"]) == 64
    assert config["server"]["secret_key"] == stored["server"]["secret_key"]
    assert config["security"]["pepper"] == stored["security"]["pepper"]


def test_missing_initialization_marker_does_not_rotate_existing_secrets(
    bootstrap_config,
):
    config, config_path, document = bootstrap_config
    document["server"]["secret_key"] = "existing-server-secret"
    document["security"]["pepper"] = "existing-security-pepper"
    config_path.write_text(tomlkit.dumps(document), encoding="utf-8")
    original = config_path.read_bytes()
    config.__init__(str(config_path))

    config.initialize_secrets()

    assert config_path.read_bytes() == original
    assert config["server"]["secret_key"] == "existing-server-secret"
    assert config["security"]["pepper"] == "existing-security-pepper"
