import threading
from collections.abc import Mapping

import pytest
from tomlkit import parse

from include.config.settings import GlobalConfig
from include.config.validation import (
    AuthThrottlePolicy,
    ConfigValidationError,
    DocumentCreationRiskPolicy,
    DocumentDownloadRiskPolicy,
    DocumentUploadPolicy,
    get_config_warnings,
    get_enabled_extensions,
    get_trusted_proxy_networks,
    parse_config_document,
    parse_trusted_proxy_networks,
    validate_config,
)


def _valid_config() -> dict:
    return {
        "extensions": {"enabled": []},
        "server": {"trusted_proxy_networks": ["127.0.0.1/32", "::1/128"]},
        "security": {
            "pepper": "test-pepper",
            "require_client_cert": False,
            "auth_throttle": {},
        },
    }


@pytest.fixture(autouse=True)
def clear_proxy_network_cache():
    parse_trusted_proxy_networks.cache_clear()
    yield
    parse_trusted_proxy_networks.cache_clear()


def test_valid_configuration_is_accepted():
    validate_config(_valid_config())


def test_registered_extension_validates_configuration():
    from include.extensions.manager import hookimpl, pm

    class RejectingExtension:
        @hookimpl
        def ext_validate_config(self, config):
            assert config is invalid_config
            raise ConfigValidationError("extension setting is invalid")

    invalid_config = _valid_config()
    plugin = RejectingExtension()
    pm.register(plugin, name="test_config_validator")
    try:
        with pytest.raises(ConfigValidationError, match="extension setting is invalid"):
            validate_config(invalid_config)
    finally:
        pm.unregister(name="test_config_validator")


def test_enabled_extensions_preserve_configuration_order():
    config = _valid_config()
    config["extensions"]["enabled"] = ["first_ext", "second_ext"]

    assert get_enabled_extensions(config) == ("first_ext", "second_ext")


@pytest.mark.parametrize(
    ("value", "message"),
    [
        ("sample_ext", "must be an array"),
        (["Invalid-Identifier"], "valid extension identifiers"),
        (["sample_ext", "sample_ext"], "duplicate identifier"),
        (["builtin"], "always enabled"),
    ],
)
def test_invalid_enabled_extensions_are_rejected(value, message):
    config = _valid_config()
    config["extensions"]["enabled"] = value

    with pytest.raises(ConfigValidationError, match=message):
        get_enabled_extensions(config)


def test_extensions_enabled_is_required():
    config = _valid_config()
    del config["extensions"]["enabled"]

    with pytest.raises(ConfigValidationError, match="extensions.enabled"):
        get_enabled_extensions(config)


def test_invalid_proxy_network_is_rejected():
    config = _valid_config()
    config["server"]["trusted_proxy_networks"] = ["not-a-cidr"]

    with pytest.raises(ConfigValidationError, match="server.trusted_proxy_networks"):
        validate_config(config)


def test_proxy_networks_must_be_an_array():
    config = _valid_config()
    config["server"]["trusted_proxy_networks"] = "10.0.0.0/8"

    with pytest.raises(ConfigValidationError, match="must be an array of CIDRs"):
        validate_config(config)


def test_proxy_network_entries_must_be_strings():
    config = _valid_config()
    config["server"]["trusted_proxy_networks"] = [10]

    with pytest.raises(ConfigValidationError, match="must be CIDR strings"):
        validate_config(config)


def test_auth_throttle_values_are_validated():
    config = _valid_config()
    config["security"]["auth_throttle"] = {"ip_failure_threshold": 0}

    with pytest.raises(ConfigValidationError, match="must be a positive integer"):
        validate_config(config)


def test_auth_throttle_delay_range_is_validated():
    config = _valid_config()
    config["security"]["auth_throttle"] = {
        "account_base_delay_seconds": 60,
        "account_max_delay_seconds": 30,
    }

    with pytest.raises(ConfigValidationError, match="must not exceed"):
        validate_config(config)


def test_client_certificate_ca_directory_is_validated(tmp_path):
    config = _valid_config()
    config["security"].update(
        {
            "require_client_cert": True,
            "client_cert_ca_path": str(tmp_path / "missing"),
        }
    )

    with pytest.raises(ConfigValidationError, match="client_cert_ca_path"):
        validate_config(config)


def test_client_certificate_flag_must_be_boolean():
    config = _valid_config()
    config["security"]["require_client_cert"] = "false"

    with pytest.raises(ConfigValidationError, match="must be a boolean"):
        validate_config(config)


def test_proxy_networks_follow_config_changes():
    config = _valid_config()
    config["server"]["trusted_proxy_networks"] = ["10.0.0.0/8"]

    initial_networks = get_trusted_proxy_networks(config)
    config["server"]["trusted_proxy_networks"] = ["192.0.2.0/24"]
    reloaded_networks = get_trusted_proxy_networks(config)

    assert str(initial_networks[0]) == "10.0.0.0/8"
    assert str(reloaded_networks[0]) == "192.0.2.0/24"


def test_unchanged_proxy_networks_reuse_parse_cache():
    config = _valid_config()
    config["server"]["trusted_proxy_networks"] = ["10.0.0.0/8"]

    initial_networks = get_trusted_proxy_networks(config)
    cached_networks = get_trusted_proxy_networks(config)
    cache_info = parse_trusted_proxy_networks.cache_info()

    assert cached_networks is initial_networks
    assert cache_info.hits == 1
    assert cache_info.misses == 1


def test_policy_is_built_from_validated_config():
    config = _valid_config()
    config["security"]["auth_throttle"] = {"ip_failure_threshold": 42}

    policy = AuthThrottlePolicy.from_config(config)

    assert policy.ip_failure_threshold == 42


def test_document_upload_policy_defaults_and_overrides():
    config = _valid_config()
    assert DocumentUploadPolicy.from_config(config).start_timeout_seconds == 3600

    config["document"] = {"upload": {"max_pending_documents_per_creator": 8}}
    assert (
        DocumentUploadPolicy.from_config(config).max_pending_documents_per_creator == 8
    )


def test_document_creation_risk_policy_defaults():
    policy = DocumentCreationRiskPolicy.from_config(_valid_config())

    assert policy.mode == "enforce"
    assert policy.account_capacity == 60
    assert policy.account_refill_tokens == 300
    assert policy.ip_capacity == 200
    assert policy.ip_refill_tokens == 1000


def test_document_download_risk_policy_defaults_and_overrides():
    config = _valid_config()
    policy = DocumentDownloadRiskPolicy.from_config(config)

    assert policy.mode == "observe"
    assert policy.issue_account_refill_tokens == 300
    assert policy.transfer_ip_refill_tokens == 1000
    assert policy.task_capacity == 5
    assert policy.task_refill_tokens == 10

    config["document"] = {
        "download": {"risk_control": {"mode": "enforce", "task_capacity": 8}}
    }
    policy = DocumentDownloadRiskPolicy.from_config(config)
    assert policy.mode == "enforce"
    assert policy.task_capacity == 8


@pytest.mark.parametrize(
    ("setting", "value", "message"),
    [
        ("mode", "disabled", "must be 'observe' or 'enforce'"),
        ("issue_account_capacity", 0, "positive integer"),
        ("ip_accounts_high", 4, "must be less than"),
        ("denials_high", 1, "must be less than"),
        ("high_cost", 201, "at least high_cost"),
        ("state_retention_seconds", 3599, "cover every risk-control window"),
    ],
)
def test_download_risk_policy_validates_settings(setting, value, message):
    config = _valid_config()
    config["document"] = {"download": {"risk_control": {setting: value}}}

    with pytest.raises(ConfigValidationError, match=message):
        validate_config(config)


def test_legacy_creation_rate_settings_are_ignored():
    config = _valid_config()
    config["document"] = {
        "upload": {
            "creation_rate_window_seconds": 300,
            "creation_rate_per_user": 50,
            "creation_rate_per_ip": 125,
        }
    }

    validate_config(config)
    policy = DocumentCreationRiskPolicy.from_config(config)

    assert policy == DocumentCreationRiskPolicy()
    assert get_config_warnings(config) == ()


def test_new_creation_risk_settings_override_ignored_legacy_settings():
    config = _valid_config()
    config["document"] = {
        "upload": {
            "creation_rate_per_user": 50,
            "creation_risk_control": {
                "account_refill_tokens": 75,
                "ip_refill_tokens": 250,
            },
        }
    }

    validate_config(config)
    policy = DocumentCreationRiskPolicy.from_config(config)

    assert policy.account_refill_tokens == 75
    assert policy.ip_refill_tokens == 250
    assert get_config_warnings(config) == ()


@pytest.mark.parametrize(
    ("setting", "value", "message"),
    [
        ("mode", "disabled", "must be 'observe' or 'enforce'"),
        ("account_capacity", 0, "positive integer"),
        ("pending_elevated_ratio", 1.1, "at most 1"),
        ("pending_high_ratio", 0.25, "must be less than"),
        ("ip_accounts_high", 4, "must be less than"),
        ("denials_high", 1, "must be less than"),
        ("high_cost", 201, "at least high_cost"),
        ("state_retention_seconds", 599, "cover every risk-control window"),
    ],
)
def test_creation_risk_policy_validates_settings(setting, value, message):
    config = _valid_config()
    config["document"] = {"upload": {"creation_risk_control": {setting: value}}}

    with pytest.raises(ConfigValidationError, match=message):
        validate_config(config)


@pytest.mark.parametrize(
    "upload",
    [
        {"start_timeout_seconds": 0},
        {"idle_timeout_seconds": True},
        {"idle_timeout_seconds": 10, "max_duration_seconds": 5},
        {"start_timeout_seconds": 10, "max_duration_seconds": 10},
    ],
)
def test_document_upload_policy_rejects_invalid_values(upload):
    config = _valid_config()
    config["document"] = {"upload": upload}

    with pytest.raises(ConfigValidationError, match="document.upload"):
        validate_config(config)


def test_empty_pepper_warning_is_centralized():
    config = _valid_config()
    config["security"]["pepper"] = ""

    assert "`pepper`" in get_config_warnings(config)[0]


def test_obsolete_document_name_duplicate_option_warns_and_is_ignored():
    config = _valid_config()
    config["document"] = {"allow_name_duplicate": True}

    warnings = get_config_warnings(config)

    assert len(warnings) == 1
    assert "obsolete and ignored" in warnings[0]
    assert "unique names" in warnings[0]


def test_invalid_reload_keeps_previous_configuration(tmp_path):
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        """
[server]
trusted_proxy_networks = ["not-a-cidr"]

[security]
pepper = "test-pepper"
require_client_cert = false
""".strip(),
        encoding="utf-8",
    )
    previous_data = parse(
        """
[server]
trusted_proxy_networks = ["127.0.0.1/32"]

[security]
pepper = "test-pepper"
require_client_cert = false
""".strip()
    )
    config = object.__new__(GlobalConfig)
    config._config_path = config_path
    config._data = previous_data
    config._lock = threading.Lock()
    config._initialized = True

    assert config.reload() is False
    assert config._data is previous_data


def test_global_config_implements_read_only_mapping_contract():
    config = object.__new__(GlobalConfig)
    config._data = parse("[server]\nport = 8765")
    config._lock = threading.Lock()

    assert isinstance(config, Mapping)
    assert len(config) == 1
    assert list(config) == ["server"]
    assert "server" in config
    assert config.get("missing", "fallback") == "fallback"
    assert config["server"]["port"] == 8765


def test_invalid_toml_is_reported_as_configuration_error():
    with pytest.raises(ConfigValidationError, match="Invalid TOML configuration"):
        parse_config_document("[server")
