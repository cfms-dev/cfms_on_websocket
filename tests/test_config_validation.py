import threading

import pytest
from tomlkit import parse

from include.config.settings import GlobalConfig
from include.config.validation import (
    AuthThrottlePolicy,
    ConfigValidationError,
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


def test_empty_pepper_warning_is_centralized():
    config = _valid_config()
    config["security"]["pepper"] = ""

    assert "`pepper`" in get_config_warnings(config)[0]


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


def test_invalid_toml_is_reported_as_configuration_error():
    with pytest.raises(ConfigValidationError, match="Invalid TOML configuration"):
        parse_config_document("[server")
