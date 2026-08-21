import threading
from collections.abc import Mapping

import pytest
from tomlkit import parse

from include.config.settings import GlobalConfig
from include.config.validation import (
    AdmissionControlPolicy,
    AuthThrottlePolicy,
    ConfigValidationError,
    DocumentCreationRiskPolicy,
    DocumentDownloadRiskPolicy,
    DocumentUploadPolicy,
    IdentityPermissionRetentionPolicy,
    RequestRateControlPolicy,
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
        "server": {
            "file_chunk_size": 2 * 1024 * 1024,
            "trusted_proxy_networks": ["127.0.0.1/32", "::1/128"],
        },
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
        ([1], "valid extension identifiers"),
        (["Invalid-Identifier"], "valid extension identifiers"),
        ([" sample_ext "], "valid extension identifiers"),
        (["x" * 256], "valid extension identifiers"),
        (["core"], "valid extension identifiers"),
        (["sample_ext", "sample_ext"], "duplicate identifier"),
        (["builtin"], "always enabled"),
    ],
)
def test_invalid_enabled_extensions_are_rejected(value, message):
    config = _valid_config()
    config["extensions"]["enabled"] = value

    with pytest.raises(ConfigValidationError, match=message):
        get_enabled_extensions(config)


def test_maximum_length_extension_identifier_is_accepted():
    identifier = "a" + "x" * 254
    config = _valid_config()
    config["extensions"]["enabled"] = [identifier]

    assert get_enabled_extensions(config) == (identifier,)


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


@pytest.mark.parametrize("value", [True, 0, -1, 1.5, "65536"])
def test_file_chunk_size_must_be_a_positive_integer(value):
    config = _valid_config()
    config["server"]["file_chunk_size"] = value

    with pytest.raises(
        ConfigValidationError, match="server.file_chunk_size must be a positive integer"
    ):
        validate_config(config)


def test_file_chunk_size_is_required():
    config = _valid_config()
    del config["server"]["file_chunk_size"]

    with pytest.raises(ConfigValidationError, match="server.file_chunk_size"):
        validate_config(config)


def test_auth_throttle_values_are_validated():
    config = _valid_config()
    config["security"]["auth_throttle"] = {"ip_failure_threshold": 0}

    with pytest.raises(ConfigValidationError) as error:
        validate_config(config)

    assert "security.auth_throttle.ip_failure_threshold" in str(error.value)


def test_auth_throttle_delay_range_is_validated():
    config = _valid_config()
    config["security"]["auth_throttle"] = {
        "account_base_delay_seconds": 60,
        "account_max_delay_seconds": 30,
    }

    with pytest.raises(ConfigValidationError, match="must not exceed"):
        validate_config(config)


def test_request_rate_control_defaults_to_observation_mode():
    config = _valid_config()

    policy = RequestRateControlPolicy.from_config(config)

    assert policy.mode == "observe"
    assert policy.cost_for("unconfigured") == 1
    assert AdmissionControlPolicy.from_config(config).max_connections == 64


def test_identity_permission_retention_defaults_and_overrides():
    config = _valid_config()
    policy = IdentityPermissionRetentionPolicy.from_config(config)

    assert policy.retention_days == 30
    assert policy.cleanup_interval_seconds == 3600
    assert policy.batch_size == 500

    config["identity"] = {
        "permission_retention": {
            "retention_days": 14,
            "cleanup_interval_seconds": 600,
            "batch_size": 100,
        }
    }
    policy = IdentityPermissionRetentionPolicy.from_config(config)

    assert policy.retention_days == 14
    assert policy.cleanup_interval_seconds == 600
    assert policy.batch_size == 100


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("retention_days", 0),
        ("cleanup_interval_seconds", -1),
        ("batch_size", True),
    ],
)
def test_identity_permission_retention_rejects_invalid_values(setting, value):
    config = _valid_config()
    config["identity"] = {"permission_retention": {setting: value}}

    with pytest.raises(ConfigValidationError) as error:
        validate_config(config)

    assert f"identity.permission_retention.{setting}" in str(error.value)


@pytest.mark.parametrize(
    ("setting", "value", "expected_fragment"),
    [
        ("mode", "sometimes", "security.request_rate_control.mode"),
        (
            "account_capacity",
            0,
            "security.request_rate_control.account_capacity",
        ),
        ("state_retention_seconds", 1, "cover every refill period"),
        (
            "action_costs",
            {"search": 0},
            "security.request_rate_control.action_costs",
        ),
        ("action_costs", {"search": 1_000}, "must not exceed"),
    ],
)
def test_request_rate_control_values_are_validated(setting, value, expected_fragment):
    config = _valid_config()
    config["security"]["request_rate_control"] = {setting: value}

    with pytest.raises(ConfigValidationError) as error:
        validate_config(config)

    assert expected_fragment in str(error.value)


def test_request_rate_control_action_cost_overrides_handler_default():
    config = _valid_config()
    config["security"]["request_rate_control"] = {"action_costs": {"search": 5}}

    policy = RequestRateControlPolicy.from_config(config)

    assert policy.cost_for("search", 2) == 5
    assert policy.cost_for("list_users", 2) == 2


def test_admission_control_rejects_per_identity_limit_above_global_limit():
    config = _valid_config()
    config["server"]["admission_control"] = {
        "max_connections": 4,
        "max_connections_per_ip": 5,
    }

    with pytest.raises(ConfigValidationError, match="must not exceed"):
        validate_config(config)


def test_rate_limit_provider_selection_is_validated():
    config = _valid_config()
    config["provider"] = {"rate_limit": "database"}

    with pytest.raises(ConfigValidationError, match="provider.rate_limit"):
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


def test_policy_sources_preserve_required_root_sections():
    with pytest.raises(ConfigValidationError) as security_error:
        AuthThrottlePolicy.from_config({})
    with pytest.raises(ConfigValidationError) as server_error:
        AdmissionControlPolicy.from_config({})

    assert str(security_error.value) == "Missing configuration section 'security'"
    assert str(server_error.value) == "Missing configuration section 'server'"


def test_document_policy_sources_preserve_optional_section_semantics():
    assert DocumentUploadPolicy.from_config({}) == DocumentUploadPolicy()
    assert DocumentDownloadRiskPolicy.from_config({}) == DocumentDownloadRiskPolicy()
    assert (
        DocumentCreationRiskPolicy.from_config(
            {"document": {"upload": {"creation_risk_control": None}}}
        )
        == DocumentCreationRiskPolicy()
    )


@pytest.mark.parametrize(
    ("policy_type", "config", "path"),
    [
        (
            AuthThrottlePolicy,
            {"security": {"auth_throttle": {"ip_failure_threshold": True}}},
            "security.auth_throttle.ip_failure_threshold",
        ),
        (
            AdmissionControlPolicy,
            {"server": {"admission_control": {"max_connections": True}}},
            "server.admission_control.max_connections",
        ),
        (
            RequestRateControlPolicy,
            {"security": {"request_rate_control": {"account_capacity": True}}},
            "security.request_rate_control.account_capacity",
        ),
        (
            DocumentUploadPolicy,
            {"document": {"upload": {"idle_timeout_seconds": True}}},
            "document.upload.idle_timeout_seconds",
        ),
        (
            DocumentCreationRiskPolicy,
            {
                "document": {
                    "upload": {"creation_risk_control": {"account_capacity": True}}
                }
            },
            "document.upload.creation_risk_control.account_capacity",
        ),
        (
            DocumentDownloadRiskPolicy,
            {"document": {"download": {"risk_control": {"task_capacity": True}}}},
            "document.download.risk_control.task_capacity",
        ),
    ],
)
def test_policy_positive_integer_fields_reject_booleans(policy_type, config, path):
    with pytest.raises(ConfigValidationError) as error:
        policy_type.from_config(config)

    assert path in str(error.value)


def test_declarative_policy_fields_do_not_coerce_values():
    with pytest.raises(ConfigValidationError) as boolean_error:
        AuthThrottlePolicy.from_config({"security": {"auth_throttle": {"enabled": 1}}})
    with pytest.raises(ConfigValidationError) as ratio_error:
        DocumentCreationRiskPolicy.from_config(
            {
                "document": {
                    "upload": {
                        "creation_risk_control": {"pending_elevated_ratio": "0.5"}
                    }
                }
            }
        )

    assert "security.auth_throttle.enabled" in str(boolean_error.value)
    assert "document.upload.creation_risk_control.pending_elevated_ratio" in str(
        ratio_error.value
    )


def test_policy_mapping_conversion_and_unknown_fields_preserve_compatibility():
    policy = RequestRateControlPolicy.from_config(
        {
            "security": {
                "request_rate_control": {
                    "action_costs": {"search": 5, "login": 2},
                    "future_setting": "ignored",
                }
            }
        }
    )

    assert policy.action_costs == (("login", 2), ("search", 5))


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
    ("setting", "value", "expected_fragment"),
    [
        ("mode", "disabled", "document.download.risk_control.mode"),
        (
            "issue_account_capacity",
            0,
            "document.download.risk_control.issue_account_capacity",
        ),
        ("ip_accounts_high", 4, "must be less than"),
        ("denials_high", 1, "must be less than"),
        ("high_cost", 201, "at least high_cost"),
        ("state_retention_seconds", 3599, "cover every risk-control window"),
    ],
)
def test_download_risk_policy_validates_settings(setting, value, expected_fragment):
    config = _valid_config()
    config["document"] = {"download": {"risk_control": {setting: value}}}

    with pytest.raises(ConfigValidationError) as error:
        validate_config(config)

    assert expected_fragment in str(error.value)


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
    ("setting", "value", "expected_fragment"),
    [
        ("mode", "disabled", "document.upload.creation_risk_control.mode"),
        (
            "account_capacity",
            0,
            "document.upload.creation_risk_control.account_capacity",
        ),
        (
            "pending_elevated_ratio",
            1.1,
            "document.upload.creation_risk_control.pending_elevated_ratio",
        ),
        ("pending_high_ratio", 0.25, "must be less than"),
        ("ip_accounts_high", 4, "must be less than"),
        ("denials_high", 1, "must be less than"),
        ("high_cost", 201, "at least high_cost"),
        ("state_retention_seconds", 599, "cover every risk-control window"),
    ],
)
def test_creation_risk_policy_validates_settings(setting, value, expected_fragment):
    config = _valid_config()
    config["document"] = {"upload": {"creation_risk_control": {setting: value}}}

    with pytest.raises(ConfigValidationError) as error:
        validate_config(config)

    assert expected_fragment in str(error.value)


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
