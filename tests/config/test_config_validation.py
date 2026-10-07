import subprocess
import sys
from textwrap import dedent, indent
from types import SimpleNamespace

import pytest
from tomlkit import dumps

from include.config.validation import (
    AdmissionControlPolicy,
    AuditRetentionPolicy,
    AuthThrottlePolicy,
    ConfigValidationError,
    DatabasePoolPolicy,
    DocumentCreationRiskPolicy,
    DocumentDownloadRiskPolicy,
    DocumentUploadPolicy,
    IdentityPermissionRetentionPolicy,
    RequestRateControlPolicy,
    S3StoragePolicy,
    SchedulingPolicy,
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


@pytest.fixture
def _clear_proxy_network_cache():
    parse_trusted_proxy_networks.cache_clear()
    yield
    parse_trusted_proxy_networks.cache_clear()


@pytest.fixture
def config_lifecycle(tmp_path):
    config_root = tmp_path / "server"
    config_root.mkdir()
    config_path = config_root / "config.toml"
    document = _valid_config()
    document["server"].update({"secret_key": "existing-secret", "port": 8765})
    document["security"]["pepper"] = "existing-pepper"
    config_path.write_text(dumps(document), encoding="utf-8")
    sentinel = config_root / "init"
    sentinel.touch()
    working_directory = tmp_path / "elsewhere"
    working_directory.mkdir()

    def run_check(code):
        script = (
            "import sys\n"
            "from pathlib import Path\n"
            "from include.config import paths\n"
            "config_path = Path(sys.argv[1])\n"
            "paths.EXECUTABLE_ABSPATH = config_path.parent\n"
            "from include.config.settings import GlobalConfig, global_config\n"
            "config = GlobalConfig(str(config_path))\n"
            "assert config is global_config\n"
            "config.stop()\n"
            "try:\n" + indent(dedent(code).strip(), "    ") + "\nfinally:\n"
            "    config.stop()\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", script, str(config_path)],
            cwd=working_directory,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
        assert result.returncode == 0, (
            f"Configuration lifecycle check failed\n"
            f"stdout:\n{result.stdout}\nstderr:\n{result.stderr}"
        )

    return SimpleNamespace(
        run_check=run_check,
        config_path=config_path,
        sentinel=sentinel,
        working_directory=working_directory,
    )


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
        (["scheduling"], "management APIs are part of the server core"),
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


def test_admission_control_uses_default_connection_and_request_limits():
    config = _valid_config()

    admission_policy = AdmissionControlPolicy.from_config(config)

    assert admission_policy.max_connections == 64
    assert admission_policy.max_inflight_requests == 12


@pytest.mark.parametrize(
    ("pool", "expected"),
    [
        pytest.param(
            {},
            DatabasePoolPolicy(size=5, max_overflow=10, timeout_seconds=30),
            id="defaults",
        ),
        pytest.param(
            {"size": 3, "max_overflow": 2, "timeout_seconds": 0},
            DatabasePoolPolicy(size=3, max_overflow=2, timeout_seconds=0),
            id="overrides",
        ),
    ],
)
def test_database_pool_policy_uses_configured_values_or_defaults(pool, expected):
    config = _valid_config()
    config["database"] = {"pool": pool}

    policy = DatabasePoolPolicy.from_config(config)

    assert policy == expected


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("size", 0),
        ("size", True),
        ("size", "5"),
        ("max_overflow", -1),
        ("max_overflow", True),
        ("max_overflow", "10"),
        ("timeout_seconds", -0.1),
        ("timeout_seconds", True),
        ("timeout_seconds", "30"),
    ],
)
def test_database_pool_policy_rejects_invalid_values(setting, value):
    config = _valid_config()
    config["database"] = {"pool": {setting: value}}

    with pytest.raises(ConfigValidationError) as error:
        validate_config(config)

    assert f"database.pool.{setting}" in str(error.value)


def test_database_pool_capacity_mismatch_emits_warning():
    config = _valid_config()
    config["server"]["admission_control"] = {"max_inflight_requests": 16}
    config["database"] = {
        "pool": {"size": 5, "max_overflow": 10, "timeout_seconds": 30}
    }

    warnings = get_config_warnings(config)

    assert len(warnings) == 1
    assert "max_inflight_requests" in warnings[0]
    assert "database pool capacity" in warnings[0]


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        pytest.param({}, (30, 3600, 500), id="defaults"),
        pytest.param(
            {"retention_days": 14, "cleanup_interval_seconds": 600, "batch_size": 100},
            (14, 600, 100),
            id="overrides",
        ),
    ],
)
def test_identity_permission_retention_uses_configured_values_or_defaults(
    settings, expected
):
    config = _valid_config()
    config["identity"] = {"permission_retention": settings}

    policy = IdentityPermissionRetentionPolicy.from_config(config)

    assert (
        policy.retention_days,
        policy.cleanup_interval_seconds,
        policy.batch_size,
    ) == expected


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        pytest.param({}, (365, 500), id="defaults"),
        pytest.param(
            {"retention_days": 730, "batch_size": 100}, (730, 100), id="overrides"
        ),
    ],
)
def test_audit_retention_uses_configured_values_or_defaults(settings, expected):
    config = _valid_config()
    config["maintenance"] = {"audit_retention": settings}

    policy = AuditRetentionPolicy.from_config(config)

    assert (policy.retention_days, policy.batch_size) == expected


@pytest.mark.parametrize(
    ("setting", "value"),
    [
        ("retention_days", 0),
        ("retention_days", "365"),
        ("batch_size", -1),
        ("batch_size", True),
    ],
)
def test_audit_retention_rejects_invalid_values(setting, value):
    config = _valid_config()
    config["maintenance"] = {"audit_retention": {setting: value}}

    with pytest.raises(ConfigValidationError) as error:
        validate_config(config)

    assert f"maintenance.audit_retention.{setting}" in str(error.value)


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


@pytest.mark.parametrize(
    ("settings", "expected"),
    [
        pytest.param({}, (4, 60, 20), id="defaults"),
        pytest.param(
            {
                "worker_threads": 2,
                "execution_lease_seconds": 30,
                "lease_refresh_seconds": 10,
            },
            (2, 30, 10),
            id="overrides",
        ),
    ],
)
def test_scheduling_policy_uses_configured_values_or_defaults(settings, expected):
    config = _valid_config()
    config["scheduling"] = settings

    policy = SchedulingPolicy.from_config(config)

    assert (
        policy.worker_threads,
        policy.execution_lease_seconds,
        policy.lease_refresh_seconds,
    ) == expected


@pytest.mark.parametrize("provider", ["database", "dramatiq"])
def test_scheduling_provider_selection_is_validated(provider):
    config = _valid_config()
    config["provider"] = {"scheduling": provider}

    with pytest.raises(ConfigValidationError, match="provider.scheduling"):
        validate_config(config)


def test_redis_scheduling_requires_shared_database():
    config = _valid_config()
    config["provider"] = {"scheduling": "redis"}
    config["database"] = {"type": "sqlite"}

    with pytest.raises(ConfigValidationError, match="non-SQLite"):
        validate_config(config)


def test_redis_scheduling_requires_explicit_deployment_namespace():
    config = _valid_config()
    config["provider"] = {"scheduling": "redis"}
    config["database"] = {"type": "postgresql"}

    with pytest.raises(ConfigValidationError, match="redis_namespace is required"):
        validate_config(config)


def test_redis_scheduling_accepts_explicit_deployment_namespace():
    config = _valid_config()
    config["provider"] = {"scheduling": "redis"}
    config["database"] = {"type": "postgresql"}
    config["scheduling"] = {"redis_namespace": "production-1"}

    validate_config(config)


@pytest.mark.parametrize(
    "namespace",
    ["", "Uppercase", "contains.space", "x" * 64, "namespace:part"],
)
def test_redis_scheduling_namespace_is_validated(namespace):
    config = _valid_config()
    config["scheduling"] = {"redis_namespace": namespace}

    with pytest.raises(ConfigValidationError, match="redis_namespace"):
        validate_config(config)


def test_local_scheduling_does_not_require_redis_namespace():
    config = _valid_config()
    config["provider"] = {"scheduling": "local"}

    validate_config(config)


def test_scheduling_lease_refresh_must_precede_expiry():
    config = _valid_config()
    config["scheduling"] = {
        "execution_lease_seconds": 20,
        "lease_refresh_seconds": 20,
    }

    with pytest.raises(ConfigValidationError, match="must be less than"):
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


@pytest.mark.usefixtures("_clear_proxy_network_cache")
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


@pytest.mark.parametrize(
    ("policy_type", "section"),
    [
        pytest.param(AuthThrottlePolicy, "security", id="security"),
        pytest.param(AdmissionControlPolicy, "server", id="server"),
    ],
)
def test_policy_sources_require_their_root_section(policy_type, section):
    with pytest.raises(
        ConfigValidationError, match=f"^Missing configuration section '{section}'$"
    ):
        policy_type.from_config({})


@pytest.mark.parametrize(
    ("policy_type", "config"),
    [
        pytest.param(DocumentUploadPolicy, {}, id="absent-upload"),
        pytest.param(DocumentDownloadRiskPolicy, {}, id="absent-download"),
        pytest.param(
            DocumentCreationRiskPolicy,
            {"document": {"upload": {"creation_risk_control": None}}},
            id="null-creation-risk",
        ),
    ],
)
def test_document_policy_sources_default_optional_sections(policy_type, config):
    policy = policy_type.from_config(config)

    assert policy == policy_type()


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


@pytest.mark.parametrize(
    ("policy_type", "config", "path"),
    [
        pytest.param(
            AuthThrottlePolicy,
            {"security": {"auth_throttle": {"enabled": 1}}},
            "security.auth_throttle.enabled",
            id="integer-is-not-boolean",
        ),
        pytest.param(
            DocumentCreationRiskPolicy,
            {
                "document": {
                    "upload": {
                        "creation_risk_control": {"pending_elevated_ratio": "0.5"}
                    }
                }
            },
            "document.upload.creation_risk_control.pending_elevated_ratio",
            id="string-is-not-ratio",
        ),
    ],
)
def test_declarative_policy_fields_do_not_coerce_values(policy_type, config, path):
    with pytest.raises(ConfigValidationError) as error:
        policy_type.from_config(config)

    assert path in str(error.value)


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


@pytest.mark.parametrize(
    ("settings", "expected_pending"),
    [
        pytest.param({}, 16, id="defaults"),
        pytest.param({"max_pending_documents_per_creator": 8}, 8, id="overrides"),
    ],
)
def test_document_upload_policy_uses_configured_values_or_defaults(
    settings, expected_pending
):
    config = _valid_config()
    config["document"] = {"upload": settings}

    policy = DocumentUploadPolicy.from_config(config)

    assert policy.start_timeout_seconds == 3600
    assert policy.max_pending_documents_per_creator == expected_pending


def test_document_creation_risk_policy_defaults():
    policy = DocumentCreationRiskPolicy.from_config(_valid_config())

    assert policy.mode == "enforce"
    assert policy.account_capacity == 60
    assert policy.account_refill_tokens == 300
    assert policy.ip_capacity == 200
    assert policy.ip_refill_tokens == 1000


@pytest.mark.parametrize(
    ("settings", "expected_mode", "expected_capacity"),
    [
        pytest.param({}, "observe", 5, id="defaults"),
        pytest.param(
            {"mode": "enforce", "task_capacity": 8}, "enforce", 8, id="overrides"
        ),
    ],
)
def test_document_download_risk_policy_uses_configured_values_or_defaults(
    settings, expected_mode, expected_capacity
):
    config = _valid_config()
    config["document"] = {"download": {"risk_control": settings}}

    policy = DocumentDownloadRiskPolicy.from_config(config)

    assert policy.mode == expected_mode
    assert policy.issue_account_refill_tokens == 300
    assert policy.transfer_ip_refill_tokens == 1000
    assert policy.task_capacity == expected_capacity
    assert policy.task_refill_tokens == 10


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


@pytest.mark.parametrize("invalid_source", ["[server", "invalid-cidr"])
def test_invalid_reload_keeps_previous_configuration(config_lifecycle, invalid_source):
    config_lifecycle.run_check(
        f"""
        valid_source = config_path.read_text(encoding="utf-8")
        previous = dict(config)
        invalid_source = {invalid_source!r}
        if invalid_source == "invalid-cidr":
            invalid_source = valid_source.replace("127.0.0.1/32", "not-a-cidr")
        config_path.write_text(invalid_source, encoding="utf-8")

        assert config.reload() is False
        assert dict(config) == previous
        assert config["server"]["port"] == 8765

        config_path.write_text(
            valid_source.replace("port = 8765", "port = 9000"), encoding="utf-8"
        )
        assert config.reload() is True
        assert config["server"]["port"] == 9000
        assert config["security"]["pepper"] == "existing-pepper"
        """
    )


@pytest.mark.parametrize("sentinel_in_config_directory", [True, False])
def test_secret_initialization_uses_config_directory_sentinel(
    config_lifecycle, sentinel_in_config_directory
):
    if not sentinel_in_config_directory:
        config_lifecycle.sentinel.unlink()
        (config_lifecycle.working_directory / "init").touch()

    config_lifecycle.run_check(
        f"""
        from tomlkit import parse

        document = parse(config_path.read_text(encoding="utf-8"))
        if {sentinel_in_config_directory!r}:
            assert document["server"]["secret_key"] == "existing-secret"
            assert document["security"]["pepper"] == "existing-pepper"
        else:
            assert document["server"]["secret_key"]
            assert document["server"]["secret_key"] != "existing-secret"
            assert document["security"]["pepper"]
            assert document["security"]["pepper"] != "existing-pepper"
        assert config["server"]["secret_key"] == document["server"]["secret_key"]
        assert config["security"]["pepper"] == document["security"]["pepper"]
        """
    )


def test_global_config_implements_read_only_mapping_contract(config_lifecycle):
    config_lifecycle.run_check(
        """
        from collections.abc import Mapping

        import pytest

        assert isinstance(config, Mapping)
        assert len(config) == 3
        assert list(config) == ["extensions", "server", "security"]
        assert "server" in config
        assert "missing" not in config
        assert config.get("missing", "fallback") == "fallback"
        assert config["server"]["port"] == 8765
        with pytest.raises(TypeError):
            config["server"] = {}
        """
    )


def test_invalid_toml_is_reported_as_configuration_error():
    with pytest.raises(ConfigValidationError, match="Invalid TOML configuration"):
        parse_config_document("[server")


def _valid_s3_config() -> dict:
    config = _valid_config()
    config["provider"] = {"storage": "s3"}
    config["s3"] = {
        "bucket": "test-bucket",
        "endpoint_url": "",
        "access_key_id": "",
        "secret_access_key": "",
        "session_token": "",
        "region_name": "",
        "addressing_style": "auto",
        "max_pool_connections": 64,
    }
    return config


def test_s3_configuration_accepts_sdk_default_resolution():
    config = _valid_s3_config()

    validate_config(config)

    policy = S3StoragePolicy.from_config(config)
    assert policy.bucket == "test-bucket"
    assert policy.addressing_style == "auto"
    assert policy.max_pool_connections == 64


def test_s3_configuration_allows_omitting_connection_pool():
    config = _valid_s3_config()
    del config["s3"]["max_pool_connections"]
    config["server"]["admission_control"] = {
        "max_connections": 20,
        "max_connections_per_ip": 10,
    }

    validate_config(config)

    policy = S3StoragePolicy.from_config(config)
    assert policy.max_pool_connections is None


def test_s3_policy_hides_explicit_credentials_from_its_representation():
    config = _valid_s3_config()
    config["s3"].update(
        {
            "access_key_id": "access",
            "secret_access_key": "secret-value",
            "session_token": "token-value",
        }
    )

    policy = S3StoragePolicy.from_config(config)

    assert policy.access_key_id == "access"
    assert policy.secret_access_key == "secret-value"
    assert policy.session_token == "token-value"
    assert "secret-value" not in repr(policy)
    assert "token-value" not in repr(policy)


@pytest.mark.parametrize("addressing_style", ["auto", "virtual", "path"])
def test_s3_configuration_accepts_supported_addressing_styles(addressing_style):
    config = _valid_s3_config()
    config["s3"]["addressing_style"] = addressing_style

    validate_config(config)


@pytest.mark.parametrize("max_pool_connections", [0, -1, True, "64"])
def test_s3_configuration_rejects_invalid_connection_pool(max_pool_connections):
    config = _valid_s3_config()
    config["s3"]["max_pool_connections"] = max_pool_connections

    with pytest.raises(ConfigValidationError, match="max_pool_connections"):
        validate_config(config)


def test_s3_configuration_rejects_invalid_addressing_style():
    config = _valid_s3_config()
    config["s3"]["addressing_style"] = "custom"

    with pytest.raises(ConfigValidationError, match="addressing_style"):
        validate_config(config)


@pytest.mark.parametrize(
    ("access_key_id", "secret_access_key", "session_token", "message"),
    [
        ("access", "", "", "configured together"),
        ("", "secret", "", "configured together"),
        ("", "", "token", "session_token"),
    ],
)
def test_s3_configuration_rejects_incomplete_explicit_credentials(
    access_key_id, secret_access_key, session_token, message
):
    config = _valid_s3_config()
    config["s3"].update(
        {
            "access_key_id": access_key_id,
            "secret_access_key": secret_access_key,
            "session_token": session_token,
        }
    )

    with pytest.raises(ConfigValidationError, match=message):
        validate_config(config)


def test_s3_configuration_requires_non_empty_bucket():
    config = _valid_s3_config()
    config["s3"]["bucket"] = ""

    with pytest.raises(ConfigValidationError, match="s3.bucket"):
        validate_config(config)


def test_storage_provider_rejects_unknown_backend():
    config = _valid_config()
    config["provider"] = {"storage": "unknown"}

    with pytest.raises(ConfigValidationError, match="provider.storage"):
        validate_config(config)
