import ipaddress
import os
from collections.abc import Mapping, Sequence
from dataclasses import field
from functools import lru_cache
from typing import Any, Literal

from pydantic import ValidationError
from pydantic.dataclasses import dataclass
from tomlkit import TOMLDocument, parse
from tomlkit.exceptions import TOMLKitError

from include.config._policy import (
    ConfigValidationError,
    _CollectionValueLimit,
    _ConfigPolicy,
    _ConfigSource,
    _FieldOrder,
    _MappingItems,
    _MinimumCapacity,
    _PolicySource,
    _Section,
    _WindowCoverage,
)
from include.config.constants import DEFAULT_TRUSTED_PROXY_NETWORKS
from include.extensions.identifiers import validate_extension_identifier
from include.types import NonEmptyString, PositiveInt, UnitRatio

__all__ = [
    "AdmissionControlPolicy",
    "AuditRetentionPolicy",
    "AuthThrottlePolicy",
    "ConfigValidationError",
    "DocumentCreationRiskPolicy",
    "DocumentDownloadRiskPolicy",
    "DocumentUploadPolicy",
    "IdentityPermissionRetentionPolicy",
    "RequestRateControlPolicy",
    "S3StoragePolicy",
    "get_config_warnings",
    "get_enabled_extensions",
    "get_trusted_proxy_networks",
    "parse_config_document",
    "parse_trusted_proxy_networks",
    "validate_config",
]


def _section(config: _ConfigSource, name: str) -> Mapping[str, Any]:
    try:
        section = config[name]
    except KeyError as exc:
        raise ConfigValidationError(f"Missing configuration section {name!r}") from exc
    if not isinstance(section, Mapping):
        raise ConfigValidationError(f"Configuration section {name!r} must be a table")
    return section


@lru_cache(maxsize=8)
def parse_trusted_proxy_networks(
    configured: tuple[str, ...],
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    networks = []
    for value in configured:
        try:
            networks.append(ipaddress.ip_network(value, strict=False))
        except ValueError as exc:
            raise ConfigValidationError(
                f"Invalid server.trusted_proxy_networks entry {value!r}"
            ) from exc
    return tuple(networks)


def get_trusted_proxy_networks(
    config: _ConfigSource,
) -> tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...]:
    values = _section(config, "server").get(
        "trusted_proxy_networks", DEFAULT_TRUSTED_PROXY_NETWORKS
    )
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ConfigValidationError(
            "server.trusted_proxy_networks must be an array of CIDRs"
        )
    if not all(isinstance(value, str) for value in values):
        raise ConfigValidationError(
            "server.trusted_proxy_networks entries must be CIDR strings"
        )
    configured = tuple(values)
    return parse_trusted_proxy_networks(configured)


def get_enabled_extensions(config: _ConfigSource) -> tuple[str, ...]:
    extensions = _section(config, "extensions")
    try:
        values = extensions["enabled"]
    except KeyError as exc:
        raise ConfigValidationError(
            "Missing required configuration value extensions.enabled"
        ) from exc
    if isinstance(values, (str, bytes)) or not isinstance(values, Sequence):
        raise ConfigValidationError(
            "extensions.enabled must be an array of identifiers"
        )

    enabled = []
    seen = set()
    for value in values:
        try:
            identifier = validate_extension_identifier(value)
        except ValidationError as exc:
            raise ConfigValidationError(
                "extensions.enabled entries must be valid extension identifiers"
            ) from exc
        if identifier == "builtin":
            raise ConfigValidationError(
                "extensions.enabled must not contain 'builtin'; it is always enabled"
            )
        if identifier in seen:
            raise ConfigValidationError(
                f"extensions.enabled contains duplicate identifier {identifier!r}"
            )
        seen.add(identifier)
        enabled.append(identifier)
    return tuple(enabled)


@dataclass(frozen=True)
class AuthThrottlePolicy(_ConfigPolicy):
    _SOURCE = _PolicySource(
        (
            _Section("security", required=True),
            _Section("auth_throttle"),
        )
    )
    _RULES = (
        _FieldOrder(
            "account_base_delay_seconds",
            "account_max_delay_seconds",
            allow_equal=True,
            message=(
                "security.auth_throttle.account_base_delay_seconds must not exceed "
                "security.auth_throttle.account_max_delay_seconds"
            ),
        ),
    )

    enabled: bool = True
    account_failure_threshold: PositiveInt = 5
    account_base_delay_seconds: PositiveInt = 30
    account_max_delay_seconds: PositiveInt = 3600
    account_reset_seconds: PositiveInt = 86400
    account_ip_failure_threshold: PositiveInt = 5
    account_ip_window_seconds: PositiveInt = 900
    account_ip_block_seconds: PositiveInt = 900
    ip_failure_threshold: PositiveInt = 60
    ip_window_seconds: PositiveInt = 600
    ip_block_seconds: PositiveInt = 900
    record_retention_days: PositiveInt = 7


@dataclass(frozen=True)
class AdmissionControlPolicy(_ConfigPolicy):
    _SOURCE = _PolicySource(
        (
            _Section("server", required=True),
            _Section("admission_control"),
        )
    )
    _RULES = (
        _FieldOrder(
            "max_connections_per_ip",
            "max_connections",
            allow_equal=True,
            message=(
                "server.admission_control.max_connections_per_ip must not exceed "
                "max_connections"
            ),
        ),
        _FieldOrder(
            "max_inflight_requests_per_connection",
            "max_inflight_requests",
            allow_equal=True,
            message=(
                "server.admission_control.max_inflight_requests_per_connection must "
                "not exceed max_inflight_requests"
            ),
        ),
    )

    max_connections: PositiveInt = 64
    max_connections_per_ip: PositiveInt = 16
    max_inflight_requests: PositiveInt = 64
    max_inflight_requests_per_connection: PositiveInt = 8
    max_pending_streams_per_connection: PositiveInt = 16
    busy_retry_after_seconds: PositiveInt = 1


@dataclass(frozen=True)
class AuditRetentionPolicy(_ConfigPolicy):
    _SOURCE = _PolicySource(
        (
            _Section("maintenance"),
            _Section("audit_retention"),
        )
    )

    retention_days: PositiveInt = 365
    batch_size: PositiveInt = 500


@dataclass(frozen=True)
class IdentityPermissionRetentionPolicy(_ConfigPolicy):
    _SOURCE = _PolicySource(
        (
            _Section("identity"),
            _Section("permission_retention"),
        )
    )

    retention_days: PositiveInt = 30
    cleanup_interval_seconds: PositiveInt = 3600
    batch_size: PositiveInt = 500


@dataclass(frozen=True)
class RequestRateControlPolicy(_ConfigPolicy):
    _SOURCE = _PolicySource(
        (
            _Section("security", required=True),
            _Section("request_rate_control"),
        )
    )
    _RULES = (
        _CollectionValueLimit(
            "action_costs",
            ("account_capacity", "ip_capacity"),
            message=(
                "security.request_rate_control action costs must not exceed "
                "account_capacity or ip_capacity"
            ),
        ),
        _WindowCoverage(
            "state_retention_seconds",
            (
                "connection_refill_period_seconds",
                "request_refill_period_seconds",
            ),
            message=(
                "security.request_rate_control.state_retention_seconds must cover "
                "every refill period"
            ),
        ),
    )

    mode: Literal["disabled", "observe", "enforce"] = "observe"
    connection_capacity: PositiveInt = 20
    connection_refill_tokens: PositiveInt = 60
    connection_refill_period_seconds: PositiveInt = 60
    request_refill_period_seconds: PositiveInt = 60
    account_capacity: PositiveInt = 120
    account_refill_tokens: PositiveInt = 120
    ip_capacity: PositiveInt = 600
    ip_refill_tokens: PositiveInt = 600
    state_retention_seconds: PositiveInt = 600
    action_costs: _MappingItems = ()

    def cost_for(self, action: str, default: int = 1) -> int:
        for configured_action, cost in self.action_costs:
            if configured_action == action:
                return cost
        return default


@dataclass(frozen=True)
class DocumentUploadPolicy(_ConfigPolicy):
    _SOURCE = _PolicySource((_Section("document"), _Section("upload")))
    _RULES = (
        _FieldOrder(
            "idle_timeout_seconds",
            "max_duration_seconds",
            allow_equal=True,
            message=(
                "document.upload.idle_timeout_seconds must not exceed "
                "document.upload.max_duration_seconds"
            ),
        ),
        _FieldOrder(
            "start_timeout_seconds",
            "max_duration_seconds",
            allow_equal=False,
            message=(
                "document.upload.start_timeout_seconds must be less than "
                "document.upload.max_duration_seconds"
            ),
        ),
    )

    start_timeout_seconds: PositiveInt = 3600
    max_duration_seconds: PositiveInt = 86400
    idle_timeout_seconds: PositiveInt = 300
    cleanup_interval_seconds: PositiveInt = 60
    max_pending_documents_per_creator: PositiveInt = 16


@dataclass(frozen=True)
class DocumentCreationRiskPolicy(_ConfigPolicy):
    _SOURCE = _PolicySource(
        (
            _Section("document"),
            _Section("upload"),
            _Section("creation_risk_control", none_as_missing=True),
        )
    )
    _RULES = (
        _FieldOrder(
            "pending_elevated_ratio",
            "pending_high_ratio",
            allow_equal=False,
            message=(
                "document.upload.creation_risk_control.pending_elevated_ratio "
                "must be less than pending_high_ratio"
            ),
        ),
        _FieldOrder(
            "ip_accounts_elevated",
            "ip_accounts_high",
            allow_equal=False,
            message=(
                "document.upload.creation_risk_control.ip_accounts_elevated "
                "must be less than ip_accounts_high"
            ),
        ),
        _FieldOrder(
            "denials_elevated",
            "denials_high",
            allow_equal=False,
            message=(
                "document.upload.creation_risk_control.denials_elevated must be "
                "less than denials_high"
            ),
        ),
        _MinimumCapacity(
            ("account_capacity", "ip_capacity"),
            "high_cost",
            message=(
                "document.upload.creation_risk_control bucket capacities must be "
                "at least high_cost"
            ),
        ),
        _WindowCoverage(
            "state_retention_seconds",
            (
                "refill_period_seconds",
                "ip_account_window_seconds",
                "denial_window_seconds",
            ),
            message=(
                "document.upload.creation_risk_control.state_retention_seconds must "
                "cover every risk-control window"
            ),
        ),
    )

    mode: Literal["observe", "enforce"] = "enforce"
    refill_period_seconds: PositiveInt = 600
    account_capacity: PositiveInt = 60
    account_refill_tokens: PositiveInt = 300
    ip_capacity: PositiveInt = 200
    ip_refill_tokens: PositiveInt = 1000
    new_account_seconds: PositiveInt = 7 * 24 * 60 * 60
    pending_elevated_ratio: UnitRatio = 0.5
    pending_high_ratio: UnitRatio = 0.75
    ip_account_window_seconds: PositiveInt = 600
    ip_accounts_elevated: PositiveInt = 4
    ip_accounts_high: PositiveInt = 10
    denial_window_seconds: PositiveInt = 600
    denials_elevated: PositiveInt = 1
    denials_high: PositiveInt = 3
    elevated_cost: PositiveInt = 3
    high_cost: PositiveInt = 10
    state_retention_seconds: PositiveInt = 86400


@dataclass(frozen=True)
class DocumentDownloadRiskPolicy(_ConfigPolicy):
    _SOURCE = _PolicySource(
        (
            _Section("document"),
            _Section("download"),
            _Section("risk_control"),
        )
    )
    _RULES = (
        _FieldOrder(
            "ip_accounts_elevated",
            "ip_accounts_high",
            allow_equal=False,
            message=(
                "document.download.risk_control.ip_accounts_elevated must be less "
                "than ip_accounts_high"
            ),
        ),
        _FieldOrder(
            "denials_elevated",
            "denials_high",
            allow_equal=False,
            message=(
                "document.download.risk_control.denials_elevated must be less than "
                "denials_high"
            ),
        ),
        _MinimumCapacity(
            (
                "issue_account_capacity",
                "issue_ip_capacity",
                "transfer_account_capacity",
                "transfer_ip_capacity",
            ),
            "high_cost",
            message=(
                "document.download.risk_control account and IP bucket capacities "
                "must be at least high_cost"
            ),
        ),
        _WindowCoverage(
            "state_retention_seconds",
            (
                "refill_period_seconds",
                "task_refill_period_seconds",
                "ip_account_window_seconds",
                "denial_window_seconds",
            ),
            message=(
                "document.download.risk_control.state_retention_seconds must cover "
                "every risk-control window"
            ),
        ),
    )

    mode: Literal["observe", "enforce"] = "observe"
    refill_period_seconds: PositiveInt = 600
    issue_account_capacity: PositiveInt = 60
    issue_account_refill_tokens: PositiveInt = 300
    issue_ip_capacity: PositiveInt = 200
    issue_ip_refill_tokens: PositiveInt = 1000
    transfer_account_capacity: PositiveInt = 60
    transfer_account_refill_tokens: PositiveInt = 300
    transfer_ip_capacity: PositiveInt = 200
    transfer_ip_refill_tokens: PositiveInt = 1000
    task_capacity: PositiveInt = 5
    task_refill_tokens: PositiveInt = 10
    task_refill_period_seconds: PositiveInt = 3600
    new_account_seconds: PositiveInt = 7 * 24 * 60 * 60
    ip_account_window_seconds: PositiveInt = 600
    ip_accounts_elevated: PositiveInt = 4
    ip_accounts_high: PositiveInt = 10
    denial_window_seconds: PositiveInt = 600
    denials_elevated: PositiveInt = 1
    denials_high: PositiveInt = 3
    elevated_cost: PositiveInt = 3
    high_cost: PositiveInt = 10
    state_retention_seconds: PositiveInt = 86400


@dataclass(frozen=True)
class S3StoragePolicy(_ConfigPolicy):
    _SOURCE = _PolicySource((_Section("s3", required=True),))

    bucket: NonEmptyString
    endpoint_url: str = ""
    access_key_id: str = ""
    secret_access_key: str = field(default="", repr=False)
    session_token: str = field(default="", repr=False)
    region_name: str = ""
    addressing_style: Literal["auto", "virtual", "path"] = "auto"
    max_pool_connections: PositiveInt | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if bool(self.access_key_id) != bool(self.secret_access_key):
            raise ConfigValidationError(
                "s3.access_key_id and s3.secret_access_key must be configured together"
            )
        if self.session_token and not self.access_key_id:
            raise ConfigValidationError(
                "s3.session_token requires explicit access key credentials"
            )


def _validate_client_certificate_config(config: _ConfigSource) -> None:
    security = _section(config, "security")
    require_client_cert = security.get("require_client_cert", False)
    if not isinstance(require_client_cert, bool):
        raise ConfigValidationError("security.require_client_cert must be a boolean")
    if not require_client_cert:
        return

    client_ca_path = security.get("client_cert_ca_path")
    if not isinstance(client_ca_path, str) or not os.path.isdir(client_ca_path):
        raise ConfigValidationError(
            "security.client_cert_ca_path must reference an existing directory "
            "when security.require_client_cert is enabled"
        )


def _validate_file_chunk_size_config(config: _ConfigSource) -> None:
    server = _section(config, "server")
    try:
        value = server["file_chunk_size"]
    except KeyError as exc:
        raise ConfigValidationError(
            "Missing required configuration value server.file_chunk_size"
        ) from exc
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ConfigValidationError("server.file_chunk_size must be a positive integer")


def _validate_storage_provider_config(
    config: _ConfigSource, provider: Mapping[str, Any]
) -> None:
    storage = provider.get("storage", "local")
    if storage not in {"local", "s3"}:
        raise ConfigValidationError("provider.storage must be either 'local' or 's3'")
    if storage == "s3":
        S3StoragePolicy.from_config(config)


def validate_config(config: _ConfigSource) -> None:
    get_trusted_proxy_networks(config)
    get_enabled_extensions(config)
    AuthThrottlePolicy.from_config(config)
    AdmissionControlPolicy.from_config(config)
    AuditRetentionPolicy.from_config(config)
    IdentityPermissionRetentionPolicy.from_config(config)
    RequestRateControlPolicy.from_config(config)
    DocumentUploadPolicy.from_config(config)
    DocumentCreationRiskPolicy.from_config(config)
    DocumentDownloadRiskPolicy.from_config(config)
    _validate_file_chunk_size_config(config)
    _validate_client_certificate_config(config)

    try:
        provider = config["provider"]
    except KeyError:
        provider = {}
    if not isinstance(provider, Mapping):
        raise ConfigValidationError("Configuration section 'provider' must be a table")
    _validate_storage_provider_config(config, provider)
    if provider.get("rate_limit", "memory") not in {"memory", "redis"}:
        raise ConfigValidationError(
            "provider.rate_limit must be either 'memory' or 'redis'"
        )

    from include.extensions.manager import validate_extension_config

    validate_extension_config(config)


def parse_config_document(source: str) -> TOMLDocument:
    try:
        config = parse(source)
    except TOMLKitError as exc:
        raise ConfigValidationError(f"Invalid TOML configuration: {exc}") from exc
    validate_config(config)
    return config


def get_config_warnings(config: _ConfigSource) -> tuple[str, ...]:
    security = _section(config, "security")
    warnings = []
    try:
        document = config["document"]
    except KeyError:
        document = {}
    if isinstance(document, Mapping) and "allow_name_duplicate" in document:
        warnings.append(
            "`document.allow_name_duplicate` is obsolete and ignored; active "
            "documents and directories must have unique names within a directory"
        )
    if not security.get("pepper"):
        warnings.append(
            "Setting the value for `pepper` to empty in the configuration file can "
            "lead to potential security vulnerabilities. For details, see: "
            "https://cheatsheetseries.owasp.org/cheatsheets/"
            "Password_Storage_Cheat_Sheet.html#peppering"
        )
    return tuple(warnings)
