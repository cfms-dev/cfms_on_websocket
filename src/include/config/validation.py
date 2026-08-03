import annotationlib
import ipaddress
import os
from collections.abc import Mapping, Sequence
from dataclasses import MISSING, dataclass, fields
from functools import lru_cache
from typing import (
    Annotated,
    Any,
    ClassVar,
    Literal,
    Protocol,
    Self,
    get_args,
    get_origin,
)

from tomlkit import TOMLDocument, parse
from tomlkit.exceptions import TOMLKitError

from include.config.constants import DEFAULT_TRUSTED_PROXY_NETWORKS

__all__ = [
    "AuthThrottlePolicy",
    "AdmissionControlPolicy",
    "ConfigValidationError",
    "DocumentCreationRiskPolicy",
    "DocumentDownloadRiskPolicy",
    "DocumentUploadPolicy",
    "RequestRateControlPolicy",
    "get_config_warnings",
    "get_enabled_extensions",
    "get_trusted_proxy_networks",
    "parse_config_document",
    "parse_trusted_proxy_networks",
    "validate_config",
]


class ConfigValidationError(ValueError):
    """Raised when configuration values fail validation."""


class _ConfigSource(Protocol):
    def __getitem__(self, key: str, /) -> Any: ...


@dataclass(frozen=True, slots=True)
class _Section:
    name: str
    required: bool = False
    none_as_missing: bool = False


@dataclass(frozen=True, slots=True)
class _PolicySource:
    sections: tuple[_Section, ...]


@dataclass(frozen=True, slots=True)
class _ValueRange:
    minimum: int | float | None = None
    maximum: int | float | None = None
    minimum_inclusive: bool = True
    maximum_inclusive: bool = True
    message: str | None = None


@dataclass(frozen=True, slots=True)
class _MappingItems:
    pass


@dataclass(frozen=True, slots=True)
class _FieldOrder:
    lower_field: str
    upper_field: str
    allow_equal: bool
    message: str


@dataclass(frozen=True, slots=True)
class _MinimumCapacity:
    capacity_fields: tuple[str, ...]
    minimum_field: str
    message: str


@dataclass(frozen=True, slots=True)
class _WindowCoverage:
    retention_field: str
    window_fields: tuple[str, ...]
    message: str


@dataclass(frozen=True, slots=True)
class _CollectionValueLimit:
    collection_field: str
    limit_fields: tuple[str, ...]
    message: str


type _PolicyRule = (
    _FieldOrder | _MinimumCapacity | _WindowCoverage | _CollectionValueLimit
)

_PositiveInt = Annotated[
    int,
    _ValueRange(
        minimum=0,
        minimum_inclusive=False,
        message="must be a positive integer",
    ),
]
_UnitRatio = Annotated[
    float,
    _ValueRange(
        minimum=0,
        maximum=1,
        minimum_inclusive=False,
        message="must be a number greater than 0 and at most 1",
    ),
]


def _unwrap_annotation(annotation: Any) -> tuple[Any, tuple[Any, ...]]:
    if get_origin(annotation) is Annotated:
        value_type, *metadata = get_args(annotation)
        return value_type, tuple(metadata)
    return annotation, ()


def _format_literal_values(values: tuple[Any, ...]) -> str:
    rendered = tuple(repr(value) for value in values)
    if len(rendered) == 1:
        return rendered[0]
    if len(rendered) == 2:
        return f"{rendered[0]} or {rendered[1]}"
    return f"{', '.join(rendered[:-1])}, or {rendered[-1]}"


def _validate_value_type(
    value: Any,
    annotation: Any,
    path: str,
    range_constraint: _ValueRange | None,
) -> None:
    error = range_constraint.message if range_constraint is not None else None
    origin = get_origin(annotation)
    if origin is Literal:
        allowed = get_args(annotation)
        if value not in allowed:
            raise ConfigValidationError(
                f"{path} must be {_format_literal_values(allowed)}"
            )
        return
    if annotation is bool:
        valid = isinstance(value, bool)
        error = error or "must be a boolean"
    elif annotation is int:
        valid = not isinstance(value, bool) and isinstance(value, int)
        error = error or "must be an integer"
    elif annotation is float:
        valid = not isinstance(value, bool) and isinstance(value, int | float)
        error = error or "must be a number"
    elif annotation is str:
        valid = isinstance(value, str)
        error = error or "must be a string"
    else:
        raise TypeError(f"Unsupported policy annotation for {path}: {annotation!r}")
    if not valid:
        raise ConfigValidationError(f"{path} {error}")


def _validate_value_range(
    value: int | float,
    constraint: _ValueRange,
    path: str,
) -> None:
    below_minimum = constraint.minimum is not None and (
        value < constraint.minimum
        or (not constraint.minimum_inclusive and value == constraint.minimum)
    )
    above_maximum = constraint.maximum is not None and (
        value > constraint.maximum
        or (not constraint.maximum_inclusive and value == constraint.maximum)
    )
    if below_minimum or above_maximum:
        if constraint.message is None:
            raise TypeError(f"Policy range for {path} does not define an error message")
        raise ConfigValidationError(f"{path} {constraint.message}")


def _decode_mapping_items(value: Any, path: str) -> tuple[tuple[str, int], ...]:
    if not isinstance(value, Mapping):
        raise ConfigValidationError(f"{path} must be a table")
    items = []
    for key, item_value in value.items():
        if not isinstance(key, str) or not key:
            raise ConfigValidationError(f"{path} keys must be non-empty strings")
        if (
            isinstance(item_value, bool)
            or not isinstance(item_value, int)
            or item_value <= 0
        ):
            raise ConfigValidationError(f"{path} values must be positive integers")
        items.append((key, item_value))
    return tuple(sorted(items))


class _ConfigPolicy:
    _SOURCE: ClassVar[_PolicySource]
    _RULES: ClassVar[tuple[_PolicyRule, ...]] = ()

    @classmethod
    def _read_section(cls, config: _ConfigSource) -> Mapping[str, Any]:
        current: Any = config
        path_parts = []
        for section in cls._SOURCE.sections:
            path_parts.append(section.name)
            path = ".".join(path_parts)
            try:
                value = current[section.name]
            except KeyError as exc:
                if section.required:
                    raise ConfigValidationError(
                        f"Missing configuration section {path!r}"
                    ) from exc
                return {}
            if value is None and section.none_as_missing:
                return {}
            if not isinstance(value, Mapping):
                if section.required:
                    raise ConfigValidationError(
                        f"Configuration section {path!r} must be a table"
                    )
                raise ConfigValidationError(f"{path} must be a table")
            current = value
        return current

    @classmethod
    def from_config(cls, config: _ConfigSource | None = None) -> Self:
        if config is None:
            from include.config.settings import global_config

            config = global_config

        section = cls._read_section(config)
        annotations = annotationlib.get_annotations(
            cls,
            format=annotationlib.Format.VALUE,
        )
        values = {}
        for field in fields(cls):
            try:
                annotation = annotations[field.name]
            except KeyError as exc:
                raise TypeError(
                    f"Policy field {cls.__name__}.{field.name} has no annotation"
                ) from exc
            value_type, metadata = _unwrap_annotation(annotation)
            range_constraints = tuple(
                item for item in metadata if isinstance(item, _ValueRange)
            )
            mapping_decoders = tuple(
                item for item in metadata if isinstance(item, _MappingItems)
            )
            known_metadata = (*range_constraints, *mapping_decoders)
            if len(known_metadata) != len(metadata):
                raise TypeError(
                    f"Policy field {cls.__name__}.{field.name} has unsupported metadata"
                )
            if (
                len(range_constraints) > 1
                or len(mapping_decoders) > 1
                or (range_constraints and mapping_decoders)
            ):
                raise TypeError(
                    f"Policy field {cls.__name__}.{field.name} has conflicting metadata"
                )

            configured = field.name in section
            if configured:
                value = section[field.name]
            elif field.default is not MISSING:
                value = field.default
            elif field.default_factory is not MISSING:
                value = field.default_factory()
            else:
                raise TypeError(
                    f"Policy field {cls.__name__}.{field.name} has no default"
                )

            path = (
                f"{'.'.join(part.name for part in cls._SOURCE.sections)}.{field.name}"
            )
            if mapping_decoders:
                if configured:
                    value = _decode_mapping_items(value, path)
            else:
                range_constraint = range_constraints[0] if range_constraints else None
                _validate_value_type(value, value_type, path, range_constraint)
                if range_constraint is not None:
                    _validate_value_range(value, range_constraint, path)
            values[field.name] = value

        policy = cls(**values)
        policy._validate_rules()
        return policy

    def _validate_rules(self) -> None:
        for rule in self._RULES:
            if isinstance(rule, _FieldOrder):
                lower = getattr(self, rule.lower_field)
                upper = getattr(self, rule.upper_field)
                valid = lower <= upper if rule.allow_equal else lower < upper
            elif isinstance(rule, _MinimumCapacity):
                valid = min(
                    getattr(self, field_name) for field_name in rule.capacity_fields
                ) >= getattr(self, rule.minimum_field)
            elif isinstance(rule, _WindowCoverage):
                valid = getattr(self, rule.retention_field) >= max(
                    getattr(self, field_name) for field_name in rule.window_fields
                )
            elif isinstance(rule, _CollectionValueLimit):
                limit = min(
                    getattr(self, field_name) for field_name in rule.limit_fields
                )
                valid = all(
                    value <= limit for _, value in getattr(self, rule.collection_field)
                )
            else:
                raise TypeError(f"Unsupported policy rule: {rule!r}")
            if not valid:
                raise ConfigValidationError(rule.message)


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
    from include.extensions.manager import IDENTIFIER_PATTERN

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
        if not isinstance(value, str) or IDENTIFIER_PATTERN.fullmatch(value) is None:
            raise ConfigValidationError(
                "extensions.enabled entries must be valid extension identifiers"
            )
        if value == "builtin":
            raise ConfigValidationError(
                "extensions.enabled must not contain 'builtin'; it is always enabled"
            )
        if value in seen:
            raise ConfigValidationError(
                f"extensions.enabled contains duplicate identifier {value!r}"
            )
        seen.add(value)
        enabled.append(value)
    return tuple(enabled)


@dataclass(frozen=True)
class AuthThrottlePolicy(_ConfigPolicy):
    _SOURCE = _PolicySource(
        (_Section("security", required=True), _Section("auth_throttle"))
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
    account_failure_threshold: _PositiveInt = 5
    account_base_delay_seconds: _PositiveInt = 30
    account_max_delay_seconds: _PositiveInt = 3600
    account_reset_seconds: _PositiveInt = 86400
    account_ip_failure_threshold: _PositiveInt = 5
    account_ip_window_seconds: _PositiveInt = 900
    account_ip_block_seconds: _PositiveInt = 900
    ip_failure_threshold: _PositiveInt = 60
    ip_window_seconds: _PositiveInt = 600
    ip_block_seconds: _PositiveInt = 900
    record_retention_days: _PositiveInt = 7


@dataclass(frozen=True)
class AdmissionControlPolicy(_ConfigPolicy):
    _SOURCE = _PolicySource(
        (_Section("server", required=True), _Section("admission_control"))
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

    max_connections: _PositiveInt = 64
    max_connections_per_ip: _PositiveInt = 16
    max_inflight_requests: _PositiveInt = 64
    max_inflight_requests_per_connection: _PositiveInt = 8
    max_pending_streams_per_connection: _PositiveInt = 16
    busy_retry_after_seconds: _PositiveInt = 1


@dataclass(frozen=True)
class RequestRateControlPolicy(_ConfigPolicy):
    _SOURCE = _PolicySource(
        (_Section("security", required=True), _Section("request_rate_control"))
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
    connection_capacity: _PositiveInt = 20
    connection_refill_tokens: _PositiveInt = 60
    connection_refill_period_seconds: _PositiveInt = 60
    request_refill_period_seconds: _PositiveInt = 60
    account_capacity: _PositiveInt = 120
    account_refill_tokens: _PositiveInt = 120
    ip_capacity: _PositiveInt = 600
    ip_refill_tokens: _PositiveInt = 600
    state_retention_seconds: _PositiveInt = 600
    action_costs: Annotated[tuple[tuple[str, int], ...], _MappingItems()] = ()

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

    start_timeout_seconds: _PositiveInt = 3600
    max_duration_seconds: _PositiveInt = 86400
    idle_timeout_seconds: _PositiveInt = 300
    cleanup_interval_seconds: _PositiveInt = 60
    max_pending_documents_per_creator: _PositiveInt = 16


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
    refill_period_seconds: _PositiveInt = 600
    account_capacity: _PositiveInt = 60
    account_refill_tokens: _PositiveInt = 300
    ip_capacity: _PositiveInt = 200
    ip_refill_tokens: _PositiveInt = 1000
    new_account_seconds: _PositiveInt = 7 * 24 * 60 * 60
    pending_elevated_ratio: _UnitRatio = 0.5
    pending_high_ratio: _UnitRatio = 0.75
    ip_account_window_seconds: _PositiveInt = 600
    ip_accounts_elevated: _PositiveInt = 4
    ip_accounts_high: _PositiveInt = 10
    denial_window_seconds: _PositiveInt = 600
    denials_elevated: _PositiveInt = 1
    denials_high: _PositiveInt = 3
    elevated_cost: _PositiveInt = 3
    high_cost: _PositiveInt = 10
    state_retention_seconds: _PositiveInt = 86400


@dataclass(frozen=True)
class DocumentDownloadRiskPolicy(_ConfigPolicy):
    _SOURCE = _PolicySource(
        (_Section("document"), _Section("download"), _Section("risk_control"))
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
    refill_period_seconds: _PositiveInt = 600
    issue_account_capacity: _PositiveInt = 60
    issue_account_refill_tokens: _PositiveInt = 300
    issue_ip_capacity: _PositiveInt = 200
    issue_ip_refill_tokens: _PositiveInt = 1000
    transfer_account_capacity: _PositiveInt = 60
    transfer_account_refill_tokens: _PositiveInt = 300
    transfer_ip_capacity: _PositiveInt = 200
    transfer_ip_refill_tokens: _PositiveInt = 1000
    task_capacity: _PositiveInt = 5
    task_refill_tokens: _PositiveInt = 10
    task_refill_period_seconds: _PositiveInt = 3600
    new_account_seconds: _PositiveInt = 7 * 24 * 60 * 60
    ip_account_window_seconds: _PositiveInt = 600
    ip_accounts_elevated: _PositiveInt = 4
    ip_accounts_high: _PositiveInt = 10
    denial_window_seconds: _PositiveInt = 600
    denials_elevated: _PositiveInt = 1
    denials_high: _PositiveInt = 3
    elevated_cost: _PositiveInt = 3
    high_cost: _PositiveInt = 10
    state_retention_seconds: _PositiveInt = 86400


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


def validate_config(config: _ConfigSource) -> None:
    get_trusted_proxy_networks(config)
    get_enabled_extensions(config)
    AuthThrottlePolicy.from_config(config)
    AdmissionControlPolicy.from_config(config)
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
