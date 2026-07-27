import ipaddress
import os
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, fields
from functools import lru_cache
from typing import Any, Protocol

from tomlkit import TOMLDocument, parse
from tomlkit.exceptions import TOMLKitError

from include.config.constants import DEFAULT_TRUSTED_PROXY_NETWORKS

__all__ = [
    "AuthThrottlePolicy",
    "ConfigValidationError",
    "DocumentUploadPolicy",
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
class AuthThrottlePolicy:
    enabled: bool = True
    account_failure_threshold: int = 5
    account_base_delay_seconds: int = 30
    account_max_delay_seconds: int = 3600
    account_reset_seconds: int = 86400
    account_ip_failure_threshold: int = 5
    account_ip_window_seconds: int = 900
    account_ip_block_seconds: int = 900
    ip_failure_threshold: int = 60
    ip_window_seconds: int = 600
    ip_block_seconds: int = 900
    record_retention_days: int = 7

    @classmethod
    def from_config(cls, config: _ConfigSource | None = None) -> AuthThrottlePolicy:
        if config is None:
            from include.config.settings import global_config

            config = global_config

        section = _section(config, "security").get("auth_throttle", {})
        if not isinstance(section, Mapping):
            raise ConfigValidationError("security.auth_throttle must be a table")

        values = {
            field.name: section.get(field.name, field.default) for field in fields(cls)
        }
        policy = cls(**values)
        if not isinstance(policy.enabled, bool):
            raise ConfigValidationError(
                "security.auth_throttle.enabled must be a boolean"
            )
        for field in fields(cls):
            if field.name == "enabled":
                continue
            value = getattr(policy, field.name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ConfigValidationError(
                    f"security.auth_throttle.{field.name} must be a positive integer"
                )
        if policy.account_base_delay_seconds > policy.account_max_delay_seconds:
            raise ConfigValidationError(
                "security.auth_throttle.account_base_delay_seconds must not exceed "
                "security.auth_throttle.account_max_delay_seconds"
            )
        return policy


@dataclass(frozen=True)
class DocumentUploadPolicy:
    start_timeout_seconds: int = 3600
    max_duration_seconds: int = 86400
    idle_timeout_seconds: int = 300
    cleanup_interval_seconds: int = 60
    max_pending_documents_per_creator: int = 16
    creation_rate_window_seconds: int = 600
    creation_rate_per_user: int = 300
    creation_rate_per_ip: int = 1000

    @classmethod
    def from_config(cls, config: _ConfigSource | None = None) -> DocumentUploadPolicy:
        if config is None:
            from include.config.settings import global_config

            config = global_config

        try:
            document = config["document"]
        except KeyError:
            document = {}
        if not isinstance(document, Mapping):
            raise ConfigValidationError("document must be a table")

        upload = document.get("upload", {})
        if not isinstance(upload, Mapping):
            raise ConfigValidationError("document.upload must be a table")

        values = {
            field.name: upload.get(field.name, field.default) for field in fields(cls)
        }
        policy = cls(**values)
        for field in fields(cls):
            value = getattr(policy, field.name)
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                raise ConfigValidationError(
                    f"document.upload.{field.name} must be a positive integer"
                )
        if policy.idle_timeout_seconds > policy.max_duration_seconds:
            raise ConfigValidationError(
                "document.upload.idle_timeout_seconds must not exceed "
                "document.upload.max_duration_seconds"
            )
        if policy.start_timeout_seconds >= policy.max_duration_seconds:
            raise ConfigValidationError(
                "document.upload.start_timeout_seconds must be less than "
                "document.upload.max_duration_seconds"
            )
        return policy


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


def validate_config(config: _ConfigSource) -> None:
    get_trusted_proxy_networks(config)
    get_enabled_extensions(config)
    AuthThrottlePolicy.from_config(config)
    DocumentUploadPolicy.from_config(config)
    _validate_client_certificate_config(config)

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
