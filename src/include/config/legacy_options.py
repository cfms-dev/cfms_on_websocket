"""File locations superseded by namespaced database options."""

from collections.abc import Mapping
from typing import Any

from include.config._policy import ConfigValidationError

PASSWORD_OPTION_KEYS = (
    "passwd_min_length",
    "passwd_max_length",
    "passwd_rules",
    "passwd_min_passed_count",
    "enable_passwd_force_expiration",
    "passwd_expire_after_days",
)
LEGACY_OPTION_GROUPS = (
    ("server", "server", "core", ("name",)),
    ("security", "security.password", "core", PASSWORD_OPTION_KEYS),
    ("security.auth_throttle", "security.auth_throttle", "core", None),
    ("security.request_rate_control", "security.request_rate_control", "core", None),
    ("access", "access", "core", None),
    (
        "document.upload.creation_risk_control",
        "document.upload.creation_risk_control",
        "core",
        None,
    ),
    (
        "document.upload",
        "document.upload",
        "core",
        (
            "start_timeout_seconds",
            "max_duration_seconds",
            "idle_timeout_seconds",
            "cleanup_interval_seconds",
            "max_pending_documents_per_creator",
        ),
    ),
    ("document.download.risk_control", "document.download.risk_control", "core", None),
    ("identity.permission_retention", "identity.permission_retention", "core", None),
    ("maintenance.audit_retention", "maintenance.audit_retention", "core", None),
    (
        "scheduling",
        "scheduling",
        "core",
        ("misfire_grace_seconds", "history_retention_days"),
    ),
    (
        "extensions.brute_force_lockdown",
        "security.brute_force_lockdown",
        "brute_force_lockdown",
        None,
    ),
    (
        "extensions.oidc_sso",
        "identity.oidc",
        "oidc_sso",
        ("username_claim", "auto_provision", "default_groups"),
    ),
)


def legacy_option_candidates(config: Mapping[str, Any]):
    for path, namespace, owner, keys in LEGACY_OPTION_GROUPS:
        section = config
        parts = path.split(".")
        for index, part in enumerate(parts):
            if part not in section:
                break
            section = section[part]
            if not isinstance(section, Mapping):
                if index == len(parts) - 1 and keys is None:
                    yield path, namespace, owner, section
                    break
                raise ConfigValidationError(f"{path} must be a table")
        else:
            values = (
                dict(section)
                if keys is None
                else {key: section[key] for key in keys if key in section}
            )
            if values or keys is None:
                yield path, namespace, owner, values


def legacy_option_paths(config: Mapping[str, Any]) -> tuple[str, ...]:
    return tuple(
        location
        for path, _, _, values in legacy_option_candidates(config)
        for location in (
            [f"{path}.{key}" for key in values]
            if isinstance(values, Mapping) and values
            else [path]
        )
    )
