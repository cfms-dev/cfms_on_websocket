import copy
import re
from collections.abc import Mapping, Sequence
from typing import Any

from maintenance.operations.exceptions import MaintenanceOperationError

MISSING = object()
LEGACY_PATHS = frozenset(
    {
        "database.db_name",
        "document.allow_name_duplicate",
        "document.upload.creation_rate_per_ip",
        "document.upload.creation_rate_per_user",
        "document.upload.creation_rate_window_seconds",
        "security.passwd_must_contain",
        "sso.oidc",
    }
)


def has_legacy_descendant(dotted_path: str) -> bool:
    prefix = f"{dotted_path}."
    return any(path.startswith(prefix) for path in LEGACY_PATHS)


def apply_legacy_migrations(
    current: Mapping[str, Any], candidate: Any
) -> tuple[list[str], set[str], list[str]]:
    migrations = []
    migrated_targets: set[str] = set()
    warnings = []

    old_database_name = get_path(current, "database.db_name")
    if old_database_name is not MISSING:
        target = "database.name"
        if not has_path(current, target):
            set_path(candidate, target, copy.deepcopy(old_database_name))
            migrated_targets.add(target)
        migrations.append("database.db_name -> database.name")

    old_oidc = get_path(current, "sso.oidc")
    if old_oidc is not MISSING:
        target = "extensions.oidc_sso"
        if isinstance(old_oidc, Mapping):
            target_section = get_path(candidate, target)
            if not isinstance(target_section, Mapping):
                raise MaintenanceOperationError(
                    f"Configuration template is missing migration target {target}"
                )
            for key, value in old_oidc.items():
                target_path = f"{target}.{key}"
                if key == "enabled" or has_path(current, target_path):
                    continue
                target_section[key] = copy.deepcopy(value)
                migrated_targets.add(target_path)

            old_oidc_enabled = old_oidc.get("enabled", MISSING)
        else:
            old_oidc_enabled = MISSING
            warnings.append(
                "sso.oidc is not a table; extensions.oidc_sso uses its current "
                "or template value"
            )

        enabled_target = "extensions.enabled"
        if isinstance(old_oidc_enabled, bool):
            enabled_extensions = get_path(candidate, enabled_target)
            if enabled_extensions is MISSING:
                raise MaintenanceOperationError(
                    "Configuration template is missing migration target "
                    f"{enabled_target}"
                )
            if (
                old_oidc_enabled
                and isinstance(enabled_extensions, list)
                and "oidc_sso" not in enabled_extensions
            ):
                enabled_extensions.append("oidc_sso")
        elif old_oidc_enabled is not MISSING:
            warnings.append(
                "sso.oidc.enabled is not a boolean; extensions.enabled keeps its "
                "current or template value"
            )
        if old_oidc_enabled is not MISSING and not has_path(current, enabled_target):
            migrated_targets.add(enabled_target)
        migrations.append("sso.oidc -> extensions.oidc_sso + extensions.enabled")

    legacy_rate_paths = {
        "document.upload.creation_rate_window_seconds": (
            "document.upload.creation_risk_control.refill_period_seconds",
        ),
        "document.upload.creation_rate_per_user": (
            "document.upload.creation_risk_control.account_refill_tokens",
            "document.upload.creation_risk_control.account_capacity",
        ),
        "document.upload.creation_rate_per_ip": (
            "document.upload.creation_risk_control.ip_refill_tokens",
            "document.upload.creation_risk_control.ip_capacity",
        ),
    }
    present_rate_paths = [path for path in legacy_rate_paths if has_path(current, path)]
    if present_rate_paths:
        high_cost = get_path(
            candidate, "document.upload.creation_risk_control.high_cost"
        )
        if isinstance(high_cost, bool) or not isinstance(high_cost, int):
            high_cost = 10
        for source_path in present_rate_paths:
            value = get_path(current, source_path)
            targets = legacy_rate_paths[source_path]
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                warnings.append(
                    f"{source_path} is not a positive integer; replacement settings "
                    "use their current or template values"
                )
                migrated_targets.update(
                    target for target in targets if not has_path(current, target)
                )
                continue
            primary_target = targets[0]
            if not has_path(current, primary_target):
                set_path(candidate, primary_target, value)
                migrated_targets.add(primary_target)
            if len(targets) == 2 and not has_path(current, targets[1]):
                set_path(candidate, targets[1], max(high_cost, (value + 4) // 5))
                migrated_targets.add(targets[1])
        migrations.append(
            "document.upload.creation_rate_* -> document.upload.creation_risk_control"
        )

    old_password_groups = get_path(current, "security.passwd_must_contain")
    if old_password_groups is not MISSING:
        targets = ("security.passwd_rules", "security.passwd_min_passed_count")
        converted_rules = _convert_password_groups(old_password_groups)
        if converted_rules is None:
            warnings.append(
                "security.passwd_must_contain cannot be converted safely; replacement "
                "settings use their current or template values"
            )
        else:
            if not has_path(current, targets[0]):
                set_path(candidate, targets[0], converted_rules)
            if not has_path(current, targets[1]):
                set_path(candidate, targets[1], len(converted_rules))
        migrated_targets.update(
            target for target in targets if not has_path(current, target)
        )
        migrations.append(
            "security.passwd_must_contain -> "
            "security.passwd_rules + security.passwd_min_passed_count"
        )

    if has_path(current, "document.allow_name_duplicate"):
        warnings.append(
            "document.allow_name_duplicate is obsolete and has no replacement; "
            "active node names are always unique"
        )

    return migrations, migrated_targets, warnings


def _convert_password_groups(value: Any) -> list[str] | None:
    if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
        return None
    rules = []
    for group in value:
        if isinstance(group, str):
            characters = tuple(group)
        elif isinstance(group, Sequence) and not isinstance(group, bytes):
            if not all(
                isinstance(character, str) and len(character) == 1
                for character in group
            ):
                return None
            characters = tuple(group)
        else:
            return None
        if not characters:
            return None
        alternatives = "|".join(
            re.escape(character) for character in dict.fromkeys(characters)
        )
        rules.append(f"(?:{alternatives})")
    return rules


def get_path(config: Mapping[str, Any], dotted_path: str) -> Any:
    value: Any = config
    for part in dotted_path.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return MISSING
        value = value[part]
    return value


def has_path(config: Mapping[str, Any], dotted_path: str) -> bool:
    return get_path(config, dotted_path) is not MISSING


def set_path(config: Any, dotted_path: str, value: Any) -> None:
    parts = dotted_path.split(".")
    target = config
    for part in parts[:-1]:
        if not isinstance(target, Mapping) or part not in target:
            raise MaintenanceOperationError(
                f"Configuration template is missing migration target {dotted_path}"
            )
        target = target[part]
    if not isinstance(target, Mapping) or parts[-1] not in target:
        raise MaintenanceOperationError(
            f"Configuration template is missing migration target {dotted_path}"
        )
    target[parts[-1]] = value
