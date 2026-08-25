import copy
import datetime as dt
import os
import re
import secrets
import shutil
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import tomlkit
from tomlkit.exceptions import TOMLKitError

from include.config.validation import ConfigValidationError, parse_config_document
from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.runtime import ensure_src_workdir

_MISSING = object()
_LEGACY_PATHS = frozenset(
    {
        "database.db_name",
        "document.allow_name_duplicate",
        "document.upload.creation_rate_per_ip",
        "document.upload.creation_rate_per_user",
        "document.upload.creation_rate_window_seconds",
        "security.passwd_must_contain",
        "sso.oidc.enabled",
    }
)


@dataclass(frozen=True)
class PepperFillResult:
    config_path: Path
    changed: bool
    added_security_section: bool


@dataclass(frozen=True, slots=True)
class ConfigTemplateInspection:
    config_path: Path
    template_path: Path
    unknown_paths: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ConfigSyncResult:
    config_path: Path
    template_path: Path
    changed: bool
    added_paths: tuple[str, ...]
    migrations: tuple[str, ...]
    removed_paths: tuple[str, ...]
    preserved_paths: tuple[str, ...]
    warnings: tuple[str, ...]
    backup_path: Path | None = None


def fill_pepper(config_path: str | Path = "config.toml") -> PepperFillResult:
    ensure_src_workdir()
    path = Path(config_path)
    if not path.exists():
        raise MaintenanceOperationError(f"Configuration file not found: {path}")

    try:
        doc = tomlkit.parse(path.read_text(encoding="utf-8"))
    except Exception as exc:
        raise MaintenanceOperationError(f"Unable to read {path}: {exc}") from exc

    added_security_section = False
    if "security" not in doc:
        doc.add("security", tomlkit.table())
        added_security_section = True

    security_section = doc["security"]
    if security_section.get("pepper"):
        return PepperFillResult(
            config_path=path,
            changed=False,
            added_security_section=added_security_section,
        )

    security_section["pepper"] = secrets.token_hex(32)
    try:
        path.write_text(tomlkit.dumps(doc), encoding="utf-8")
    except Exception as exc:
        raise MaintenanceOperationError(f"Unable to write {path}: {exc}") from exc

    return PepperFillResult(
        config_path=path,
        changed=True,
        added_security_section=added_security_section,
    )


def inspect_config_template(
    template_path: str | Path = "config.toml.sample",
) -> ConfigTemplateInspection:
    config_path, resolved_template_path, current, template, _source = _load_documents(
        template_path
    )
    return ConfigTemplateInspection(
        config_path=config_path,
        template_path=resolved_template_path,
        unknown_paths=tuple(_find_unknown_roots(current, template)),
    )


def sync_config_template(
    template_path: str | Path = "config.toml.sample",
    *,
    remove_paths: Sequence[str] = (),
    prune: bool = False,
    write: bool = True,
) -> ConfigSyncResult:
    config_path, resolved_template_path, current, template, current_source = (
        _load_documents(template_path)
    )
    unknown_paths = tuple(_find_unknown_roots(current, template))
    requested_removals = set(remove_paths)
    invalid_removals = sorted(requested_removals - set(unknown_paths))
    if invalid_removals:
        raise MaintenanceOperationError(
            "Unknown --remove path(s): " + ", ".join(invalid_removals)
        )
    selected_removals = set(unknown_paths) if prune else requested_removals

    candidate = copy.deepcopy(template)
    _overlay_current_values(
        current,
        candidate,
        removed_unknown_paths=selected_removals,
    )
    migrations, migrated_targets, warnings = _apply_legacy_migrations(
        current, candidate
    )

    rendered = tomlkit.dumps(candidate)
    try:
        parse_config_document(rendered)
    except ConfigValidationError as exc:
        raise MaintenanceOperationError(
            f"Synchronized configuration is invalid: {exc}"
        ) from exc

    added_paths = set(_find_missing_template_leaves(current, template))
    added_paths.difference_update(migrated_targets)
    legacy_present = sorted(path for path in _LEGACY_PATHS if _has_path(current, path))
    removed_paths = tuple(sorted((*legacy_present, *selected_removals)))
    preserved_paths = tuple(
        path for path in unknown_paths if path not in selected_removals
    )
    changed = rendered != current_source
    backup_path = None
    if write and changed:
        backup_path = write_config_atomically(config_path, current_source, rendered)

    return ConfigSyncResult(
        config_path=config_path,
        template_path=resolved_template_path,
        changed=changed,
        added_paths=tuple(sorted(added_paths)),
        migrations=tuple(migrations),
        removed_paths=removed_paths,
        preserved_paths=preserved_paths,
        warnings=tuple(warnings),
        backup_path=backup_path,
    )


def _load_documents(
    template_path: str | Path,
) -> tuple[Path, Path, tomlkit.TOMLDocument, tomlkit.TOMLDocument, str]:
    workdir = ensure_src_workdir()
    config_path = workdir / "config.toml"
    candidate_template_path = Path(template_path)
    if not candidate_template_path.is_absolute():
        candidate_template_path = workdir / candidate_template_path
    resolved_template_path = candidate_template_path.resolve()
    if resolved_template_path == config_path:
        raise MaintenanceOperationError(
            "The configuration template must be different from config.toml"
        )
    if not resolved_template_path.is_file():
        raise MaintenanceOperationError(
            f"Configuration template not found: {resolved_template_path}"
        )

    try:
        current_source = config_path.read_text(encoding="utf-8")
        template_source = resolved_template_path.read_text(encoding="utf-8")
        current = tomlkit.parse(current_source)
        template = tomlkit.parse(template_source)
    except (OSError, TOMLKitError) as exc:
        raise MaintenanceOperationError(
            f"Unable to read configuration documents: {exc}"
        ) from exc
    return config_path, resolved_template_path, current, template, current_source


def _find_unknown_roots(
    current: Mapping[str, Any],
    template: Mapping[str, Any],
    prefix: tuple[str, ...] = (),
) -> list[str]:
    unknown = []
    for key, current_value in current.items():
        path = (*prefix, str(key))
        dotted_path = ".".join(path)
        if dotted_path in _LEGACY_PATHS:
            continue
        if key not in template:
            unknown.append(dotted_path)
            continue
        template_value = template[key]
        current_is_table = isinstance(current_value, Mapping)
        template_is_table = isinstance(template_value, Mapping)
        if current_is_table != template_is_table:
            raise MaintenanceOperationError(
                f"Configuration shape differs from the template at {dotted_path}"
            )
        if current_is_table:
            unknown.extend(_find_unknown_roots(current_value, template_value, path))
    return unknown


def _overlay_current_values(
    current: Mapping[str, Any],
    candidate: Any,
    *,
    prefix: tuple[str, ...] = (),
    removed_unknown_paths: set[str],
) -> None:
    for key, current_value in current.items():
        path = (*prefix, str(key))
        dotted_path = ".".join(path)
        if dotted_path in _LEGACY_PATHS or dotted_path in removed_unknown_paths:
            continue
        if key not in candidate:
            candidate.add(key, copy.deepcopy(current_value))
            continue
        candidate_value = candidate[key]
        current_is_table = isinstance(current_value, Mapping)
        candidate_is_table = isinstance(candidate_value, Mapping)
        if current_is_table:
            _overlay_current_values(
                current_value,
                candidate_value,
                prefix=path,
                removed_unknown_paths=removed_unknown_paths,
            )
        elif not candidate_is_table:
            candidate[key] = copy.deepcopy(current_value)


def _find_missing_template_leaves(
    current: Mapping[str, Any],
    template: Mapping[str, Any],
    prefix: tuple[str, ...] = (),
) -> list[str]:
    missing = []
    for key, template_value in template.items():
        path = (*prefix, str(key))
        if key not in current:
            missing.extend(_leaf_paths(template_value, path))
            continue
        current_value = current[key]
        if isinstance(template_value, Mapping) and isinstance(current_value, Mapping):
            missing.extend(
                _find_missing_template_leaves(current_value, template_value, path)
            )
    return missing


def _leaf_paths(value: Any, prefix: tuple[str, ...]) -> list[str]:
    if not isinstance(value, Mapping):
        return [".".join(prefix)]
    paths = []
    for key, nested_value in value.items():
        paths.extend(_leaf_paths(nested_value, (*prefix, str(key))))
    return paths or [".".join(prefix)]


def _apply_legacy_migrations(
    current: Mapping[str, Any], candidate: Any
) -> tuple[list[str], set[str], list[str]]:
    migrations = []
    migrated_targets: set[str] = set()
    warnings = []

    old_database_name = _get_path(current, "database.db_name")
    if old_database_name is not _MISSING:
        target = "database.name"
        if not _has_path(current, target):
            _set_path(candidate, target, copy.deepcopy(old_database_name))
            migrated_targets.add(target)
        migrations.append("database.db_name -> database.name")

    old_oidc_enabled = _get_path(current, "sso.oidc.enabled")
    if old_oidc_enabled is not _MISSING:
        target = "extensions.enabled"
        if isinstance(old_oidc_enabled, bool):
            enabled_extensions = _get_path(candidate, target)
            if enabled_extensions is _MISSING:
                raise MaintenanceOperationError(
                    f"Configuration template is missing migration target {target}"
                )
            if (
                old_oidc_enabled
                and isinstance(enabled_extensions, list)
                and "oidc_sso" not in enabled_extensions
            ):
                enabled_extensions.append("oidc_sso")
        else:
            warnings.append(
                "sso.oidc.enabled is not a boolean; extensions.enabled keeps its "
                "current or template value"
            )
        if not _has_path(current, target):
            migrated_targets.add(target)
        migrations.append("sso.oidc.enabled -> extensions.enabled")

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
    present_rate_paths = [
        path for path in legacy_rate_paths if _has_path(current, path)
    ]
    if present_rate_paths:
        high_cost = _get_path(
            candidate, "document.upload.creation_risk_control.high_cost"
        )
        if isinstance(high_cost, bool) or not isinstance(high_cost, int):
            high_cost = 10
        for source_path in present_rate_paths:
            value = _get_path(current, source_path)
            targets = legacy_rate_paths[source_path]
            if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                warnings.append(
                    f"{source_path} is not a positive integer; replacement settings "
                    "use their current or template values"
                )
                migrated_targets.update(
                    target for target in targets if not _has_path(current, target)
                )
                continue
            primary_target = targets[0]
            if not _has_path(current, primary_target):
                _set_path(candidate, primary_target, value)
                migrated_targets.add(primary_target)
            if len(targets) == 2 and not _has_path(current, targets[1]):
                _set_path(candidate, targets[1], max(high_cost, (value + 4) // 5))
                migrated_targets.add(targets[1])
        migrations.append(
            "document.upload.creation_rate_* -> document.upload.creation_risk_control"
        )

    old_password_groups = _get_path(current, "security.passwd_must_contain")
    if old_password_groups is not _MISSING:
        targets = ("security.passwd_rules", "security.passwd_min_passed_count")
        converted_rules = _convert_password_groups(old_password_groups)
        if converted_rules is None:
            warnings.append(
                "security.passwd_must_contain cannot be converted safely; replacement "
                "settings use their current or template values"
            )
        else:
            if not _has_path(current, targets[0]):
                _set_path(candidate, targets[0], converted_rules)
            if not _has_path(current, targets[1]):
                _set_path(candidate, targets[1], len(converted_rules))
        migrated_targets.update(
            target for target in targets if not _has_path(current, target)
        )
        migrations.append(
            "security.passwd_must_contain -> "
            "security.passwd_rules + security.passwd_min_passed_count"
        )

    if _has_path(current, "document.allow_name_duplicate"):
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


def _get_path(config: Mapping[str, Any], dotted_path: str) -> Any:
    value: Any = config
    for part in dotted_path.split("."):
        if not isinstance(value, Mapping) or part not in value:
            return _MISSING
        value = value[part]
    return value


def _has_path(config: Mapping[str, Any], dotted_path: str) -> bool:
    return _get_path(config, dotted_path) is not _MISSING


def _set_path(config: Any, dotted_path: str, value: Any) -> None:
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


def write_config_atomically(
    config_path: Path, current_source: str, rendered: str
) -> Path:
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    backup_path = config_path.with_name(f"{config_path.name}.backup-{timestamp}")
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=config_path.parent,
            prefix=f".{config_path.name}.",
            suffix=".tmp",
            delete=False,
            newline="",
        ) as temporary_file:
            temporary_file.write(rendered)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
            temporary_path = Path(temporary_file.name)
        shutil.copymode(config_path, temporary_path)
        shutil.copy2(config_path, backup_path)
        if backup_path.read_text(encoding="utf-8") != current_source:
            raise OSError(f"Configuration backup verification failed: {backup_path}")
        os.replace(temporary_path, config_path)
    except OSError as exc:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise MaintenanceOperationError(
            f"Unable to update {config_path}: {exc}"
        ) from exc

    return backup_path
