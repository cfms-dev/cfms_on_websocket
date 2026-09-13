import copy
import datetime as dt
import os
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
from maintenance.operations.config.legacy import (
    LEGACY_PATHS,
    apply_legacy_migrations,
    has_legacy_descendant,
    has_path,
)
from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.runtime import enter_server_root

MAX_CONFIG_BYTES = 16 * 1024 * 1024


def read_config_text(path: Path) -> str:
    with path.open("rb") as config_file:
        contents = config_file.read(MAX_CONFIG_BYTES + 1)
    if len(contents) > MAX_CONFIG_BYTES:
        raise MaintenanceOperationError(
            f"Configuration file exceeds the {MAX_CONFIG_BYTES}-byte limit: {path}"
        )
    try:
        return contents.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise MaintenanceOperationError(
            f"Configuration file is not valid UTF-8: {path}"
        ) from exc


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
    enter_server_root()
    path = Path(config_path)
    if not path.exists():
        raise MaintenanceOperationError(f"Configuration file not found: {path}")

    try:
        current_source = read_config_text(path)
        doc = tomlkit.parse(current_source)
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
        _replace_text_atomically(path, tomlkit.dumps(doc))
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
    migrations, migrated_targets, warnings = apply_legacy_migrations(current, candidate)

    rendered = tomlkit.dumps(candidate)
    try:
        parse_config_document(rendered)
    except ConfigValidationError as exc:
        raise MaintenanceOperationError(
            f"Synchronized configuration is invalid: {exc}"
        ) from exc

    added_paths = set(_find_missing_template_leaves(current, template))
    added_paths.difference_update(migrated_targets)
    legacy_present = sorted(path for path in LEGACY_PATHS if has_path(current, path))
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
    workdir = enter_server_root()
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
        current_source = read_config_text(config_path)
        template_source = read_config_text(resolved_template_path)
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
        current_is_table = isinstance(current_value, Mapping)
        if dotted_path in LEGACY_PATHS:
            continue
        if key not in template:
            if current_is_table and has_legacy_descendant(dotted_path):
                unknown.extend(_find_unknown_roots(current_value, {}, path))
                continue
            unknown.append(dotted_path)
            continue
        template_value = template[key]
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
        current_is_table = isinstance(current_value, Mapping)
        if dotted_path in LEGACY_PATHS or dotted_path in removed_unknown_paths:
            continue
        if key not in candidate:
            if current_is_table and has_legacy_descendant(dotted_path):
                nested_candidate = tomlkit.table()
                _overlay_current_values(
                    current_value,
                    nested_candidate,
                    prefix=path,
                    removed_unknown_paths=removed_unknown_paths,
                )
                if nested_candidate:
                    candidate.add(key, nested_candidate)
                continue
            candidate.add(key, copy.deepcopy(current_value))
            continue
        candidate_value = candidate[key]
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


def write_config_atomically(
    config_path: Path, current_source: str, rendered: str
) -> Path:
    timestamp = dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M%S.%fZ")
    backup_path = config_path.with_name(f"{config_path.name}.backup-{timestamp}")
    try:
        shutil.copy2(config_path, backup_path)
        if read_config_text(backup_path) != current_source:
            raise OSError(f"Configuration backup verification failed: {backup_path}")
        _replace_text_atomically(config_path, rendered)
    except OSError as exc:
        raise MaintenanceOperationError(
            f"Unable to update {config_path}: {exc}"
        ) from exc

    return backup_path


def _replace_text_atomically(path: Path, contents: str) -> None:
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
            newline="",
        ) as temporary_file:
            temporary_file.write(contents)
            temporary_file.flush()
            os.fsync(temporary_file.fileno())
            temporary_path = Path(temporary_file.name)
        shutil.copymode(path, temporary_path)
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
