from collections.abc import Mapping
from contextlib import ExitStack, contextmanager, nullcontext
from dataclasses import dataclass
from pathlib import Path
from typing import Any
lazy from collections.abc import Generator

import orjson
import tomlkit
from pydantic import TypeAdapter, ValidationError
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from tomlkit.exceptions import TOMLKitError

from include.config.validation import ConfigValidationError
from include.runtime_lock import RuntimeLockError, server_runtime_lock
from maintenance.operations.config.sync import read_config_text, write_config_atomically
from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.runtime import enter_server_root, load_database_models
lazy from include.config.options import (
    CORE_SERVER_OPTIONS,
    OptionGroupDefinition,
    ResolvedOption,
    get_option_group,
    read_options,
    write_options,
)
lazy from include.database.models.operations import OptionEntry
lazy from include.database.options import OptionOwner, StoredOption, read_option
lazy from include.database.session import Session
lazy from include.extensions.manager import (
    ExtensionLoadError,
    maintenance_extension_context,
)


@contextmanager
def _options_runtime(owner: str) -> Generator[None]:
    load_database_models()
    try:
        with nullcontext() if owner == "core" else maintenance_extension_context(owner):
            yield
    except (
        ConfigValidationError,
        ValidationError,
        ExtensionLoadError,
        SQLAlchemyError,
    ) as exc:
        raise MaintenanceOperationError(
            f"Unable to maintain options for {owner}: {exc}"
        ) from exc


def list_options(
    owner: str | None = None,
) -> tuple[ResolvedOption[Any] | StoredOption, ...]:
    load_database_models()
    try:
        with Session() as session:
            statement = select(
                OptionEntry.owner,
                OptionEntry.option_key,
                OptionEntry.schema_version,
                OptionEntry.revision,
                OptionEntry.payload,
                OptionEntry.updated_at,
            ).order_by(OptionEntry.owner, OptionEntry.option_key)
            if owner is not None:
                TypeAdapter(OptionOwner).validate_python(owner, strict=True)
                statement = statement.where(OptionEntry.owner == owner)
            options = [
                StoredOption(**row) for row in session.execute(statement).mappings()
            ]
            if owner in (None, "core") and not any(
                option.owner == "core" and option.option_key == "server"
                for option in options
            ):
                options.append(read_options(session, "core", CORE_SERVER_OPTIONS))
            return tuple(
                sorted(options, key=lambda option: (option.owner, option.option_key))
            )
    except (ConfigValidationError, ValidationError, SQLAlchemyError) as exc:
        raise MaintenanceOperationError(f"Unable to list options: {exc}") from exc


def get_options(owner: str, option_key: str) -> ResolvedOption[Any] | StoredOption:
    load_database_models()
    try:
        with Session() as session:
            stored = read_option(session, owner, option_key)
            if stored is not None:
                return stored
            if (owner, option_key) == ("core", "server"):
                return read_options(session, owner, CORE_SERVER_OPTIONS)
            raise MaintenanceOperationError(
                f"No stored option group {owner}/{option_key}"
            )
    except (ConfigValidationError, ValidationError, SQLAlchemyError) as exc:
        raise MaintenanceOperationError(f"Unable to read options: {exc}") from exc


def set_options(
    owner: str,
    option_key: str,
    payload_file: Path,
    *,
    expected_revision: int,
) -> ResolvedOption[Any]:
    try:
        payload = orjson.loads(read_config_text(payload_file.resolve()))
    except (OSError, orjson.JSONDecodeError) as exc:
        raise MaintenanceOperationError(f"Unable to read options JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise MaintenanceOperationError("Options JSON must contain an object")
    with _options_runtime(owner), Session.begin() as session:
        return write_options(
            session,
            owner,
            get_option_group(owner, option_key),
            payload,
            expected_revision=expected_revision,
            source="maintenance_cli",
        )


def reset_options(
    owner: str, option_key: str, *, expected_revision: int
) -> ResolvedOption[Any]:
    with _options_runtime(owner), Session.begin() as session:
        definition = get_option_group(owner, option_key)
        return write_options(
            session,
            owner,
            definition,
            definition.default_payload(),
            expected_revision=expected_revision,
            source="maintenance_cli",
        )


@dataclass(frozen=True, slots=True)
class OptionMigrationItem:
    legacy_path: str
    owner: str
    option_key: str
    action: str
    revision: int


@dataclass(frozen=True, slots=True)
class OptionMigrationResult:
    config_path: Path
    items: tuple[OptionMigrationItem, ...]
    backup_path: Path | None = None

    @property
    def changed(self) -> bool:
        return bool(self.items)


def migrate_options(
    *, write: bool = False, discard_legacy: bool = False
) -> OptionMigrationResult:
    workdir = enter_server_root()
    try:
        with server_runtime_lock(workdir) if write else nullcontext():
            return _migrate_options(
                workdir / "config.toml", write=write, discard_legacy=discard_legacy
            )
    except RuntimeLockError as exc:
        raise MaintenanceOperationError(str(exc)) from exc


def _migrate_options(
    config_path: Path, *, write: bool, discard_legacy: bool
) -> OptionMigrationResult:
    try:
        current_source = read_config_text(config_path)
        document = tomlkit.parse(current_source)
    except (OSError, TOMLKitError) as exc:
        raise MaintenanceOperationError(f"Unable to read config.toml: {exc}") from exc

    server = document.get("server", {})
    extensions = document.get("extensions", {})
    has_server_name = isinstance(server, Mapping) and "name" in server
    has_policy = (
        isinstance(extensions, Mapping) and "brute_force_lockdown" in extensions
    )
    if not has_server_name and not has_policy:
        return OptionMigrationResult(config_path, ())

    load_database_models()
    items = []
    try:
        with ExitStack() as resources:
            candidates: list[tuple[str, str, OptionGroupDefinition[Any], dict]] = []
            if has_server_name:
                candidates.append(
                    (
                        "server.name",
                        "core",
                        CORE_SERVER_OPTIONS,
                        {"name": server["name"]},
                    )
                )
            if has_policy:
                legacy_policy = extensions["brute_force_lockdown"]
                if not discard_legacy and not isinstance(legacy_policy, Mapping):
                    raise MaintenanceOperationError(
                        "extensions.brute_force_lockdown must be a table"
                    )
                resources.enter_context(
                    maintenance_extension_context("brute_force_lockdown")
                )
                candidates.append(
                    (
                        "extensions.brute_force_lockdown",
                        "brute_force_lockdown",
                        get_option_group("brute_force_lockdown", "policy"),
                        {} if discard_legacy else legacy_policy.unwrap(),
                    )
                )
            session = resources.enter_context(Session())
            pending = []
            for legacy_path, owner, definition, legacy_payload in candidates:
                existing = read_options(session, owner, definition)
                if discard_legacy:
                    action = (
                        "Discard legacy" if existing.revision else "Create defaults"
                    )
                    payload = existing.payload
                else:
                    payload = definition.serialize(definition.validate(legacy_payload))
                    if existing.revision and existing.payload != payload:
                        raise MaintenanceOperationError(
                            f"Database options for {owner}/{definition.option_key} differ from "
                            f"{legacy_path}. Use --discard-legacy to keep the database value."
                        )
                    action = "Already imported" if existing.revision else "Import"
                items.append(
                    OptionMigrationItem(
                        legacy_path,
                        owner,
                        definition.option_key,
                        action,
                        existing.revision,
                    )
                )
                if not existing.revision:
                    pending.append((owner, definition, payload))

            if not write:
                return OptionMigrationResult(config_path, tuple(items))
            if read_config_text(config_path) != current_source:
                raise MaintenanceOperationError(
                    "config.toml changed while preparing migration; retry"
                )
            for owner, definition, payload in pending:
                write_options(
                    session,
                    owner,
                    definition,
                    payload,
                    expected_revision=0,
                    source="maintenance_cli_migration",
                )
            session.commit()
    except (
        ConfigValidationError,
        ValidationError,
        ExtensionLoadError,
        SQLAlchemyError,
    ) as exc:
        raise MaintenanceOperationError(f"Unable to migrate options: {exc}") from exc

    if has_server_name:
        del document["server"]["name"]
    if has_policy:
        del document["extensions"]["brute_force_lockdown"]
    try:
        backup_path = write_config_atomically(
            config_path, current_source, tomlkit.dumps(document)
        )
    except MaintenanceOperationError as exc:
        raise MaintenanceOperationError(
            "Database options were committed, but config.toml cleanup failed. "
            "Rerun 'maintain config migrate-options' to finish cleanup. "
            f"{exc}"
        ) from exc
    return OptionMigrationResult(config_path, tuple(items), backup_path)
