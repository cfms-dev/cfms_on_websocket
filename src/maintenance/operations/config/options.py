import json
from collections.abc import Mapping
from contextlib import ExitStack, contextmanager, nullcontext
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, Any
lazy from collections.abc import Generator

import tomlkit
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    JsonValue,
    TypeAdapter,
    ValidationError,
)
from sqlalchemy import select
from sqlalchemy.exc import SQLAlchemyError
from tomlkit.exceptions import TOMLKitError

from include.config.legacy_options import legacy_option_candidates
from include.config.paths import EXTENSION_ROOT
from include.config.validation import ConfigValidationError
from include.runtime_lock import RuntimeLockError, server_runtime_lock
from maintenance.operations.config.legacy import (
    LEGACY_PATHS,
    apply_legacy_migrations,
    has_path,
)
from maintenance.operations.config.sync import read_config_text, write_config_atomically
from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.runtime import enter_server_root, load_database_models
lazy from include.config.options import (
    CORE_OPTIONS,
    ResolvedOption,
    get_option_definition,
    read_options,
    validate_options,
    write_options,
)
lazy from include.config.options import (
    read_option as read_resolved_option,
)
lazy from include.database.models.operations import OptionEntry
lazy from include.database.options import (
    OptionKey,
    OptionNamespace,
    StoredOption,
    read_option,
)
lazy from include.database.session import Session
lazy from include.extensions.manager import (
    ExtensionLoadError,
    discover_extensions,
    maintenance_extension_context,
)


@contextmanager
def _options_runtime(namespace: str) -> Generator[None]:
    load_database_models()
    try:
        if namespace in CORE_OPTIONS:
            owner = "core"
        else:
            owners = [
                identifier
                for identifier, extension in discover_extensions(EXTENSION_ROOT).items()
                if namespace in extension.manifest.option_namespaces
            ]
            if len(owners) != 1:
                raise ConfigValidationError(
                    f"Cannot resolve option declarations for {namespace!r}: {owners}"
                )
            owner = owners[0]
        with nullcontext() if owner == "core" else maintenance_extension_context(owner):
            yield
    except (
        ConfigValidationError,
        ValidationError,
        ExtensionLoadError,
        SQLAlchemyError,
        ValueError,
    ) as exc:
        raise MaintenanceOperationError(
            f"Unable to maintain options for {namespace}: {exc}"
        ) from exc


def list_options(
    namespace: str | None = None,
) -> tuple[ResolvedOption[Any] | StoredOption, ...]:
    load_database_models()
    try:
        with Session() as session:
            statement = select(
                OptionEntry.namespace,
                OptionEntry.owner,
                OptionEntry.option_key,
                OptionEntry.schema_version,
                OptionEntry.revision,
                OptionEntry.option_value,
                OptionEntry.value_type,
                OptionEntry.updated_at,
            ).order_by(OptionEntry.namespace, OptionEntry.option_key)
            if namespace is not None:
                TypeAdapter(OptionNamespace).validate_python(namespace, strict=True)
                statement = statement.where(OptionEntry.namespace == namespace)
            options = [
                StoredOption(**row) for row in session.execute(statement).mappings()
            ]
            stored_keys = {(option.namespace, option.option_key) for option in options}
            options.extend(
                read_resolved_option(session, current_namespace, definition)
                for current_namespace, definitions in CORE_OPTIONS.items()
                if namespace is None or namespace == current_namespace
                for definition in definitions
                if (current_namespace, definition.option_key) not in stored_keys
            )
            return tuple(
                sorted(
                    options, key=lambda option: (option.namespace, option.option_key)
                )
            )
    except (ConfigValidationError, ValidationError, SQLAlchemyError, ValueError) as exc:
        raise MaintenanceOperationError(f"Unable to list options: {exc}") from exc


def get_options(namespace: str, option_key: str) -> ResolvedOption[Any] | StoredOption:
    load_database_models()
    try:
        with Session() as session:
            stored = read_option(session, namespace, option_key)
            if stored is not None:
                return stored
            if namespace in CORE_OPTIONS:
                definition = get_option_definition(namespace, option_key)
                return read_resolved_option(session, namespace, definition)
            raise MaintenanceOperationError(
                f"No stored option {namespace}/{option_key}"
            )
    except (ConfigValidationError, ValidationError, SQLAlchemyError, ValueError) as exc:
        raise MaintenanceOperationError(f"Unable to read options: {exc}") from exc


def set_options(
    namespace: str,
    option_key: str,
    payload_file: Path,
    *,
    expected_revision: int,
) -> ResolvedOption[Any]:
    try:
        value = json.loads(read_config_text(payload_file.resolve()))
    except (OSError, json.JSONDecodeError) as exc:
        raise MaintenanceOperationError(f"Unable to read options JSON: {exc}") from exc
    with _options_runtime(namespace), Session.begin() as session:
        return write_options(
            session,
            namespace,
            {option_key: value},
            expected_revisions={option_key: expected_revision},
            source="maintenance_cli",
        )[option_key]


class _OptionUpdate(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", allow_inf_nan=False)

    value: JsonValue
    expected_revision: Annotated[int, Field(ge=0)]


def set_many_options(
    namespace: str, payload_file: Path
) -> dict[str, ResolvedOption[Any]]:
    payload_path = payload_file.resolve()
    enter_server_root()
    try:
        updates = TypeAdapter(dict[OptionKey, _OptionUpdate]).validate_json(
            read_config_text(payload_path), strict=True
        )
    except OSError as exc:
        raise MaintenanceOperationError(f"Unable to read options JSON: {exc}") from exc
    except ValidationError as exc:
        details = "; ".join(
            f"{'.'.join(map(str, error['loc']))}: {error['msg']}"
            for error in exc.errors(include_input=False, include_context=False)
        )
        raise MaintenanceOperationError(
            f"Invalid options update JSON: {details}"
        ) from None
    if not updates:
        raise MaintenanceOperationError(
            "Options update JSON must contain at least one setting"
        )
    with _options_runtime(namespace), Session.begin() as session:
        return write_options(
            session,
            namespace,
            {key: update.value for key, update in updates.items()},
            expected_revisions={
                key: update.expected_revision for key, update in updates.items()
            },
            source="maintenance_cli",
        )


def reset_options(
    namespace: str, option_key: str, *, expected_revision: int
) -> ResolvedOption[Any]:
    with _options_runtime(namespace), Session.begin() as session:
        definition = get_option_definition(namespace, option_key)
        return write_options(
            session,
            namespace,
            {option_key: definition.default},
            expected_revisions={option_key: expected_revision},
            source="maintenance_cli",
        )[option_key]


@dataclass(frozen=True, slots=True)
class OptionMigrationItem:
    legacy_path: str
    namespace: str
    option_key: str
    action: str
    revision: int


@dataclass(frozen=True, slots=True)
class OptionMigrationResult:
    config_path: Path
    items: tuple[OptionMigrationItem, ...]
    backup_path: Path | None = None
    warnings: tuple[str, ...] = ()

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

    original = deepcopy(document)
    for namespace, sources, path in (
        ("security.password", ("security.passwd_must_contain",), ("security",)),
        (
            "document.upload.creation_risk_control",
            (
                "document.upload.creation_rate_per_user",
                "document.upload.creation_rate_per_ip",
                "document.upload.creation_rate_window_seconds",
            ),
            ("document", "upload", "creation_risk_control"),
        ),
    ):
        if any(has_path(original, source) for source in sources):
            section = document
            for part in path:
                section = section.setdefault(part, tomlkit.table())
            for definition in CORE_OPTIONS[namespace]:
                section.setdefault(definition.option_key, deepcopy(definition.default))
    if has_path(original, "sso.oidc"):
        extensions = document.setdefault("extensions", tomlkit.table())
        extensions.setdefault("oidc_sso", tomlkit.table())
        extensions.setdefault("enabled", [])
    if has_path(original, "database.db_name"):
        document["database"].setdefault("name", "")
    _migrations, _, warnings = apply_legacy_migrations(original, document)
    for path in LEGACY_PATHS:
        if not has_path(document, path):
            continue
        parts = path.split(".")
        parents = [document]
        for part in parts[:-1]:
            parents.append(parents[-1][part])
        del parents[-1][parts[-1]]
        for index in range(len(parts) - 2, -1, -1):
            if parents[index][parts[index]]:
                break
            del parents[index][parts[index]]

    try:
        candidates = tuple(legacy_option_candidates(document.unwrap()))
    except ConfigValidationError as exc:
        raise MaintenanceOperationError(str(exc)) from exc
    obsolete = "require_passwd_enforcement_changes" in document.get("security", {})
    if not candidates and not obsolete:
        return OptionMigrationResult(config_path, ())

    load_database_models()
    items = []
    try:
        with ExitStack() as resources:
            loaded_owners = set()
            for _, _, owner, _ in candidates:
                if owner != "core" and owner not in loaded_owners:
                    resources.enter_context(maintenance_extension_context(owner))
                    loaded_owners.add(owner)
            session = resources.enter_context(Session())
            pending = []
            for legacy_path, namespace, owner, legacy_values in candidates:
                if not discard_legacy and not isinstance(legacy_values, Mapping):
                    raise MaintenanceOperationError(f"{legacy_path} must be a table")
                existing = read_options(session, namespace)
                values = validate_options(
                    namespace,
                    {key: option.value for key, option in existing.items()}
                    if discard_legacy
                    else legacy_values,
                )
                missing = {}
                for key, value in values.items():
                    previous = existing[key]
                    if discard_legacy:
                        action = (
                            "Discard legacy" if previous.revision else "Create defaults"
                        )
                    else:
                        if previous.revision and previous.value != value:
                            raise MaintenanceOperationError(
                                f"Database option {namespace}/{key} differs from {legacy_path}. "
                                "Use --discard-legacy to keep the database value."
                            )
                        action = "Already imported" if previous.revision else "Import"
                    items.append(
                        OptionMigrationItem(
                            f"{legacy_path}.{key}",
                            namespace,
                            key,
                            action,
                            previous.revision,
                        )
                    )
                    if not previous.revision:
                        missing[key] = value
                if missing:
                    pending.append((namespace, missing))

            if obsolete:
                items.append(
                    OptionMigrationItem(
                        "security.require_passwd_enforcement_changes",
                        "security",
                        "require_passwd_enforcement_changes",
                        "Remove obsolete (ignored)",
                        0,
                    )
                )
            if not write:
                return OptionMigrationResult(
                    config_path, tuple(items), warnings=tuple(warnings)
                )
            if read_config_text(config_path) != current_source:
                raise MaintenanceOperationError(
                    "config.toml changed while preparing migration; retry"
                )
            for namespace, values in pending:
                write_options(
                    session,
                    namespace,
                    values,
                    expected_revisions={key: 0 for key in values},
                    source="maintenance_cli_migration",
                )
            session.commit()
    except (
        ConfigValidationError,
        ValidationError,
        ExtensionLoadError,
        SQLAlchemyError,
        ValueError,
    ) as exc:
        raise MaintenanceOperationError(f"Unable to migrate options: {exc}") from exc

    for path, _, _, values in candidates:
        parts = path.split(".")
        parent = document
        for part in parts[:-1]:
            parent = parent[part]
        section = parent[parts[-1]]
        if isinstance(values, Mapping):
            for key in values:
                del section[key]
        if not isinstance(values, Mapping) or not section:
            del parent[parts[-1]]
    if obsolete:
        del document["security"]["require_passwd_enforcement_changes"]
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
    return OptionMigrationResult(
        config_path, tuple(items), backup_path, tuple(warnings)
    )
