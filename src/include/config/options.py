from copy import deepcopy
from dataclasses import dataclass, field, fields
from typing import Annotated, Any, Protocol

from pydantic import Field, TypeAdapter, ValidationError, validate_call
from sqlalchemy import select
lazy from sqlalchemy.orm import Session

from include.config._policy import ConfigValidationError
from include.config.setting_metadata import CORE_SETTING_METADATA, SettingMetadata
from include.config.validation import (
    AuditRetentionPolicy,
    AuthThrottlePolicy,
    DocumentCreationRiskPolicy,
    DocumentDownloadRiskPolicy,
    DocumentUploadPolicy,
    IdentityPermissionRetentionPolicy,
    PasswordPolicy,
    RequestRateControlPolicy,
    SchedulingOptionsPolicy,
)
from include.database.models.operations import AuditEntry, OptionEntry, SystemStateEntry
from include.database.options import (
    OPTION_VALIDATION_CONFIG,
    OptionKey,
    OptionNamespace,
    OptionOwner,
    OptionSchemaVersion,
    OptionValue,
    StoredOption,
    create_option,
    encode_option_value,
    update_option,
)
from include.database.options import (
    read_option as read_stored_option,
)
from include.database.system_states import create_system_state, update_system_state
from include.types import PositiveInt

_KEY_ADAPTER = TypeAdapter(OptionKey)
_NAMESPACE_ADAPTER = TypeAdapter(OptionNamespace)
_SCHEMA_ADAPTER = TypeAdapter(OptionSchemaVersion)
_VALUE_ADAPTER = TypeAdapter(OptionValue, config=OPTION_VALIDATION_CONFIG)
_OPTIONS_REVISION_PREFIX = "options_revision."


class OptionValidator(Protocol):
    def __call__(self, *, values: dict[str, OptionValue]) -> None: ...


class OptionConflictError(ConfigValidationError):
    pass


class OptionValidationError(ConfigValidationError):
    """A submitted option value or complete policy is invalid."""


@dataclass(frozen=True, slots=True)
class OptionDefinition[T]:
    option_key: str
    schema_version: int
    annotation: Any
    default: T = field(repr=False)
    setting: SettingMetadata | None = field(default=None, kw_only=True)
    _adapter: TypeAdapter[T] = field(init=False, repr=False, compare=False)

    def __post_init__(self) -> None:
        _KEY_ADAPTER.validate_python(self.option_key, strict=True)
        _SCHEMA_ADAPTER.validate_python(self.schema_version, strict=True)
        object.__setattr__(self, "_adapter", TypeAdapter(self.annotation))
        object.__setattr__(self, "default", self.validate(self.default))

    def validate(self, value: Any) -> T:
        try:
            normalized = self._adapter.validate_python(value, strict=True)
            _VALUE_ADAPTER.validate_python(normalized, strict=True)
            return normalized
        except ValidationError as exc:
            errors = "; ".join(
                f"{'.'.join(map(str, error['loc']))}: {error['msg']}"
                for error in exc.errors(include_input=False, include_context=False)
            )
            raise OptionValidationError(
                f"Invalid option {self.option_key!r}: {errors}"
            ) from None


SERVER_NAME_OPTION = OptionDefinition(
    "name",
    1,
    str,
    "CFMS WebSocket Server",
    setting=CORE_SETTING_METADATA["server"]["name"],
)
_option_definitions: dict[tuple[str, str], OptionDefinition[Any]] = {}
_option_owners: dict[tuple[str, str], str] = {}
_option_validators: dict[str, OptionValidator] = {}
_validator_owners: dict[str, str] = {}


def register_options(
    namespace: str,
    definitions: tuple[OptionDefinition[Any], ...],
    validator: OptionValidator | None = None,
    *,
    owner: str = "core",
) -> None:
    _NAMESPACE_ADAPTER.validate_python(namespace, strict=True)
    TypeAdapter(OptionOwner).validate_python(owner, strict=True)
    staged = {}
    for definition in definitions:
        identity = (namespace, definition.option_key)
        if identity in staged or identity in _option_definitions:
            raise ConfigValidationError(f"Duplicate option {identity!r}")
        staged[identity] = definition
    if validator is not None and namespace in _option_validators:
        raise ConfigValidationError(f"Duplicate option validator for {namespace!r}")
    defaults = {
        definition.option_key: deepcopy(definition.default)
        for definition in definitions
    }
    if validator is not None:
        try:
            validator(values=defaults)
        except ValidationError as exc:
            raise ConfigValidationError(
                f"Invalid option defaults for {namespace}: "
                + "; ".join(
                    error["msg"]
                    for error in exc.errors(include_input=False, include_context=False)
                )
            ) from None
    _option_definitions.update(staged)
    _option_owners.update(dict.fromkeys(staged, owner))
    if validator is not None:
        _option_validators[namespace] = validator
        _validator_owners[namespace] = owner


def unregister_options(owner: str) -> None:
    if owner == "core":
        raise ConfigValidationError("Core option definitions cannot be unregistered")
    for identity in tuple(_option_definitions):
        if _option_owners[identity] == owner:
            del _option_definitions[identity]
            del _option_owners[identity]
    for namespace in tuple(_option_validators):
        if _validator_owners[namespace] == owner:
            del _option_validators[namespace]
            del _validator_owners[namespace]


def iter_options(
    namespace: str | None = None, *, owner: str | None = None
) -> tuple[tuple[str, OptionDefinition[Any]], ...]:
    return tuple(
        (identity[0], definition)
        for identity, definition in _option_definitions.items()
        if (namespace is None or namespace == identity[0])
        and (owner is None or owner == _option_owners[identity])
    )


def get_option_definition(namespace: str, option_key: str) -> OptionDefinition[Any]:
    try:
        return _option_definitions[namespace, option_key]
    except KeyError as exc:
        raise ConfigValidationError(
            f"No option definition for {namespace}/{option_key}"
        ) from exc


def describe_settings(namespace: str | None = None) -> list[dict[str, Any]]:
    return [
        {
            "namespace": option_namespace,
            "option_key": definition.option_key,
            "owner": _option_owners[option_namespace, definition.option_key],
            "schema_version": definition.schema_version,
            "title": definition.setting.title,
            "description": definition.setting.description,
            "default": deepcopy(definition.default),
            "value_schema": TypeAdapter(definition.annotation).json_schema(
                mode="validation"
            ),
        }
        for option_namespace, definition in sorted(
            iter_options(namespace), key=lambda item: (item[0], item[1].option_key)
        )
        if definition.setting is not None
    ]


def get_setting_definitions(
    namespace: str, keys: list[str] | None = None
) -> tuple[OptionDefinition[Any], ...]:
    definitions = {
        definition.option_key: definition
        for _, definition in iter_options(namespace)
        if definition.setting is not None
    }
    if not definitions or (keys is not None and not definitions.keys() >= set(keys)):
        raise LookupError("Setting not found")
    return tuple(
        definitions[key] for key in sorted(definitions if keys is None else keys)
    )


@dataclass(frozen=True, slots=True)
class ResolvedOption[T]:
    namespace: str
    owner: str
    option_key: str
    schema_version: int
    revision: int
    value: T = field(repr=False)
    updated_at: float | None


def _resolve_option[T](
    namespace: str, definition: OptionDefinition[T], stored: StoredOption | None
) -> ResolvedOption[T]:
    if stored is not None and stored.schema_version != definition.schema_version:
        raise ConfigValidationError(
            f"Unsupported option schema for {namespace}/{definition.option_key}: "
            f"{stored.schema_version}; expected {definition.schema_version}"
        )
    try:
        value = (
            deepcopy(definition.default)
            if stored is None
            else definition.validate(stored.value)
        )
    except OptionValidationError as exc:
        raise ConfigValidationError(
            f"Invalid stored option {namespace}/{definition.option_key}"
        ) from exc
    return ResolvedOption(
        namespace=namespace,
        owner=stored.owner
        if stored is not None
        else _option_owners.get((namespace, definition.option_key), "core"),
        option_key=definition.option_key,
        schema_version=definition.schema_version,
        revision=0 if stored is None else stored.revision,
        value=value,
        updated_at=None if stored is None else stored.updated_at,
    )


def read_option[T](
    session: Session, namespace: str, definition: OptionDefinition[T]
) -> ResolvedOption[T]:
    return _resolve_option(
        namespace,
        definition,
        read_stored_option(session, namespace, definition.option_key),
    )


@validate_call(config=OPTION_VALIDATION_CONFIG)
def read_options(
    session: Session,
    namespace: OptionNamespace,
    definitions: tuple[OptionDefinition[Any], ...] | None = None,
) -> dict[str, ResolvedOption[Any]]:
    if definitions is None:
        definitions = tuple(definition for _, definition in iter_options(namespace))
    if not definitions:
        return {}
    keys = tuple(definition.option_key for definition in definitions)
    rows = session.execute(
        select(
            OptionEntry.namespace,
            OptionEntry.owner,
            OptionEntry.option_key,
            OptionEntry.schema_version,
            OptionEntry.revision,
            OptionEntry.value_type,
            OptionEntry.option_value,
            OptionEntry.updated_at,
        ).where(OptionEntry.namespace == namespace, OptionEntry.option_key.in_(keys))
    ).mappings()
    stored = {row["option_key"]: StoredOption(**row) for row in rows}
    return {
        definition.option_key: _resolve_option(
            namespace, definition, stored.get(definition.option_key)
        )
        for definition in definitions
    }


def validate_options(
    namespace: str, values: dict[str, OptionValue]
) -> dict[str, OptionValue]:
    definitions = {
        definition.option_key: definition for _, definition in iter_options(namespace)
    }
    for option_key in values:
        if option_key not in definitions:
            raise ConfigValidationError(
                f"No option definition for {namespace}/{option_key}"
            )
    normalized = {
        key: definition.validate(
            values[key] if key in values else deepcopy(definition.default)
        )
        for key, definition in definitions.items()
    }
    try:
        if namespace in CORE_POLICY_TYPES:
            CORE_POLICY_TYPES[namespace](**normalized)
        validator = _option_validators.get(namespace)
        if validator is not None:
            validator(values=normalized)
    except ValidationError as exc:
        raise OptionValidationError(
            f"Invalid options for {namespace}: "
            + "; ".join(
                error["msg"]
                for error in exc.errors(include_input=False, include_context=False)
            )
        ) from None
    except ConfigValidationError as exc:
        raise OptionValidationError(str(exc)) from exc
    return normalized


def _read_options_revision(session: Session, namespace: str) -> int:
    row = session.execute(
        select(
            SystemStateEntry.schema_version,
            SystemStateEntry.revision,
            SystemStateEntry.payload,
        ).where(
            SystemStateEntry.owner == "core",
            SystemStateEntry.state_key == _OPTIONS_REVISION_PREFIX + namespace,
        )
    ).one_or_none()
    if row is None:
        return 0
    if row.schema_version != 1 or row.payload != {}:
        raise ConfigValidationError(
            f"Unsupported options revision schema for {namespace}"
        )
    return row.revision


def _claim_options_revision(session: Session, namespace: str, revision: int) -> int:
    if revision == 0:
        applied = create_system_state(
            session,
            "core",
            _OPTIONS_REVISION_PREFIX + namespace,
            schema_version=1,
            payload={},
        )
    else:
        applied = update_system_state(
            session,
            "core",
            _OPTIONS_REVISION_PREFIX + namespace,
            expected_revision=revision,
            schema_version=1,
            payload={},
        )
    if not applied:
        raise OptionConflictError(f"Concurrent option update for {namespace}")
    return revision + 1


@validate_call(config=OPTION_VALIDATION_CONFIG)
def acquire_options_revision(session: Session, namespace: OptionNamespace) -> int:
    return _claim_options_revision(
        session, namespace, _read_options_revision(session, namespace)
    )


@validate_call(config=OPTION_VALIDATION_CONFIG)
def write_options(
    session: Session,
    namespace: OptionNamespace,
    values: dict[OptionKey, OptionValue],
    *,
    expected_revisions: dict[OptionKey, Annotated[int, Field(ge=0)]],
    source: str = "extension",
) -> dict[str, ResolvedOption[Any]]:
    if values.keys() != expected_revisions.keys():
        raise ConfigValidationError(
            "Expected revisions must match the written option keys"
        )
    if not values:
        return {}
    guard_revision = _read_options_revision(session, namespace)
    for option_key in values:
        get_option_definition(namespace, option_key)
    previous = read_options(session, namespace)
    for key, expected_revision in expected_revisions.items():
        if previous[key].revision != expected_revision:
            raise OptionConflictError(f"Option revision conflict for {namespace}/{key}")
    normalized = validate_options(
        namespace, {key: option.value for key, option in previous.items()} | values
    )
    _claim_options_revision(session, namespace, guard_revision)
    for key in sorted(values):
        definition = get_option_definition(namespace, key)
        expected_revision = expected_revisions[key]
        if expected_revision == 0:
            applied = create_option(
                session,
                namespace,
                key,
                schema_version=definition.schema_version,
                value=normalized[key],
                owner=_option_owners[namespace, key],
            )
        else:
            applied = update_option(
                session,
                namespace,
                key,
                expected_revision=expected_revision,
                schema_version=definition.schema_version,
                value=normalized[key],
            )
        if not applied:
            raise OptionConflictError(f"Option revision conflict for {namespace}/{key}")
    session.add(
        AuditEntry(
            action="update_options",
            result=0,
            user_id=None,
            remote_address=None,
            target=namespace,
            data={
                "source": source,
                "namespace": namespace,
                "previous_revisions": dict(expected_revisions),
                "revisions": {
                    key: revision + 1 for key, revision in expected_revisions.items()
                },
                "changed_keys": sorted(
                    key
                    for key in values
                    if encode_option_value(previous[key].value)
                    != encode_option_value(normalized[key])
                ),
            },
        )
    )
    return read_options(
        session,
        namespace,
        tuple(get_option_definition(namespace, key) for key in values),
    )


@validate_call(config=OPTION_VALIDATION_CONFIG)
def ensure_option_defaults(
    session: Session,
    namespace: OptionNamespace,
    definitions: tuple[OptionDefinition[Any], ...] | None = None,
) -> dict[str, ResolvedOption[Any]]:
    if definitions is None:
        definitions = tuple(definition for _, definition in iter_options(namespace))
    if not definitions:
        return {}
    guard_revision = _read_options_revision(session, namespace)
    previous = read_options(session, namespace)
    normalized = validate_options(
        namespace, {key: option.value for key, option in previous.items()}
    )
    missing = tuple(
        definition
        for definition in definitions
        if previous[definition.option_key].revision == 0
    )
    if not missing:
        return {
            definition.option_key: previous[definition.option_key]
            for definition in definitions
        }
    _claim_options_revision(session, namespace, guard_revision)
    for definition in missing:
        applied = create_option(
            session,
            namespace,
            definition.option_key,
            schema_version=definition.schema_version,
            value=normalized[definition.option_key],
            owner=_option_owners[namespace, definition.option_key],
        )
        if not applied:
            raise OptionConflictError(
                f"Option revision conflict for {namespace}/{definition.option_key}"
            )
    return read_options(session, namespace, definitions)


CORE_POLICY_TYPES = {
    policy._OPTION_NAMESPACE: policy
    for policy in (
        PasswordPolicy,
        AuthThrottlePolicy,
        AuditRetentionPolicy,
        IdentityPermissionRetentionPolicy,
        RequestRateControlPolicy,
        DocumentUploadPolicy,
        DocumentCreationRiskPolicy,
        DocumentDownloadRiskPolicy,
        SchedulingOptionsPolicy,
    )
}
CORE_OPTIONS = {
    "server": (SERVER_NAME_OPTION,),
    "access": (
        OptionDefinition(
            "enable_access_recursive_check",
            1,
            bool,
            True,
            setting=CORE_SETTING_METADATA["access"]["enable_access_recursive_check"],
        ),
    ),
}
for _namespace, _policy in CORE_POLICY_TYPES.items():
    _defaults = _policy()
    CORE_OPTIONS[_namespace] = tuple(
        OptionDefinition(
            item.name,
            1,
            dict[str, PositiveInt] if item.name == "action_costs" else item.type,
            dict(getattr(_defaults, item.name))
            if item.name == "action_costs"
            else getattr(_defaults, item.name),
            setting=CORE_SETTING_METADATA[_namespace][item.name],
        )
        for item in fields(_policy)
    )
for _namespace, _definitions in CORE_OPTIONS.items():
    register_options(_namespace, _definitions)


def ensure_core_option_defaults(session: Session) -> None:
    for namespace in CORE_OPTIONS:
        ensure_option_defaults(session, namespace)
