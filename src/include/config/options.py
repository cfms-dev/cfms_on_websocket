from dataclasses import dataclass, field
from typing import Annotated, Any

import orjson
from pydantic import ConfigDict, Field, TypeAdapter, ValidationError, validate_call
from pydantic.dataclasses import dataclass as validated_dataclass
lazy from sqlalchemy.orm import Session

from include.config._policy import ConfigValidationError
from include.database.options import (
    OPTION_VALIDATION_CONFIG,
    OptionKey,
    OptionOwner,
    OptionPayload,
    create_option,
    read_option,
    update_option,
)
lazy from include.database.models.operations import AuditEntry


class OptionConflictError(ConfigValidationError):
    pass


@dataclass(frozen=True, slots=True)
class OptionGroupDefinition[T]:
    option_key: str
    schema_version: int
    model: type[T]
    _adapter: TypeAdapter[T] = field(init=False, repr=False, compare=False)

    def __post_init__(self):
        TypeAdapter(OptionKey).validate_python(self.option_key, strict=True)
        TypeAdapter(Annotated[int, Field(gt=0)]).validate_python(
            self.schema_version, strict=True
        )
        object.__setattr__(self, "_adapter", TypeAdapter(self.model))
        self.validate({})

    def validate(self, payload: OptionPayload) -> T:
        try:
            return self._adapter.validate_json(orjson.dumps(payload), strict=True)
        except (ValidationError, orjson.JSONEncodeError) as exc:
            raise ConfigValidationError(
                f"Invalid options for {self.option_key!r}: "
                + (
                    "; ".join(
                        f"{'.'.join(map(str, error['loc']))}: {error['msg']}"
                        for error in exc.errors(
                            include_input=False, include_context=False
                        )
                    )
                    if isinstance(exc, ValidationError)
                    else "invalid JSON value"
                )
            ) from exc

    def serialize(self, value: T) -> OptionPayload:
        payload = self._adapter.dump_python(value, mode="json")
        return TypeAdapter(OptionPayload).validate_python(payload, strict=True)

    def default_payload(self) -> OptionPayload:
        return self.serialize(self.validate({}))


@validated_dataclass(
    frozen=True, slots=True, config=ConfigDict(strict=True, extra="forbid")
)
class ServerOptions:
    name: str = "CFMS WebSocket Server"


CORE_SERVER_OPTIONS = OptionGroupDefinition("server", 1, ServerOptions)
_option_groups: dict[tuple[str, str], OptionGroupDefinition[Any]] = {
    ("core", "server"): CORE_SERVER_OPTIONS
}


def register_option_groups(
    owner: str, definitions: tuple[OptionGroupDefinition[Any], ...]
) -> None:
    TypeAdapter(OptionOwner).validate_python(owner, strict=True)
    staged = {}
    for definition in definitions:
        identity = (owner, definition.option_key)
        if identity in staged or identity in _option_groups:
            raise ConfigValidationError(f"Duplicate option group {identity!r}")
        staged[identity] = definition
    _option_groups.update(staged)


def unregister_option_groups(owner: str) -> None:
    if owner == "core":
        raise ConfigValidationError("Core option definitions cannot be unregistered")
    for identity in tuple(_option_groups):
        if identity[0] == owner:
            del _option_groups[identity]


def iter_option_groups(
    owner: str | None = None,
) -> tuple[tuple[str, OptionGroupDefinition[Any]], ...]:
    return tuple(
        (current_owner, definition)
        for (current_owner, _), definition in _option_groups.items()
        if owner is None or owner == current_owner
    )


def get_option_group(owner: str, option_key: str) -> OptionGroupDefinition[Any]:
    try:
        return _option_groups[owner, option_key]
    except KeyError as exc:
        raise ConfigValidationError(
            f"No option definition for {owner}/{option_key}"
        ) from exc


@dataclass(frozen=True, slots=True)
class ResolvedOption[T]:
    owner: str
    option_key: str
    schema_version: int
    revision: int
    value: T
    payload: OptionPayload
    updated_at: float | None


def read_options[T](
    session: Session, owner: str, definition: OptionGroupDefinition[T]
) -> ResolvedOption[T]:
    stored = read_option(session, owner, definition.option_key)
    if stored is not None and stored.schema_version != definition.schema_version:
        raise ConfigValidationError(
            f"Unsupported option schema for {owner}/{definition.option_key}: "
            f"{stored.schema_version}; expected {definition.schema_version}"
        )
    value = definition.validate({} if stored is None else stored.payload)
    return ResolvedOption(
        owner=owner,
        option_key=definition.option_key,
        schema_version=definition.schema_version,
        revision=0 if stored is None else stored.revision,
        value=value,
        payload=definition.serialize(value),
        updated_at=None if stored is None else stored.updated_at,
    )


@validate_call(config=OPTION_VALIDATION_CONFIG)
def write_options(
    session: Session,
    owner: OptionOwner,
    definition: OptionGroupDefinition[Any],
    payload: OptionPayload,
    *,
    expected_revision: Annotated[int, Field(ge=0)],
    source: str = "extension",
) -> ResolvedOption[Any]:
    normalized = definition.serialize(definition.validate(payload))
    previous = read_options(session, owner, definition)
    if expected_revision == 0:
        applied = create_option(
            session,
            owner,
            definition.option_key,
            schema_version=definition.schema_version,
            payload=normalized,
        )
    else:
        applied = update_option(
            session,
            owner,
            definition.option_key,
            expected_revision=expected_revision,
            schema_version=definition.schema_version,
            payload=normalized,
        )
    if not applied:
        raise OptionConflictError(
            f"Option revision conflict for {owner}/{definition.option_key}"
        )
    session.add(
        AuditEntry(
            action="update_options",
            result=0,
            username=None,
            remote_address=None,
            target=owner,
            data={
                "source": source,
                "owner": owner,
                "option_key": definition.option_key,
                "previous_revision": expected_revision,
                "revision": expected_revision + 1,
                "changed_fields": sorted(
                    key
                    for key in previous.payload.keys() | normalized.keys()
                    if previous.payload.get(key) != normalized.get(key)
                ),
            },
        )
    )
    return read_options(session, owner, definition)


def ensure_option_defaults[T](
    session: Session, owner: str, definition: OptionGroupDefinition[T]
) -> ResolvedOption[T]:
    create_option(
        session,
        owner,
        definition.option_key,
        schema_version=definition.schema_version,
        payload=definition.default_payload(),
    )
    return read_options(session, owner, definition)
