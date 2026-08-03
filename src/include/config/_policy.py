import annotationlib
from collections.abc import Mapping
from dataclasses import MISSING, dataclass, fields
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
    value: float,
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


@dataclass(frozen=True)
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
