from collections.abc import Mapping
from dataclasses import dataclass
from typing import Annotated, Any, ClassVar, Protocol, Self

from pydantic import AfterValidator, BeforeValidator, ConfigDict, ValidationError
from pydantic.dataclasses import dataclass as pydantic_dataclass

from include.types import PositiveInt, TrimmedNonEmptyString


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


_POLICY_CONFIG = ConfigDict(
    strict=True,
    validate_default=True,
    extra="ignore",
)


def _mapping_to_items(value: Any) -> Any:
    if isinstance(value, Mapping):
        return tuple(value.items())
    return value


def _sort_mapping_items(
    value: tuple[tuple[str, int], ...],
) -> tuple[tuple[str, int], ...]:
    return tuple(sorted(value))


_MappingItems = Annotated[
    tuple[tuple[TrimmedNonEmptyString, PositiveInt], ...],
    BeforeValidator(_mapping_to_items),
    AfterValidator(_sort_mapping_items),
]


def _format_validation_error(path: str, exc: ValidationError) -> str:
    messages = []
    for error in exc.errors(include_url=False, include_input=False):
        context = error.get("ctx")
        original_error = context.get("error") if context is not None else None
        if isinstance(original_error, ConfigValidationError):
            messages.append(str(original_error))
            continue

        location = path
        if error["loc"]:
            suffix = ".".join(str(part) for part in error["loc"])
            location = f"{path}.{suffix}" if path else suffix

        messages.append(f"{location}: {error['msg']}")

    return "; ".join(messages)


@pydantic_dataclass(
    frozen=True,
    config=_POLICY_CONFIG,
)
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
        section_path = ".".join(part.name for part in cls._SOURCE.sections)

        try:
            return cls(**section)
        except ValidationError as exc:
            raise ConfigValidationError(
                _format_validation_error(section_path, exc)
            ) from exc

    def __post_init__(self) -> None:
        self._validate_rules()

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
