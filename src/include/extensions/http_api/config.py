__all__ = ["HttpApiPolicy"]

from collections.abc import Mapping
from typing import Annotated, Any, Self
from urllib.parse import urlsplit

from pydantic import (
    AnyHttpUrl,
    ConfigDict,
    Field,
    TypeAdapter,
    ValidationError,
    field_validator,
    model_validator,
)
from pydantic.dataclasses import dataclass as pydantic_dataclass

from include.config.validation import ConfigValidationError

_POLICY_CONFIG = ConfigDict(
    strict=True,
    validate_default=True,
    extra="forbid",
)
_PositiveInt = Annotated[int, Field(gt=0)]
_Port = Annotated[int, Field(ge=1, le=65535)]
_PositiveSeconds = Annotated[float, Field(gt=0)]
_Origins = Annotated[tuple[str, ...], Field(strict=False)]
_HTTP_ORIGIN_ADAPTER = TypeAdapter(AnyHttpUrl)
_DEFAULT_PORTS = {"http": 80, "https": 443}


@pydantic_dataclass(frozen=True, slots=True, config=_POLICY_CONFIG)
class HttpApiPolicy:
    host: str = "localhost"
    port: _Port = 5105
    ssl_certfile: str | None = None
    ssl_keyfile: str | None = None
    max_concurrency: _PositiveInt = 64
    max_request_body_bytes: _PositiveInt = 1_048_576
    request_header_timeout_seconds: _PositiveSeconds = 10.0
    request_body_timeout_seconds: _PositiveSeconds = 30.0
    startup_timeout_seconds: _PositiveSeconds = 10.0
    shutdown_timeout_seconds: _PositiveSeconds = 10.0
    cors_allowed_origins: _Origins = ()
    docs_enabled: bool = False

    @field_validator("cors_allowed_origins")
    @classmethod
    def normalize_cors_allowed_origins(
        cls, origins: tuple[str, ...]
    ) -> tuple[str, ...]:
        normalized_origins = []
        for origin in origins:
            if any(character.isspace() for character in origin) or any(
                delimiter in origin for delimiter in ("?", "#", "\\")
            ):
                raise ValueError(
                    f"cors_allowed_origins contains invalid origin {origin!r}"
                )
            try:
                parsed = urlsplit(origin)
                parsed_port = parsed.port
                url = _HTTP_ORIGIN_ADAPTER.validate_python(origin, strict=True)
            except ValidationError, ValueError:
                raise ValueError(
                    f"cors_allowed_origins contains invalid origin {origin!r}"
                ) from None

            if (
                parsed.path
                or parsed.username is not None
                or parsed.password is not None
                or (parsed_port is None and parsed.netloc.endswith(":"))
            ):
                raise ValueError(
                    f"cors_allowed_origins contains invalid origin {origin!r}"
                )

            normalized_origin = f"{url.scheme}://{url.host}"
            if url.port != _DEFAULT_PORTS[url.scheme]:
                normalized_origin = f"{normalized_origin}:{url.port}"
            normalized_origins.append(normalized_origin)

        if len(normalized_origins) != len(set(normalized_origins)):
            raise ValueError("cors_allowed_origins must not contain duplicates")
        return tuple(normalized_origins)

    @model_validator(mode="after")
    def validate_policy(self) -> Self:
        if not self.host or self.host != self.host.strip():
            raise ValueError("host must not be blank or have surrounding whitespace")
        if (self.ssl_certfile is None) != (self.ssl_keyfile is None):
            raise ValueError("ssl_certfile and ssl_keyfile must be configured together")
        for name, value in (
            ("ssl_certfile", self.ssl_certfile),
            ("ssl_keyfile", self.ssl_keyfile),
        ):
            if value is not None and (not value or value != value.strip()):
                raise ValueError(
                    f"{name} must not be blank or have surrounding whitespace"
                )
        return self

    @classmethod
    def from_config(cls, config: Any) -> HttpApiPolicy:
        try:
            extensions = config["extensions"]
        except KeyError as exc:
            raise ConfigValidationError(
                "Missing configuration section 'extensions'"
            ) from exc
        if not isinstance(extensions, Mapping):
            raise ConfigValidationError(
                "Configuration section 'extensions' must be a table"
            )
        section = extensions.get("http_api", {})
        if not isinstance(section, Mapping):
            raise ConfigValidationError("extensions.http_api must be a table")
        try:
            return cls(**section)
        except ValidationError as exc:
            raise ConfigValidationError(
                f"Invalid extensions.http_api configuration: {exc}"
            ) from exc
