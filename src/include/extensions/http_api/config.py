__all__ = ["HttpApiPolicy"]

from collections.abc import Mapping
from typing import Annotated, Any, Self
from urllib.parse import urlsplit

from pydantic import ConfigDict, Field, ValidationError, model_validator
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


@pydantic_dataclass(frozen=True, slots=True, config=_POLICY_CONFIG)
class HttpApiPolicy:
    host: str = "localhost"
    port: _Port = 5105
    ssl_certfile: str | None = None
    ssl_keyfile: str | None = None
    max_concurrency: _PositiveInt = 64
    max_request_body_bytes: _PositiveInt = 1_048_576
    startup_timeout_seconds: _PositiveSeconds = 10.0
    shutdown_timeout_seconds: _PositiveSeconds = 10.0
    cors_allowed_origins: _Origins = ()
    docs_enabled: bool = False

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
        if len(self.cors_allowed_origins) != len(set(self.cors_allowed_origins)):
            raise ValueError("cors_allowed_origins must not contain duplicates")
        for origin in self.cors_allowed_origins:
            parsed = urlsplit(origin)
            if (
                parsed.scheme not in {"http", "https"}
                or not parsed.netloc
                or parsed.path not in {"", "/"}
                or parsed.query
                or parsed.fragment
            ):
                raise ValueError(
                    f"cors_allowed_origins contains invalid origin {origin!r}"
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
