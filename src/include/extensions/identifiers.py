__all__ = ["ExtensionIdentifier", "validate_extension_identifier"]

from typing import Annotated

from pydantic import AfterValidator, StringConstraints, TypeAdapter


def _reject_core_identifier(value: str) -> str:
    if value == "core":
        raise ValueError(f"Extension identifier {value!r} is reserved")
    return value


ExtensionIdentifier = Annotated[
    str,
    StringConstraints(
        strict=True,
        strip_whitespace=False,
        max_length=255,
        pattern=r"^[a-z][a-z0-9_]*$",
    ),
    AfterValidator(_reject_core_identifier),
]

_IDENTIFIER_ADAPTER = TypeAdapter(ExtensionIdentifier)


def validate_extension_identifier(value: object) -> str:
    return _IDENTIFIER_ADAPTER.validate_python(value)
