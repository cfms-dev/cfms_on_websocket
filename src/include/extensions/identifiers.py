__all__ = ["ExtensionIdentifier", "validate_extension_identifier"]

from typing import Annotated

from pydantic import AfterValidator, StringConstraints, TypeAdapter


def _reject_identifiers(value: str) -> str:
    """A validator that rejects the reserved extension identifiers.

    This function is experimental and may be removed in any future version.

    TODO: Consider the necessity of this function's existence.
    """
    if value in ("core",):
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
    AfterValidator(_reject_identifiers),
]

_IDENTIFIER_ADAPTER = TypeAdapter(ExtensionIdentifier)


def validate_extension_identifier(value: object) -> str:
    return _IDENTIFIER_ADAPTER.validate_python(value)
