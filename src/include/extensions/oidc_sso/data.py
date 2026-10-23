"""OIDC persistence and archive validation without optional network dependencies."""

import hashlib
from collections.abc import Mapping
from typing import Any

import orjson

from include.extensions.data import DataRow, ExtensionDataTable

from .models import UserOidcCredential


def validate_binding(row: Mapping[str, Any]) -> None:
    issuer, subject = row.get("issuer"), row.get("subject")
    if (
        not isinstance(issuer, str)
        or not issuer
        or not isinstance(subject, str)
        or not subject
        or len(subject) > 255
    ):
        raise ValueError("Invalid OIDC identity in backup")
    digest = row.get("identity_digest")
    if (
        not isinstance(digest, bytes)
        or len(digest) != 32
        or digest != hashlib.sha256(orjson.dumps([issuer, subject])).digest()
    ):
        raise ValueError("OIDC identity digest does not match the binding")


def encode_binding(row: DataRow) -> DataRow:
    return {**row, "identity_digest": bytes(row["identity_digest"]).hex()}


def decode_binding(row: DataRow) -> DataRow:
    try:
        return {**row, "identity_digest": bytes.fromhex(row["identity_digest"])}
    except (KeyError, TypeError, ValueError) as exc:
        raise ValueError("Invalid OIDC identity digest in backup") from exc


def register_data() -> tuple[ExtensionDataTable, ...]:
    return (
        ExtensionDataTable(
            owner="oidc_sso",
            table=UserOidcCredential.__table__,
            backup_component="accounts",
            encode_row=encode_binding,
            decode_row=decode_binding,
            validate_row=validate_binding,
        ),
    )
