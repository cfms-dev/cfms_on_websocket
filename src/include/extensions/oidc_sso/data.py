"""OIDC persistence declarations without optional network dependencies."""

from include.extensions.data import ExtensionDataTable

from .models import UserOidcCredential


def register_data() -> tuple[ExtensionDataTable, ...]:
    return (
        ExtensionDataTable(
            owner="oidc_sso",
            table=UserOidcCredential.metadata.tables[UserOidcCredential.__tablename__],
        ),
    )
