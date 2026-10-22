from include.domains.identity.auth.base import (
    AuthFactorCategory,
    AuthVerificationResult,
    BaseAuthMethodProvider,
)
from include.domains.identity.auth.providers.password import (
    PasswordAuthProvider,
    PasswordCredentialSchema,
)
from include.domains.identity.auth.providers.publickey import (
    PublicKeyAuthProvider,
    PublicKeyCredentialSchema,
)
from include.domains.identity.auth.providers.totp import (
    TOTPAuthProvider,
    TOTPCredentialSchema,
)
from include.domains.identity.auth.registry import AuthRegistry, auth_registry

# Register core built-in authentication method providers
auth_registry.register(PasswordAuthProvider())
auth_registry.register(PublicKeyAuthProvider())
auth_registry.register(TOTPAuthProvider())

__all__ = [
    "AuthFactorCategory",
    "AuthRegistry",
    "AuthVerificationResult",
    "BaseAuthMethodProvider",
    "PasswordAuthProvider",
    "PasswordCredentialSchema",
    "PublicKeyAuthProvider",
    "PublicKeyCredentialSchema",
    "TOTPAuthProvider",
    "TOTPCredentialSchema",
    "auth_registry",
]
