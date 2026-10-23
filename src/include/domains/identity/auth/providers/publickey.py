import base64
import binascii
import contextlib
import secrets
import time
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
from pydantic import BaseModel
from sqlalchemy.orm import Session

from include.database.models.auth import UserAuthPublicKey
from include.database.models.identity import User
from include.domains.identity.auth.base import (
    AuthFactorCategory,
    AuthVerificationResult,
    BaseAuthMethodProvider,
)
from include.providers.manager import ProviderManager
lazy from include.types import NonEmptyString


class PublicKeyCredentialSchema(BaseModel):
    username: NonEmptyString
    fingerprint: NonEmptyString
    nonce: NonEmptyString
    signature: NonEmptyString


class PublicKeyAuthProvider(BaseAuthMethodProvider):
    method_id = "publickey"
    category = AuthFactorCategory.PRIMARY
    throttle_factor = "publickey"
    credential_schema = PublicKeyCredentialSchema

    def is_configured(self, session: Session, user: User) -> bool:
        return bool(user.auth_public_keys)

    def create_challenge(self, session: Session, user: User) -> dict[str, Any] | None:
        nonce = secrets.token_urlsafe(32)
        cache = ProviderManager().caching
        cache.set(f"auth:challenge:{user.id}:{nonce}", 1, ttl=60)
        return {"nonce": nonce, "expires_in": 60}

    def verify(
        self,
        session: Session,
        user: User,
        payload: dict[str, Any],
        context: dict[str, Any],
    ) -> AuthVerificationResult:
        nonce = payload.get("nonce")
        fingerprint_str = payload.get("fingerprint")
        signature_b64 = payload.get("signature")

        if not nonce or not fingerprint_str or not signature_b64:
            return AuthVerificationResult(
                success=False,
                error_code=400,
                error_message="Missing required public key credential fields",
            )

        cache = ProviderManager().caching
        cache_key = f"auth:challenge:{user.id}:{nonce}"
        if not cache.get(cache_key):
            return AuthVerificationResult(
                success=False,
                error_code=401,
                error_message="Invalid or expired challenge nonce",
            )
        cache.delete(cache_key)

        fp_bytes: bytes | None = None
        try:
            fp_bytes = bytes.fromhex(fingerprint_str)
        except ValueError:
            with contextlib.suppress(binascii.Error, ValueError):
                fp_bytes = base64.b64decode(fingerprint_str)

        if not fp_bytes:
            return AuthVerificationResult(
                success=False,
                error_code=400,
                error_message="Invalid fingerprint format",
            )

        key_entry = (
            session.query(UserAuthPublicKey)
            .filter(
                UserAuthPublicKey.user_id == user.id,
                UserAuthPublicKey.fingerprint == fp_bytes,
            )
            .one_or_none()
        )
        if not key_entry:
            return AuthVerificationResult(
                success=False, error_code=401, error_message="Public key not found"
            )

        try:
            sig_bytes = base64.b64decode(signature_b64)
        except binascii.Error, ValueError:
            return AuthVerificationResult(
                success=False,
                error_code=400,
                error_message="Invalid signature encoding",
            )

        nonce_bytes = nonce.encode("utf-8")
        try:
            pubkey = load_der_public_key(key_entry.public_key_der)
            if isinstance(pubkey, ed25519.Ed25519PublicKey):
                pubkey.verify(sig_bytes, nonce_bytes)
            elif isinstance(pubkey, rsa.RSAPublicKey):
                try:
                    pubkey.verify(
                        sig_bytes,
                        nonce_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )
                except InvalidSignature:
                    pubkey.verify(
                        sig_bytes, nonce_bytes, padding.PKCS1v15(), hashes.SHA256()
                    )
            elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                pubkey.verify(sig_bytes, nonce_bytes, ec.ECDSA(hashes.SHA256()))
            else:
                return AuthVerificationResult(
                    success=False,
                    error_code=500,
                    error_message="Unsupported public key type",
                )
        except InvalidSignature:
            return AuthVerificationResult(
                success=False, error_code=401, error_message="Invalid signature"
            )
        except (ValueError, TypeError) as exc:
            return AuthVerificationResult(
                success=False,
                error_code=401,
                error_message=f"Signature verification failed: {exc}",
            )

        key_entry.last_used_time = time.time()
        session.add(key_entry)
        return AuthVerificationResult(success=True)
