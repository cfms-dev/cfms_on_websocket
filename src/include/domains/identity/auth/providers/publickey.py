import base64
import binascii
import contextlib
import secrets
import time
import uuid
from dataclasses import dataclass, field
from typing import Any, Literal

import orjson
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa
from cryptography.hazmat.primitives.serialization import load_der_public_key
from pydantic import Field, TypeAdapter
from pydantic.dataclasses import dataclass as pydantic_dataclass
from sqlalchemy import select
from sqlalchemy.orm import Session

from include.database.models.auth import UserAuthPublicKey
from include.database.models.identity import User
from include.database.session import Session as DatabaseSession
from include.domains.identity.auth.base import (
    AuthFactorCategory,
    AuthVerificationResult,
    BaseAuthMethodProvider,
)
from include.domains.identity.auth.flows import (
    AuthenticationAttempt,
    AuthenticationFailure,
)
from include.domains.identity.auth.types import (
    AuthPurpose,
    InvalidAuthenticationAttempt,
    RegisteredCredential,
)
from include.domains.identity.types import RequestUsername
from include.domains.security.guards.login import LoginGuard
from include.transport.multiplexing import FrameType
from include.transport.request_handler import RequestDataModel
lazy from include.transport.connection import ConnectionHandler
lazy from include.types import NonEmptyString

PUBLICKEY_CHALLENGE_SCOPE = "cfms.auth.publickey"


@pydantic_dataclass(frozen=True, slots=True)
class PublicKeyChallenge:
    user_id: uuid.UUID
    attempt_id: str
    stage: Literal["login", "mfa", "escalation"]
    stream_id: int
    interaction_id: str
    fingerprint: str
    scope: str = PUBLICKEY_CHALLENGE_SCOPE
    nonce: str = field(default_factory=lambda: secrets.token_urlsafe(32), repr=False)


public_key_challenge_adapter = TypeAdapter(PublicKeyChallenge)


@dataclass(frozen=True, slots=True)
class Challenge:
    user_id: uuid.UUID
    data: bytes = field(repr=False)
    expires_at: float


class PublicKeyCredentialSchema(RequestDataModel):
    fingerprint: NonEmptyString
    signature: NonEmptyString = Field(repr=False)


class PublicKeySelection(RequestDataModel):
    fingerprint: NonEmptyString


class PublicKeyLoginRequest(PublicKeySelection):
    username: RequestUsername


class PublicKeyAuthProvider(BaseAuthMethodProvider):
    method_id = "publickey"
    category = AuthFactorCategory.PRIMARY
    throttle_factor = "publickey"
    credential_schema = PublicKeyCredentialSchema
    supported_purposes = frozenset(AuthPurpose)

    def authenticate(
        self,
        handler: ConnectionHandler,
        attempt: AuthenticationAttempt,
        payload: dict[str, Any],
    ) -> None:
        if attempt.purpose == AuthPurpose.LOGIN:
            selection = PublicKeyLoginRequest.model_validate(payload)
            attempt.username = selection.username
        else:
            selection = PublicKeySelection.model_validate(payload)
        attempt.check_throttle(self)
        with DatabaseSession() as session:
            user = (
                session.scalar(select(User).where(User.username == attempt.username))
                if attempt.purpose == AuthPurpose.LOGIN
                else session.get(User, attempt.user_id)
            )
            if user is None:
                if attempt.purpose != AuthPurpose.LOGIN:
                    raise InvalidAuthenticationAttempt(
                        "Account changed; restart authentication"
                    )
                assert attempt.username is not None
                LoginGuard.report_failure(
                    attempt.ip, attempt.username, self.throttle_factor
                )
                raise AuthenticationFailure(401, "Invalid credentials")
            attempt.bind(session, user)
            assert attempt.context is not None
            if attempt.purpose != AuthPurpose.LOGIN:
                attempt.check_throttle(self)

        while True:
            with DatabaseSession() as session:
                user = session.get(User, attempt.user_id)
                if user is None:
                    raise InvalidAuthenticationAttempt(
                        "Account changed; restart authentication"
                    )
                permitted = attempt.permitted_credentials(session, user)
                try:
                    try:
                        identity = bytes.fromhex(selection.fingerprint)
                    except ValueError:
                        identity = base64.b64decode(
                            selection.fingerprint, validate=True
                        )
                except binascii.Error, ValueError:
                    raise AuthenticationFailure(
                        400, "Invalid fingerprint format"
                    ) from None
                if not any(
                    c.credential_id in permitted and c.key_identity == identity.hex()
                    for c in self.list_credentials(session, user)
                ):
                    LoginGuard.report_failure(
                        attempt.ip, user.username, self.throttle_factor
                    )
                    raise AuthenticationFailure(401, "Invalid credentials")
                verification_context = {
                    "attempt_id": attempt.context.attempt_id,
                    "stage": attempt.purpose.value,
                    "stream_id": handler.stream.frame_id,
                    "interaction_id": secrets.token_hex(16),
                    "fingerprint": selection.fingerprint,
                }
                challenge = self.create_challenge(
                    session, user, context=verification_context
                )
            interaction_id = verification_context["interaction_id"]
            handler.stream.send(
                orjson.dumps(
                    {
                        "action": "auth_challenge",
                        "data": {
                            "stage": attempt.purpose.value,
                            "method": self.method_id,
                            "interaction_id": interaction_id,
                            **challenge,
                        },
                    }
                ),
                FrameType.PROCESS,
            )
            proof = PublicKeyCredentialSchema.model_validate(
                attempt.receive(handler, interaction_id, self)
            )
            with DatabaseSession() as session:
                user = session.get(User, attempt.user_id)
                if user is None:
                    raise InvalidAuthenticationAttempt(
                        "Account changed; restart authentication"
                    )
                attempt.progress(session, user)
                verified = self.verify(
                    session, user, proof.model_dump(), verification_context
                )
                progress = attempt.accept(session, user, self, verified)
                if progress.satisfied or (
                    progress.purpose is not None and progress.purpose != attempt.purpose
                ):
                    return
                next_steps = [
                    step.model_dump()
                    for step in progress.next_steps
                    if step.method == self.method_id
                ]
                if not next_steps:
                    raise AuthenticationFailure(
                        403, "Public-key authentication cannot satisfy this policy"
                    )
            interaction_id = secrets.token_hex(16)
            handler.stream.send(
                orjson.dumps(
                    {
                        "action": "auth_continue",
                        "data": {
                            "stage": attempt.purpose.value,
                            "method": self.method_id,
                            "interaction_id": interaction_id,
                            "next_steps": next_steps,
                        },
                    }
                ),
                FrameType.PROCESS,
            )
            selection = PublicKeySelection.model_validate(
                attempt.receive(handler, interaction_id, self)
            )

    def list_credentials(
        self, session: Session, user: User
    ) -> list[RegisteredCredential]:
        return [
            RegisteredCredential(
                method=self.method_id,
                credential_id=key.id,
                active=True,
                label=key.label,
                key_identity=key.fingerprint.hex(),
            )
            for key in session.scalars(
                select(UserAuthPublicKey)
                .where(UserAuthPublicKey.user_id == user.id)
                .order_by(UserAuthPublicKey.id)
            )
        ]

    def create_challenge(
        self, session: Session, user: User, *, context: dict[str, Any]
    ) -> dict[str, Any]:
        challenge = public_key_challenge_adapter.dump_json(
            PublicKeyChallenge(
                user_id=user.id,
                attempt_id=context["attempt_id"],
                stage=context["stage"],
                stream_id=context["stream_id"],
                interaction_id=context["interaction_id"],
                fingerprint=context["fingerprint"],
            )
        )
        context["publickey_challenge"] = Challenge(
            user_id=user.id, data=challenge, expires_at=time.monotonic() + 60
        )
        return {
            "challenge": base64.b64encode(challenge).decode("ascii"),
            "expires_in": 60,
        }

    def verify(
        self,
        session: Session,
        user: User,
        payload: dict[str, Any],
        context: dict[str, Any],
    ) -> AuthVerificationResult:
        fingerprint_str = payload.get("fingerprint")
        signature_b64 = payload.get("signature")

        if not fingerprint_str or not signature_b64:
            return AuthVerificationResult(
                success=False,
                error_code=400,
                error_message="Missing required public key credential fields",
            )

        challenge = context.pop("publickey_challenge", None)
        if (
            challenge is None
            or challenge.user_id != user.id
            or time.monotonic() >= challenge.expires_at
            or fingerprint_str != context["fingerprint"]
        ):
            return AuthVerificationResult(
                success=False,
                error_code=401,
                error_message="Invalid or expired public key challenge",
            )

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

        key_entry = session.scalar(
            select(UserAuthPublicKey).where(
                UserAuthPublicKey.user_id == user.id,
                UserAuthPublicKey.fingerprint == fp_bytes,
            )
        )
        if not key_entry:
            return AuthVerificationResult(
                success=False, error_code=401, error_message="Public key not found"
            )

        try:
            sig_bytes = base64.b64decode(signature_b64, validate=True)
        except binascii.Error, ValueError:
            return AuthVerificationResult(
                success=False,
                error_code=400,
                error_message="Invalid signature encoding",
            )

        challenge_bytes = challenge.data
        try:
            pubkey = load_der_public_key(key_entry.public_key_der)
            if isinstance(pubkey, ed25519.Ed25519PublicKey):
                pubkey.verify(sig_bytes, challenge_bytes)
            elif isinstance(pubkey, rsa.RSAPublicKey):
                try:
                    pubkey.verify(
                        sig_bytes,
                        challenge_bytes,
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )
                except InvalidSignature:
                    pubkey.verify(
                        sig_bytes, challenge_bytes, padding.PKCS1v15(), hashes.SHA256()
                    )
            elif isinstance(pubkey, ec.EllipticCurvePublicKey):
                pubkey.verify(sig_bytes, challenge_bytes, ec.ECDSA(hashes.SHA256()))
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
        except ValueError, TypeError:
            return AuthVerificationResult(
                success=False,
                error_code=401,
                error_message="Signature verification failed",
            )

        key_entry.last_used_time = time.time()
        session.add(key_entry)
        return AuthVerificationResult(success=True, credential_id=key_entry.id)
