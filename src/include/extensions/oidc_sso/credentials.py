import hashlib

import orjson
from sqlalchemy import select
from sqlalchemy.orm import Session

from include.database.models.identity import User

from .models import UserOidcCredential


def find_oidc_credential(
    session: Session,
    issuer: str,
    subject: str,
) -> UserOidcCredential | None:
    digest = hashlib.sha256(orjson.dumps([issuer, subject])).digest()
    credential = session.scalar(
        select(UserOidcCredential).where(UserOidcCredential.identity_digest == digest)
    )
    if credential is not None and (
        credential.issuer != issuer or credential.subject != subject
    ):
        raise ValueError("OIDC identity digest collision")
    return credential


def bind_oidc_identity(
    session: Session,
    user: User,
    issuer: str,
    subject: str,
) -> UserOidcCredential:
    """Bind a verified/operator-supplied identity without granting any purpose."""
    if not issuer or not subject or len(subject) > 255:
        raise ValueError(
            "OIDC issuer and subject must be nonempty; subject is at most 255 characters"
        )
    credential = UserOidcCredential(
        user_id=user.id,
        issuer=issuer,
        subject=subject,
        identity_digest=hashlib.sha256(orjson.dumps([issuer, subject])).digest(),
    )
    session.add(credential)
    session.flush()
    return credential
