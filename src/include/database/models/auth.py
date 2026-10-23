import secrets
import time
import uuid

import orjson
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import (
    JSON,
    VARCHAR,
    Boolean,
    CheckConstraint,
    Double,
    ForeignKey,
    Index,
    Integer,
    LargeBinary,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.mysql import BINARY as MySQLBinary
from sqlalchemy.orm import Mapped, mapped_column, relationship

from include.config.settings import global_config
from include.database.session import Base
lazy from include.database.models.identity import User

_password_hasher = PasswordHasher()


class UserPasswordCredential(Base):
    __tablename__ = "user_passwords"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    credential_id: Mapped[str] = mapped_column(
        VARCHAR(32), default=lambda: secrets.token_hex(16), unique=True, nullable=False
    )
    pass_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    passwd_last_modified: Mapped[float] = mapped_column(
        Double,
        default=time.time,
        nullable=False,
    )

    user: Mapped["User"] = relationship("User")

    def verify(self, plain_password: str) -> bool:
        try:
            return _password_hasher.verify(self.pass_hash, plain_password)
        except VerifyMismatchError, VerificationError, InvalidHashError:
            return False

    def check_needs_rehash(self) -> bool:
        return _password_hasher.check_needs_rehash(self.pass_hash)

    def rehash_if_needed(self, plain_password: str) -> None:
        if self.check_needs_rehash():
            self.pass_hash = _password_hasher.hash(plain_password)

    def set_password(
        self, plain_password: str, force_update_after_login: bool = False
    ) -> None:
        self.pass_hash = _password_hasher.hash(plain_password)
        self.passwd_last_modified = time.time() if not force_update_after_login else 0


class UserTotpCredential(Base):
    __tablename__ = "user_totp_credentials"

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        primary_key=True,
    )
    credential_id: Mapped[str] = mapped_column(
        VARCHAR(32), default=lambda: secrets.token_hex(16), unique=True, nullable=False
    )
    secret: Mapped[str] = mapped_column(
        VARCHAR(32),
        nullable=False,
    )
    enabled: Mapped[bool] = mapped_column(
        Boolean,
        default=False,
        nullable=False,
    )
    backup_codes: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        default=None,
    )
    created_time: Mapped[float] = mapped_column(
        Double,
        default=time.time,
        nullable=False,
    )

    user: Mapped["User"] = relationship("User")

    def verify(self, token: str) -> bool:
        if not self.secret:
            return False

        totp = pyotp.TOTP(self.secret)
        if totp.verify(token, valid_window=1):
            return True

        if self.enabled and self.backup_codes:
            try:
                hashed_codes = orjson.loads(self.backup_codes)
                pepper = global_config["security"]["pepper"]

                for hash_str in list(hashed_codes):
                    try:
                        if _password_hasher.verify(hash_str, token + pepper):
                            hashed_codes.remove(hash_str)
                            self.backup_codes = orjson.dumps(hashed_codes).decode(
                                "utf-8"
                            )
                            return True
                    except VerifyMismatchError:
                        continue
            except orjson.JSONDecodeError, ValueError:
                pass

        return False

    @property
    def provisioning_uri(self) -> str:
        totp = pyotp.TOTP(self.secret)
        return totp.provisioning_uri(name=self.user.username, issuer_name="CFMS")

    def enable(self) -> None:
        if not self.secret:
            raise ValueError("TOTP secret not set. Set up TOTP first.")
        self.enabled = True


class UserAuthPublicKey(Base):
    __tablename__ = "user_auth_public_keys"

    __table_args__ = (
        UniqueConstraint(
            "user_id",
            "fingerprint",
            name="uq_user_auth_public_keys_user_fingerprint",
        ),
        Index(
            "ix_user_auth_public_keys_fingerprint",
            "fingerprint",
        ),
    )

    id: Mapped[str] = mapped_column(
        VARCHAR(32),
        primary_key=True,
        default=lambda: secrets.token_hex(16),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"),
        nullable=False,
    )

    # Canonical SubjectPublicKeyInfo DER encoding.
    public_key_der: Mapped[bytes] = mapped_column(
        LargeBinary,
        nullable=False,
    )

    # SHA-256 of the canonical OpenSSH public key line without a comment.
    fingerprint: Mapped[bytes] = mapped_column(
        LargeBinary(32).with_variant(MySQLBinary(32), "mysql"),
        nullable=False,
    )

    label: Mapped[str | None] = mapped_column(
        VARCHAR(255),
        nullable=True,
    )

    created_time: Mapped[float] = mapped_column(
        Double,
        nullable=False,
        default=time.time,
    )

    last_used_time: Mapped[float | None] = mapped_column(
        Double,
        nullable=True,
    )

    user: Mapped["User"] = relationship("User")


class UserAuthPolicy(Base):
    __tablename__ = "user_auth_policies"
    __table_args__ = (
        CheckConstraint(
            "purpose IN ('login', 'mfa', 'escalation')", name="ck_auth_policy_purpose"
        ),
        CheckConstraint("revision > 0", name="ck_auth_policy_revision"),
    )

    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), primary_key=True
    )
    purpose: Mapped[str] = mapped_column(VARCHAR(16), primary_key=True)
    revision: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    chains: Mapped[list[list[dict[str, str | list[str]]]]] = mapped_column(
        JSON, nullable=False
    )
    user: Mapped["User"] = relationship("User")
