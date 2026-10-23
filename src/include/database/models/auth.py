import secrets
import time
import uuid

import orjson
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import (
    VARCHAR,
    Boolean,
    Double,
    ForeignKey,
    Index,
    LargeBinary,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.mysql import BINARY as MySQLBinary
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.orm.session import object_session

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
    pass_hash: Mapped[str] = mapped_column(
        Text,
        nullable=False,
    )
    passwd_last_modified: Mapped[float] = mapped_column(
        Double,
        default=time.time,
        nullable=False,
    )

    user: Mapped["User"] = relationship(
        "User",
        back_populates="password_credential",
    )

    def verify(self, plain_password: str) -> bool:
        try:
            return _password_hasher.verify(self.pass_hash, plain_password)
        except VerifyMismatchError, VerificationError, InvalidHashError:
            return False

    def check_needs_rehash(self) -> bool:
        return _password_hasher.check_needs_rehash(self.pass_hash)

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

    user: Mapped["User"] = relationship(
        "User",
        back_populates="totp_credential",
    )

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
                            session = object_session(self)
                            if session is not None:
                                session.add(self)
                                session.commit()
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

    @classmethod
    def create_pending(
        cls, user_id: uuid.UUID
    ) -> tuple["UserTotpCredential", list[str]]:
        secret = pyotp.random_base32()
        backup_codes = [secrets.token_hex(4) for _ in range(10)]
        pepper = global_config["security"]["pepper"]
        hashed_codes = [_password_hasher.hash(code + pepper) for code in backup_codes]
        credential = cls(
            user_id=user_id,
            secret=secret,
            enabled=False,
            backup_codes=orjson.dumps(hashed_codes).decode("utf-8"),
            created_time=time.time(),
        )
        return credential, backup_codes


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

    # SHA-256 of the canonical OpenSSH public key blob.
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

    user: Mapped["User"] = relationship(
        "User",
        back_populates="auth_public_keys",
    )
