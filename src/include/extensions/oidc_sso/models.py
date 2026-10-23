import secrets
import uuid

from sqlalchemy import VARCHAR, ForeignKey, LargeBinary, MetaData, Text
from sqlalchemy.dialects.mysql import BINARY as MySQLBinary
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from include.database.models.identity import User
from include.database.session import Base


class OIDCBase(DeclarativeBase):
    metadata = MetaData(naming_convention=Base.metadata.naming_convention)


class UserOidcCredential(OIDCBase):
    __tablename__ = "user_oidc_credentials"

    id: Mapped[str] = mapped_column(
        VARCHAR(32), primary_key=True, default=lambda: secrets.token_hex(16)
    )
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey(User.id, ondelete="CASCADE"), nullable=False, index=True
    )
    issuer: Mapped[str] = mapped_column(Text, nullable=False)
    subject: Mapped[str] = mapped_column(Text, nullable=False)
    identity_digest: Mapped[bytes] = mapped_column(
        LargeBinary(32).with_variant(MySQLBinary(32), "mysql"),
        unique=True,
        nullable=False,
    )
    user: Mapped["User"] = relationship(User)
