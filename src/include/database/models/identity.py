import secrets
import time
import uuid
from enum import IntEnum
from functools import cached_property
from typing import Any
lazy from collections.abc import Callable, Iterable

import jwt
from sqlalchemy import (
    VARCHAR,
    Boolean,
    Double,
    ForeignKey,
    Index,
    Integer,
    String,
    Uuid,
    event,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.orm.session import object_session

from include.config.constants import (
    DEFAULT_TOKEN_EXPIRY_SECONDS,
    USERNAME_DATABASE_MAX_LENGTH,
)
from include.config.settings import global_config
from include.database.session import Base, Session
from include.domains.identity.tokens import Token, TokenPurpose
lazy from include.database.models.access import UserBlockEntry
lazy from include.database.models.comments import Comment
lazy from include.database.models.files import File
lazy from include.database.models.keyrings import UserKey
lazy from include.database.models.operations import AuditEntry
lazy from include.domains.access.permissions import Permissions


class UserStatus(IntEnum):
    ACTIVE = 0
    DISABLED = 1


def _permission_grants_and_revocations(
    permission_entries: Iterable[Any], now: float | None = None
) -> tuple[set, set]:
    if now is None:
        now = time.time()

    granted_permissions = set()
    revoked_permissions = set()

    for entry in permission_entries:
        if entry.start_time is not None and entry.start_time > now:
            continue
        if entry.end_time is not None and entry.end_time < now:
            continue

        target = granted_permissions if entry.granted else revoked_permissions
        target.add(entry.permission)

    return granted_permissions, revoked_permissions


def _effective_permissions(
    permission_entries: Iterable[Any], now: float | None = None
) -> set:
    granted_permissions, revoked_permissions = _permission_grants_and_revocations(
        permission_entries, now
    )
    return granted_permissions - revoked_permissions


def _replace_permission_entries(
    session,
    current_entries: list[Any],
    new_permission_entries: list[dict[str, Any]],
    create_entry: Callable[[dict[str, Any]], Any],
) -> None:
    for old_permission in list(current_entries):
        session.delete(old_permission)
    current_entries.clear()

    for entry_data in new_permission_entries:
        permission = create_entry(entry_data)
        session.add(permission)
        current_entries.append(permission)


class User(Base):
    __tablename__ = "users"
    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        # UUID v4 avoids exposing the user's creation timestamp.
        default=uuid.uuid4,
    )
    username: Mapped[str] = mapped_column(
        String(USERNAME_DATABASE_MAX_LENGTH),
        unique=True,
        nullable=False,
        index=True,
    )
    nickname: Mapped[str | None] = mapped_column(String(255), nullable=True)

    avatar_id: Mapped[str | None] = mapped_column(
        ForeignKey("files.id"), nullable=True, index=True
    )
    avatar: Mapped["File | None"] = relationship("File")

    last_login: Mapped[float | None] = mapped_column(Double)
    created_time: Mapped[float] = mapped_column(
        Double, default=time.time, nullable=False
    )

    status: Mapped[int] = mapped_column(
        Integer, default=UserStatus.ACTIVE.value, nullable=False
    )
    status_comment_id: Mapped[int | None] = mapped_column(
        ForeignKey("comments.comment_id", ondelete="SET NULL"), nullable=True
    )
    status_comment: Mapped["Comment | None"] = relationship("Comment")

    # Per-user secret key. It is regenerated whenever the password changes.
    # Token verification uses it when present; otherwise it falls back to the
    # global secret key loaded from config.toml.
    secret_key: Mapped[str] = mapped_column(
        VARCHAR(64), default=lambda: secrets.token_hex(32), nullable=True
    )

    groups: Mapped[list[UserMembership]] = relationship(
        "UserMembership", back_populates="user", cascade="all, delete-orphan"
    )
    rights: Mapped[list[UserPermission]] = relationship(
        "UserPermission", back_populates="user", cascade="all, delete-orphan"
    )

    block_entries: Mapped[list["UserBlockEntry"]] = relationship(
        "UserBlockEntry", back_populates="user", cascade="all, delete-orphan"
    )
    audit_entries: Mapped[list["AuditEntry"]] = relationship(
        "AuditEntry", back_populates="user"
    )
    keyring: Mapped[list["UserKey"]] = relationship(
        "UserKey",
        back_populates="user",
        foreign_keys="UserKey.user_id",
        cascade="all, delete-orphan",
    )

    preference_dek_id: Mapped[str | None] = mapped_column(
        String(64),
        ForeignKey(
            "keyrings.id",
            name="fk_users_preference_dek_id",
            ondelete="SET NULL",
            use_alter=True,
        ),
        nullable=True,
        unique=True,
    )
    preference_dek: Mapped["UserKey | None"] = relationship(
        "UserKey",
        uselist=False,
        post_update=True,
        foreign_keys=[preference_dek_id],
    )

    def __repr__(self) -> str:
        return (
            f"User(username={self.username!r}, "
            f"nickname={self.nickname!r}, last_login={self.last_login!r}, "
            f"created_time={self.created_time!r})"
        )

    @property
    def status_reason(self) -> str | None:
        return self.status_comment.comment_text if self.status_comment else None

    def create_token_after_authentication(self) -> Token:
        secret = (
            global_config["server"]["secret_key"]
            if not self.secret_key
            else self.secret_key
        )
        token = Token.new(self.id, DEFAULT_TOKEN_EXPIRY_SECONDS, secret)

        session = object_session(self)
        if session is not None:
            self.last_login = time.time()
            session.add(self)
            session.commit()

        return token

    def is_token_valid(self, token: Token | str, purpose=TokenPurpose.GENERAL) -> bool:
        if self.status != UserStatus.ACTIVE:
            return False
        raw_token = token.raw if isinstance(token, Token) else str(token)
        try:
            verified = Token.from_raw(
                raw_token,
                (
                    global_config["server"]["secret_key"]
                    if not self.secret_key
                    else self.secret_key
                ),
            )
            return verified.sub == self.id and bool(verified.purpose & purpose)
        except jwt.ExpiredSignatureError, jwt.InvalidTokenError:
            return False

    def renew_token(self, old: Token | None = None) -> Token:
        if old is not None and old.purpose & (
            TokenPurpose.AUTH | TokenPurpose.POST_AUTH
        ):
            raise jwt.InvalidTokenError(
                "Cannot renew an authentication continuation token"
            )
        if old is not None and not self.is_token_valid(old, purpose=old.purpose):
            raise jwt.InvalidTokenError("Cannot renew an invalid token")
        secret = self.secret_key or global_config["server"]["secret_key"]
        purpose = TokenPurpose.GENERAL

        return Token.new(self.id, DEFAULT_TOKEN_EXPIRY_SECONDS, secret, purpose)

    @property
    def all_groups(self):
        """Return the set of currently active group names for this user."""
        now = time.time()
        return {
            membership.group_name
            for membership in self.groups
            if (membership.start_time is None or membership.start_time <= now)
            and (membership.end_time is None or membership.end_time >= now)
        }

    @all_groups.setter
    def all_groups(self, new_group_list: list[str]):
        session = object_session(self)
        if not session:
            raise RuntimeError()

        for old_group in self.groups:
            session.delete(old_group)
        self.groups.clear()
        for group_name in new_group_list:
            membership = UserMembership(
                user=self, group_name=group_name, start_time=time.time(), end_time=None
            )
            session.add(membership)
            self.groups.append(membership)
        # session.commit()

    @property
    def own_permissions(self) -> set[Permissions]:
        return _effective_permissions(self.rights)

    @own_permissions.setter
    def own_permissions(self, new_permission_entries: list[dict[str, Any]]):
        session = object_session(self)
        if not session:
            raise RuntimeError()

        _replace_permission_entries(
            session,
            self.rights,
            new_permission_entries,
            lambda entry: UserPermission(
                user=self,
                user_id=self.id,
                permission=entry["permission"],
                granted=entry["granted"],
                start_time=entry["start_time"],
                end_time=entry["end_time"],
            ),
        )

    def _group_permission_grants_and_revocations(
        self, now: float | None = None
    ) -> tuple[set, set]:
        if now is None:
            now = time.time()

        group_granted_perms = set()
        group_revoked_perms = set()
        session = object_session(self)

        for membership in getattr(self, "groups", []):
            membership: UserMembership
            if membership.start_time is not None and membership.start_time > now:
                continue
            if membership.end_time is not None and membership.end_time < now:
                continue

            if hasattr(membership, "group_name"):
                if session is not None:
                    group = session.get(UserGroup, membership.group_name)
                else:
                    with Session() as fallback_session:
                        group = fallback_session.get(UserGroup, membership.group_name)
                        if group:
                            group_grants, group_revocations = (
                                _permission_grants_and_revocations(
                                    group.permissions, now
                                )
                            )
                            group_granted_perms |= group_grants
                            group_revoked_perms |= group_revocations
                    continue
                if group:
                    group_grants, group_revocations = (
                        _permission_grants_and_revocations(group.permissions, now)
                    )
                    group_granted_perms |= group_grants
                    group_revoked_perms |= group_revocations
            else:
                raise ValueError(
                    f"UserMembership {membership.id} does not have a valid group_name attribute."
                )

        return group_granted_perms, group_revoked_perms

    @property
    def inherited_permissions(self) -> set[Permissions]:
        group_granted_perms, group_revoked_perms = (
            self._group_permission_grants_and_revocations()
        )
        return group_granted_perms - group_revoked_perms

    @cached_property
    def all_permissions(self) -> set[Permissions]:
        now = time.time()
        user_granted_perms, revoked_perms = _permission_grants_and_revocations(
            self.rights, now
        )
        group_granted_perms, group_revocations = (
            self._group_permission_grants_and_revocations(now)
        )
        revoked_perms |= group_revocations

        all_perms = user_granted_perms | group_granted_perms
        return (all_perms - revoked_perms) if (all_perms or revoked_perms) else set()


# User permission table with grants, revocations, and validity windows.
class UserPermission(Base):
    __tablename__ = "user_permissions"
    __table_args__ = (Index("ix_user_permissions_end_time_id", "end_time", "id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE")
    )
    permission: Mapped[Permissions] = mapped_column(VARCHAR(255))
    granted: Mapped[bool] = mapped_column(
        Boolean, default=True
    )  # True grants the permission; False revokes it.
    start_time: Mapped[float | None] = mapped_column(
        Double, nullable=False
    )  # Permission start timestamp.
    end_time: Mapped[float | None] = mapped_column(
        Double, nullable=True
    )  # Permission end timestamp.
    user: Mapped[User] = relationship("User", back_populates="rights")

    def __repr__(self) -> str:
        return (
            f"UserPermission(id={self.id!r}, user_id={self.user_id!r}, "
            f"permission={self.permission!r}, granted={self.granted!r}, "
            f"start_time={self.start_time!r}, end_time={self.end_time!r})"
        )


# User group memberships with validity windows.
class UserMembership(Base):
    __tablename__ = "user_memberships"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE")
    )
    group_name: Mapped[str] = mapped_column(
        ForeignKey("user_groups.group_name", ondelete="CASCADE")
    )
    start_time: Mapped[float] = mapped_column(Double, nullable=False)  # Join timestamp.
    end_time: Mapped[float | None] = mapped_column(
        Double, nullable=True
    )  # Leave timestamp.
    user: Mapped[User] = relationship("User", back_populates="groups")
    group: Mapped[UserGroup] = relationship("UserGroup", back_populates="memberships")

    def __repr__(self) -> str:
        return (
            f"UserMembership(id={self.id!r}, user_id={self.user_id!r}, "
            f"group_name={self.group_name!r}, start_time={self.start_time!r}, "
            f"end_time={self.end_time!r})"
        )


@event.listens_for(User.groups, "append", retval=True)
def filter_expired_group(user, group, initiator):
    now = time.time()
    if group.end_time is not None and group.end_time < now:
        return None  # Do not append.
    return group


class UserGroup(Base):
    __tablename__ = "user_groups"
    group_name: Mapped[str] = mapped_column(VARCHAR(255), primary_key=True)
    group_display_name: Mapped[str | None] = mapped_column(VARCHAR(128), nullable=True)

    permissions: Mapped[list[UserGroupPermission]] = relationship(
        "UserGroupPermission", back_populates="group", cascade="all, delete-orphan"
    )
    memberships: Mapped[list[UserMembership]] = relationship(
        "UserMembership", back_populates="group", cascade="all, delete"
    )

    @property
    def all_permissions(self) -> set[str]:
        return _effective_permissions(self.permissions)

    @all_permissions.setter
    def all_permissions(self, new_permission_entries: list[dict[str, Any]]):
        session = object_session(self)
        if not session:
            raise RuntimeError()

        _replace_permission_entries(
            session,
            self.permissions,
            new_permission_entries,
            lambda entry: UserGroupPermission(
                group=self,
                group_name=self.group_name,
                permission=entry["permission"],
                granted=entry["granted"],
                start_time=entry["start_time"],
                end_time=entry["end_time"],
            ),
        )

    @property
    def members(self) -> set[uuid.UUID]:
        session = object_session(self)
        if not session:
            raise RuntimeError("No active object session found")

        now = time.time()
        _members = set()
        for membership in (
            session.query(UserMembership)
            .filter(UserMembership.group_name == self.group_name)
            .all()
        ):
            if membership.end_time is None or membership.end_time >= now:
                _members.add(membership.user_id)

        return _members

    def __repr__(self) -> str:
        return (
            f"UserGroup(group_name={self.group_name!r}, "
            f"permissions={self.permissions!r})"
        )


# Group permission table with grants, revocations, and validity windows.
class UserGroupPermission(Base):
    __tablename__ = "group_permissions"
    __table_args__ = (Index("ix_group_permissions_end_time_id", "end_time", "id"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    group_name: Mapped[str] = mapped_column(
        ForeignKey("user_groups.group_name", ondelete="CASCADE")
    )
    permission: Mapped[str] = mapped_column(VARCHAR(255))
    granted: Mapped[bool] = mapped_column(
        Boolean, default=True
    )  # True grants the permission; False revokes it.
    start_time: Mapped[float | None] = mapped_column(
        Double, nullable=False, default=0.0
    )  # Permission start timestamp.
    end_time: Mapped[float | None] = mapped_column(
        Double, nullable=True
    )  # Permission end timestamp.
    group: Mapped[UserGroup] = relationship("UserGroup", back_populates="permissions")

    def __repr__(self) -> str:
        return (
            f"UserGroupPermission(id={self.id!r}, group_name={self.group_name!r}, "
            f"permission={self.permission!r}, granted={self.granted!r}, "
            f"start_time={self.start_time!r}, end_time={self.end_time!r})"
        )
