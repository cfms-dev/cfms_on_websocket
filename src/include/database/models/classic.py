import secrets
import time
from functools import cached_property
from typing import TYPE_CHECKING, Any, Callable, Iterable, List, Optional, Set, cast

import jwt
import orjson
import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from sqlalchemy import (
    JSON,
    VARCHAR,
    Boolean,
    Float,
    ForeignKey,
    Integer,
    Text,
    event,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.orm.session import object_session

from include.classes.auth import Token
from include.classes.enum.permissions import Permissions
from include.classes.enum.status import UserStatus
from include.conf_loader import global_config
from include.constants import DEFAULT_TOKEN_EXPIRY_SECONDS
from include.database.handler import Base, Session
from include.exceptions.misc import (
    UserNotActiveError,
    UserTOTPFailedError,
    UserTOTPRequiredError,
)

# Module-level PasswordHasher instance — reused across all calls to avoid
# repeated construction overhead.
_password_hasher = PasswordHasher()

if TYPE_CHECKING:
    from include.database.models.blocking import UserBlockEntry
    from include.database.models.file import File
    from include.database.models.keyring import UserKey


def _permission_grants_and_revocations(
    permission_entries: Iterable[Any], now: Optional[float] = None
) -> tuple[set, set]:
    if now is None:
        now = time.time()

    granted_permissions = set()
    revoked_permissions = set()

    for entry in permission_entries:
        if entry.end_time is not None and entry.end_time < now:
            continue

        target = granted_permissions if entry.granted else revoked_permissions
        target.add(entry.permission)

    return granted_permissions, revoked_permissions


def _effective_permissions(
    permission_entries: Iterable[Any], now: Optional[float] = None
) -> set:
    granted_permissions, revoked_permissions = _permission_grants_and_revocations(
        permission_entries, now
    )
    return granted_permissions - revoked_permissions


def _replace_permission_entries(
    session,
    current_entries: list[Any],
    new_permission_list: list[str],
    create_entry: Callable[[str, float], Any],
) -> None:
    for old_permission in list(current_entries):
        session.delete(old_permission)
    current_entries.clear()

    now = time.time()
    for permission_name in new_permission_list:
        permission = create_entry(permission_name, now)
        session.add(permission)
        current_entries.append(permission)


class User(Base):
    __tablename__ = "users"
    # id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(VARCHAR(64), primary_key=True)
    pass_hash: Mapped[str] = mapped_column(Text)
    passwd_last_modified: Mapped[float] = mapped_column(
        Float, default=0, nullable=False
    )
    nickname: Mapped[Optional[str]] = mapped_column(VARCHAR(255), nullable=True)

    avatar_id: Mapped[Optional[str]] = mapped_column(
        ForeignKey("files.id"), nullable=True
    )
    avatar: Mapped[Optional["File"]] = relationship("File")

    last_login: Mapped[Optional[float]] = mapped_column(Float)
    created_time: Mapped[Optional[float]] = mapped_column(Float, nullable=False)

    status: Mapped[UserStatus] = mapped_column(
        Integer, default=UserStatus.ACTIVE.value, nullable=False
    )

    # 这是对应每个用户的 secret_key. 每次更改密码时将重新生成，如果该属性不为空，则在验证 token 时使用此
    # 密钥，否则，使用从 config.toml 加载的全局密钥。
    secret_key: Mapped[str] = mapped_column(
        VARCHAR(64), default=lambda: secrets.token_hex(32), nullable=True
    )

    # Two-Factor Authentication (TOTP) fields
    totp_secret: Mapped[Optional[str]] = mapped_column(
        VARCHAR(32), nullable=True, default=None
    )
    totp_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    totp_backup_codes: Mapped[Optional[str]] = mapped_column(
        Text, nullable=True, default=None
    )  # JSON string of backup codes

    groups: Mapped[List["UserMembership"]] = relationship(
        "UserMembership", back_populates="user", cascade="all, delete-orphan"
    )
    rights: Mapped[List["UserPermission"]] = relationship(
        "UserPermission", back_populates="user", cascade="all, delete-orphan"
    )

    block_entries: Mapped[List["UserBlockEntry"]] = relationship(
        "UserBlockEntry", back_populates="user", cascade="all, delete-orphan"
    )
    audit_entries: Mapped[List["AuditEntry"]] = relationship(
        "AuditEntry", back_populates="user"
    )
    keyring: Mapped[List["UserKey"]] = relationship(
        "UserKey",
        back_populates="user",
        foreign_keys="UserKey.username",
        cascade="all, delete-orphan",
    )

    preference_dek_id: Mapped[Optional[str]] = mapped_column(
        VARCHAR(64),
        ForeignKey(
            "keyrings.id",
            name="fk_users_preference_dek_id",
            ondelete="SET NULL",
            use_alter=True,
        ),
        nullable=True,
        unique=True,
    )
    preference_dek: Mapped[Optional["UserKey"]] = relationship(
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

    def verify_password(self, plain_password: str) -> bool:
        try:
            return _password_hasher.verify(self.pass_hash, plain_password)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False

    def authenticate(
        self, plain_password: str, totp_token: Optional[str] = None
    ) -> bool:
        if not self.verify_password(plain_password):
            return False

        if self.totp_enabled:
            if not totp_token:
                raise UserTOTPRequiredError
            elif not self.verify_totp(totp_token):
                raise UserTOTPFailedError

        if self.status != UserStatus.ACTIVE:
            raise UserNotActiveError

        return True

    def authenticate_and_create_token(
        self, plain_password: str, totp_token: Optional[str] = None
    ) -> Optional[Token]:
        if not self.authenticate(plain_password, totp_token=totp_token):
            return None  # exceptions should be handled by caller

        secret = (
            global_config["server"]["secret_key"]
            if not self.secret_key
            else self.secret_key
        )
        token = Token(secret, self.username)
        token.new(DEFAULT_TOKEN_EXPIRY_SECONDS)

        session = object_session(self)
        if session is not None:
            self.last_login = time.time()
            # Rehash password if argon2id parameters have changed (same transaction)
            if _password_hasher.check_needs_rehash(self.pass_hash):
                self.pass_hash = _password_hasher.hash(plain_password)
            session.add(self)
            session.commit()

        return token

    def is_token_valid(self, token: str) -> bool:
        """
        验证JWT令牌的有效性。
        如果令牌有效且未过期，且用户账户处于活跃状态，返回True；否则返回False。
        """
        if self.status != UserStatus.ACTIVE:
            return False
        try:
            payload = jwt.decode(
                token,
                (
                    global_config["server"]["secret_key"]
                    if not self.secret_key
                    else self.secret_key
                ),
                algorithms=["HS256"],
            )
            return payload.get("username") == self.username
        except (jwt.ExpiredSignatureError, jwt.InvalidTokenError):
            return False

    def renew_token(self) -> Token:
        """
        重新生成用户的JWT令牌。
        """

        secret = (
            global_config["server"]["secret_key"]
            if not self.secret_key
            else self.secret_key
        )
        new_token = Token(secret, self.username)
        new_token.new(DEFAULT_TOKEN_EXPIRY_SECONDS)

        return new_token

    def set_password(self, plain_password: str, force_update_after_login: bool = False):
        """
        修改用户密码，使用 argon2id KDF 生成哈希并保存，写入数据库。
        """
        self.pass_hash = _password_hasher.hash(plain_password)

        self.secret_key = secrets.token_hex(
            32
        )  # token_hex(32) generates a 64-character hex
        self.passwd_last_modified = time.time() if not force_update_after_login else 0

        # 写入数据库
        session = object_session(self)
        if session is not None:
            session.add(self)
            session.commit()

    def setup_totp(self) -> tuple[str, list[str]]:
        """
        Setup TOTP for the user. Generates a new TOTP secret and backup codes.
        Returns a tuple of (secret, backup_codes).
        """
        # Generate a new TOTP secret
        self.totp_secret = pyotp.random_base32()

        # Generate 10 backup codes
        backup_codes = [secrets.token_hex(4) for _ in range(10)]
        pepper = global_config["security"]["pepper"]
        # Hash the backup codes before storing using Argon2id with pepper
        hashed_codes = [_password_hasher.hash(code + pepper) for code in backup_codes]
        self.totp_backup_codes = orjson.dumps(hashed_codes).decode("utf-8")

        # TOTP is not enabled yet until validated
        self.totp_enabled = False

        # Write to database
        session = object_session(self)
        if session is not None:
            session.add(self)
            session.commit()

        return cast(str, self.totp_secret), backup_codes

    def enable_totp(self):
        """
        Enable TOTP authentication for the user.
        """
        if not self.totp_secret:
            raise ValueError("TOTP secret not set. Call setup_totp() first.")

        self.totp_enabled = True

        session = object_session(self)
        if session is not None:
            session.add(self)
            session.commit()

    def disable_totp(self):
        """
        Disable and remove TOTP authentication for the user.
        """
        self.totp_enabled = False
        self.totp_secret = None
        self.totp_backup_codes = None

        session = object_session(self)
        if session is not None:
            session.add(self)
            session.commit()

    def verify_totp(self, token: str) -> bool:
        """
        Verify a TOTP token or backup code.
        Returns True if the token is valid.
        Can be called during setup (when totp_enabled is False) or during login.
        """
        # Check if TOTP secret exists (may not be enabled yet during setup)
        if not self.totp_secret:
            return False

        # Try to verify as TOTP token first
        totp = pyotp.TOTP(self.totp_secret)
        if totp.verify(token, valid_window=1):
            return True

        # Try to verify as backup code (only if 2FA is enabled)
        if self.totp_enabled and self.totp_backup_codes:
            try:
                hashed_codes = orjson.loads(self.totp_backup_codes)
                pepper = global_config["security"]["pepper"]

                for hash_str in hashed_codes:
                    try:
                        if _password_hasher.verify(hash_str, token + pepper):
                            # Verification succeeded, remove the used backup code
                            hashed_codes.remove(hash_str)
                            self.totp_backup_codes = orjson.dumps(hashed_codes).decode(
                                "utf-8"
                            )

                            session = object_session(self)
                            if session is not None:
                                session.add(self)
                                session.commit()

                            return True
                    except VerifyMismatchError:
                        continue
            except (orjson.JSONDecodeError, ValueError):
                pass

        return False

    @property
    def totp_provisioning_uri(self) -> Optional[str]:
        """
        Get the TOTP provisioning URI for QR code generation.
        """
        if not self.totp_secret:
            return None

        totp = pyotp.TOTP(self.totp_secret)
        return totp.provisioning_uri(name=self.username, issuer_name="CFMS")

    @property
    def all_groups(self):
        """
        获取用户所有有效的用户组名称集合。
        """
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
    def own_permissions(self) -> Set[Permissions]:
        return _effective_permissions(self.rights)

    @own_permissions.setter
    def own_permissions(self, new_permission_list: list[str]):
        session = object_session(self)
        if not session:
            raise RuntimeError()

        _replace_permission_entries(
            session,
            self.rights,
            new_permission_list,
            lambda permission, now: UserPermission(
                user=self,
                username=self.username,
                permission=permission,
                start_time=now,
                end_time=None,
            ),
        )

    def _group_permission_grants_and_revocations(
        self, now: Optional[float] = None
    ) -> tuple[set, set]:
        if now is None:
            now = time.time()

        group_granted_perms = set()
        group_revoked_perms = set()

        for membership in getattr(self, "groups", []):
            membership: UserMembership
            if membership.start_time is not None and membership.start_time > now:
                continue
            if membership.end_time is not None and membership.end_time < now:
                continue

            if hasattr(membership, "group_name"):
                with Session() as session:
                    group = session.get(UserGroup, membership.group_name)
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
    def inherited_permissions(self) -> Set[Permissions]:
        group_granted_perms, group_revoked_perms = (
            self._group_permission_grants_and_revocations()
        )
        return group_granted_perms - group_revoked_perms

    @cached_property
    def all_permissions(self) -> Set[Permissions]:
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


# 用户权限表，支持权限的给予/剥夺及持续时间
class UserPermission(Base):
    __tablename__ = "user_permissions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(
        ForeignKey("users.username", ondelete="CASCADE")
    )
    permission: Mapped[Permissions] = mapped_column(VARCHAR(255))
    granted: Mapped[bool] = mapped_column(
        Boolean, default=True
    )  # True: 给予, False: 剥夺
    start_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=False
    )  # 权限生效时间（时间戳）
    end_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )  # 权限失效时间（时间戳）
    user: Mapped["User"] = relationship("User", back_populates="rights")

    def __repr__(self) -> str:
        return (
            f"UserPermission(id={self.id!r}, username={self.username!r}, "
            f"permission={self.permission!r}, granted={self.granted!r}, "
            f"start_time={self.start_time!r}, end_time={self.end_time!r})"
        )


@event.listens_for(User, "load")
def filter_permissions_on_load(target, context):
    now = time.time()
    # 只保留granted=True且未过期的权限
    valid_permissions = []
    session = object_session(target)
    for perm in list(target.rights):
        if not perm.granted or (perm.end_time is not None and perm.end_time < now):
            # 从数据库中永久删除过期或被剥夺的权限
            if session is not None:
                session.delete(perm)
        else:
            valid_permissions.append(perm)
    target.rights = valid_permissions


# 用户所属组，包括在此用户组中的持续时间
class UserMembership(Base):
    __tablename__ = "user_memberships"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(
        ForeignKey("users.username", ondelete="CASCADE")
    )
    group_name: Mapped[str] = mapped_column(
        ForeignKey("user_groups.group_name", ondelete="CASCADE")
    )
    start_time: Mapped[float] = mapped_column(Float, nullable=False)  # 加入组的时间戳
    end_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )  # 离开组的时间戳
    user: Mapped["User"] = relationship("User", back_populates="groups")
    group: Mapped["UserGroup"] = relationship("UserGroup", back_populates="memberships")

    def __repr__(self) -> str:
        return (
            f"UserMembership(id={self.id!r}, username={self.username!r}, "
            f"group_name={self.group_name!r}, start_time={self.start_time!r}, "
            f"end_time={self.end_time!r})"
        )


@event.listens_for(User.groups, "append", retval=True)
def filter_expired_group(user, group, initiator):
    now = time.time()
    if group.end_time is not None and group.end_time < now:
        return None  # 不添加
    return group


class UserGroup(Base):
    __tablename__ = "user_groups"
    group_name: Mapped[str] = mapped_column(VARCHAR(255), primary_key=True)
    group_display_name: Mapped[Optional[str]] = mapped_column(
        VARCHAR(128), nullable=True
    )

    permissions: Mapped[List["UserGroupPermission"]] = relationship(
        "UserGroupPermission", back_populates="group", cascade="all, delete-orphan"
    )
    memberships: Mapped[List["UserMembership"]] = relationship(
        "UserMembership", back_populates="group", cascade="all, delete"
    )

    @property
    def all_permissions(self) -> Set[str]:
        return _effective_permissions(self.permissions)

    @all_permissions.setter
    def all_permissions(self, new_permission_list: list[str]):
        session = object_session(self)
        if not session:
            raise RuntimeError()

        _replace_permission_entries(
            session,
            self.permissions,
            new_permission_list,
            lambda permission, now: UserGroupPermission(
                group=self,
                group_name=self.group_name,
                permission=permission,
                start_time=now,
                end_time=None,
            ),
        )

    @property
    def members(self) -> set[str]:
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
                _members.add(membership.username)

        return _members

    def __repr__(self) -> str:
        return (
            f"UserGroup(group_name={self.group_name!r}, "
            f"permissions={self.permissions!r})"
        )


# 用户组权限表，支持权限的给予/剥夺及持续时间
class UserGroupPermission(Base):
    __tablename__ = "group_permissions"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    group_name: Mapped[str] = mapped_column(
        ForeignKey("user_groups.group_name", ondelete="CASCADE")
    )
    permission: Mapped[str] = mapped_column(VARCHAR(255))
    granted: Mapped[bool] = mapped_column(
        Boolean, default=True
    )  # True: 给予, False: 剥夺
    start_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=False, default=0.0
    )  # 权限生效时间（时间戳）
    end_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=True
    )  # 权限失效时间（时间戳）
    group: Mapped["UserGroup"] = relationship("UserGroup", back_populates="permissions")

    def __repr__(self) -> str:
        return (
            f"UserGroupPermission(id={self.id!r}, group_name={self.group_name!r}, "
            f"permission={self.permission!r}, granted={self.granted!r}, "
            f"start_time={self.start_time!r}, end_time={self.end_time!r})"
        )


class AuditEntry(Base):  # 审计条目
    __tablename__ = "audit_entries"
    id: Mapped[str] = mapped_column(
        VARCHAR(255), primary_key=True, default=lambda: secrets.token_hex(32)
    )
    action: Mapped[str] = mapped_column(VARCHAR(255), nullable=False)
    username: Mapped[str] = mapped_column(ForeignKey("users.username"), nullable=True)
    user: Mapped[User] = relationship("User", back_populates="audit_entries")
    target: Mapped[str] = mapped_column(VARCHAR(255), nullable=True)
    data: Mapped[dict] = mapped_column(JSON, nullable=True)
    result: Mapped[int] = mapped_column(Integer, nullable=False)
    remote_address: Mapped[Optional[str]] = mapped_column(VARCHAR(64), nullable=True)
    logged_time: Mapped[Optional[float]] = mapped_column(
        Float, nullable=False, default=time.time, index=True
    )


class ObjectAccessEntry(Base):
    """
    Model for `User`/`UserGroup` access.
    """

    __tablename__ = "object_access_entries"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)

    # User / UserGroup
    entity_type: Mapped[str] = mapped_column(VARCHAR(16), nullable=False)
    entity_identifier: Mapped[str] = mapped_column(
        VARCHAR(255), nullable=False, index=True
    )

    # Document / Folder
    target_type: Mapped[str] = mapped_column(VARCHAR(16), nullable=False)
    target_identifier: Mapped[str] = mapped_column(
        VARCHAR(255), nullable=False, index=True
    )

    # read, write, move
    access_type: Mapped[str] = mapped_column(VARCHAR(16), nullable=False)

    start_time: Mapped[Optional[float]] = mapped_column(Float, nullable=False)
    end_time: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
