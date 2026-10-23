import secrets
import string
from dataclasses import dataclass

from sqlalchemy import select

from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.runtime import enter_server_root, load_database_models
lazy from include.database.models.auth import UserTotpCredential
lazy from include.database.models.identity import User
lazy from include.database.session import Session
lazy from include.domains.identity.commands.credentials import remove_totp, set_password


@dataclass(frozen=True)
class PasswordResetResult:
    username: str
    generated_password: str | None


@dataclass(frozen=True)
class TotpClearResult:
    username: str | None
    updated_count: int


def build_random_password(length: int = 16) -> str:
    alphabet = string.ascii_letters + string.digits + "!@#$%^&*()-_=+[]{};:,.<>?/"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def reset_password(username: str, password: str | None = None) -> PasswordResetResult:
    enter_server_root()
    load_database_models()

    new_password = password or build_random_password()
    with Session() as session:
        user = session.scalar(select(User).where(User.username == username))
        if user is None:
            raise MaintenanceOperationError(f"User {username!r} was not found.")

        set_password(session, user, new_password, force_update_after_login=True)
        session.commit()

    return PasswordResetResult(
        username=username,
        generated_password=None if password else new_password,
    )


def rotate_secrets() -> int:
    """Invalidate every user's existing tokens with independent signing keys."""
    enter_server_root()
    load_database_models()

    with Session.begin() as session:
        users = session.scalars(select(User)).all()
        for user in users:
            user.secret_key = secrets.token_hex(32)
    return len(users)


def clear_totp(
    username: str | None = None,
    *,
    all_users: bool = False,
) -> TotpClearResult:
    enter_server_root()
    if all_users == bool(username):
        raise MaintenanceOperationError(
            "Specify exactly one target: a username or --all."
        )
    load_database_models()

    with Session() as session:
        if all_users:
            credentials = session.scalars(select(UserTotpCredential)).all()
            updated_count = len(credentials)
            for credential in credentials:
                remove_totp(session, credential.user, credential)
            session.commit()
            return TotpClearResult(username=None, updated_count=updated_count)

        user = session.scalar(select(User).where(User.username == username))
        if user is None:
            raise MaintenanceOperationError(f"User {username!r} was not found.")

        credential = session.get(UserTotpCredential, user.id)
        if credential is not None:
            remove_totp(session, user, credential)
            session.commit()

    return TotpClearResult(username=username, updated_count=1)
