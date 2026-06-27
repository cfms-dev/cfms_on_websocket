from __future__ import annotations

import secrets
import string
from dataclasses import dataclass

from maintenance.operations.exceptions import MaintenanceOperationError
from maintenance.runtime import ensure_src_workdir, load_database_models


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
    ensure_src_workdir()
    load_database_models()

    from include.database.session import Session
    from include.domains.identity.models import User

    new_password = password or build_random_password()
    with Session() as session:
        user = session.get(User, username)
        if user is None:
            raise MaintenanceOperationError(f"User {username!r} was not found.")

        user.set_password(new_password, force_update_after_login=True)
        session.add(user)
        session.commit()

    return PasswordResetResult(
        username=username,
        generated_password=None if password else new_password,
    )


def clear_totp(
    username: str | None = None,
    *,
    all_users: bool = False,
) -> TotpClearResult:
    ensure_src_workdir()
    if all_users == bool(username):
        raise MaintenanceOperationError(
            "Specify exactly one target: a username or --all."
        )
    load_database_models()

    from include.database.session import Session
    from include.domains.identity.models import User

    with Session() as session:
        if all_users:
            updated_count = session.query(User).update(
                {
                    User.totp_enabled: False,
                    User.totp_secret: None,
                    User.totp_backup_codes: None,
                }
            )
            session.commit()
            return TotpClearResult(username=None, updated_count=updated_count)

        user = session.get(User, username)
        if user is None:
            raise MaintenanceOperationError(f"User {username!r} was not found.")

        user.totp_enabled = False
        user.totp_secret = None
        user.totp_backup_codes = None
        session.add(user)
        session.commit()

    return TotpClearResult(username=username, updated_count=1)
