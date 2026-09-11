import datetime as dt
import json
import re
import subprocess
from pathlib import Path

import pytest
import tomlkit

_PROJECT_ROOT = Path(__file__).resolve().parents[3]
_SRC_PATH = _PROJECT_ROOT / "src"
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_BOX_DRAWING_RE = re.compile(r"[\u2500-\u257F]")
_AUDIT_CUTOFF = dt.datetime.fromtimestamp(200, dt.UTC).isoformat()


def _run_maintain(
    cwd: Path,
    args: list[str],
    *,
    check: bool = True,
    input_text: str | None = None,
):
    result = subprocess.run(
        ["uv", "run", "--project", str(_PROJECT_ROOT), "maintain", *args],
        cwd=cwd,
        input=input_text,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    if check and result.returncode != 0:
        pytest.fail(
            "maintain command failed\n"
            f"args: {args}\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def _run_python(cwd: Path, code: str):
    result = subprocess.run(
        ["uv", "run", "--project", str(_PROJECT_ROOT), "python", "-c", code],
        cwd=cwd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
    )
    if result.returncode != 0:
        pytest.fail(
            "python setup/check command failed\n"
            f"stdout:\n{result.stdout}\n"
            f"stderr:\n{result.stderr}"
        )
    return result


def _normalize_cli_output(output: str) -> str:
    output = _ANSI_ESCAPE_RE.sub("", output)
    output = _BOX_DRAWING_RE.sub(" ", output)
    return " ".join(output.split())


def _make_src_dir(tmp_path: Path, name: str = "src") -> Path:
    src_dir = tmp_path / name
    src_dir.mkdir()
    (src_dir / "main.py").write_text("", encoding="utf-8")
    (src_dir / "content" / "ssl").mkdir(parents=True)
    (src_dir / "content" / "logs").mkdir(parents=True)

    config = tomlkit.parse((_SRC_PATH / "config.toml.sample").read_text("utf-8"))
    config["server"]["secret_key"] = "test-secret"
    config["security"]["pepper"] = ""
    config["database"]["type"] = "sqlite"
    config["database"]["file"] = "app.db"
    config["provider"]["storage"] = "local"
    config["provider"]["caching"] = "memory"
    config["provider"]["event_bus"] = "local"
    (src_dir / "config.toml").write_text(tomlkit.dumps(config), encoding="utf-8")
    (src_dir / "config.toml.sample").write_text(
        (_SRC_PATH / "config.toml.sample").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    return src_dir


def _create_empty_database(src_dir: Path) -> None:
    _run_python(
        src_dir,
        """
from maintenance.runtime import load_database_models

load_database_models()

from include.database.session import Base, engine

Base.metadata.create_all(engine)
""",
    )


def _seed_users(src_dir: Path) -> None:
    _run_python(
        src_dir,
        """
from argon2 import PasswordHasher

from maintenance.runtime import load_database_models

load_database_models()

from include.database.session import Base, Session, engine
from include.database.models.identity import User

Base.metadata.create_all(engine)
hasher = PasswordHasher()
with Session() as session:
    for username in ("alice", "bob"):
        session.add(
            User(
                username=username,
                pass_hash=hasher.hash("OldPass123!"),
                nickname=username.title(),
                last_login=None,
                created_time=1.0,
                totp_enabled=True,
                totp_secret="JBSWY3DPEHPK3PXP",
                totp_backup_codes='["backup-code"]',
            )
        )
    session.commit()
""",
    )


def _read_user_state(src_dir: Path, password: str) -> dict:
    result = _run_python(
        src_dir,
        f"""
import json

from maintenance.runtime import load_database_models

load_database_models()

from include.database.session import Session
from include.database.models.identity import User

with Session() as session:
    data = {{}}
    for user in session.query(User).order_by(User.username):
        data[user.username] = {{
            "password_ok": user.verify_password({password!r}),
            "passwd_last_modified": user.passwd_last_modified,
            "totp_enabled": user.totp_enabled,
            "totp_secret": user.totp_secret,
            "totp_backup_codes": user.totp_backup_codes,
        }}
    print(json.dumps(data, sort_keys=True))
""",
    )
    return json.loads(result.stdout)


def _seed_permission_entries(src_dir: Path) -> None:
    _run_python(
        src_dir,
        """
import time

from maintenance.runtime import load_database_models

load_database_models()

from include.database.models.identity import (
    User,
    UserGroup,
    UserGroupPermission,
    UserPermission,
)
from include.database.session import Base, Session, engine

Base.metadata.create_all(engine)
now = time.time()
old_end = now - 31 * 24 * 60 * 60
recent_end = now - 29 * 24 * 60 * 60
with Session.begin() as session:
    user = User(username="alice", pass_hash="hash", created_time=now)
    user.rights.extend(
        [
            UserPermission(permission="old_user", granted=True, start_time=0.0, end_time=old_end),
            UserPermission(permission="recent_user", granted=True, start_time=0.0, end_time=recent_end),
            UserPermission(permission="permanent_user_revocation", granted=False, start_time=0.0, end_time=None),
        ]
    )
    group = UserGroup(group_name="staff")
    group.permissions.extend(
        [
            UserGroupPermission(permission="old_group", granted=False, start_time=0.0, end_time=old_end),
            UserGroupPermission(permission="recent_group", granted=True, start_time=0.0, end_time=recent_end),
            UserGroupPermission(permission="permanent_group_revocation", granted=False, start_time=0.0, end_time=None),
        ]
    )
    session.add_all([user, group])
""",
    )


def _read_permission_entries(src_dir: Path) -> dict:
    result = _run_python(
        src_dir,
        """
import json

from maintenance.runtime import load_database_models

load_database_models()

from include.database.models.identity import UserGroupPermission, UserPermission
from include.database.session import Session

with Session() as session:
    print(json.dumps({
        "user": [entry.permission for entry in session.query(UserPermission).order_by(UserPermission.id)],
        "group": [entry.permission for entry in session.query(UserGroupPermission).order_by(UserGroupPermission.id)],
    }, sort_keys=True))
""",
    )
    return json.loads(result.stdout)


def _seed_audit_entries(src_dir: Path, *, batch_size: int = 2) -> None:
    config_path = src_dir / "config.toml"
    config = tomlkit.parse(config_path.read_text(encoding="utf-8"))
    config["maintenance"] = {
        "audit_retention": {
            "retention_days": 365,
            "batch_size": batch_size,
        }
    }
    config_path.write_text(tomlkit.dumps(config), encoding="utf-8")
    _run_python(
        src_dir,
        """
from maintenance.runtime import load_database_models

load_database_models()

from include.database.models.identity import User
from include.database.models.operations import AuditEntry
from include.database.session import Base, Session, engine

Base.metadata.create_all(engine)
with Session.begin() as session:
    session.add(User(username="alice", pass_hash="hash", created_time=1.0))
    session.add_all(
        [
            AuditEntry(
                id="old-login",
                action="login",
                username="alice",
                target="alice",
                data={"detail": {"message": "重要记录"}},
                result=401,
                remote_address="203.0.113.10",
                logged_time=100.0,
            ),
            AuditEntry(
                id="old-update",
                action="update_document",
                username=None,
                target="document-1",
                data=None,
                result=0,
                remote_address=None,
                logged_time=150.0,
            ),
            AuditEntry(
                id="cutoff",
                action="login",
                username="alice",
                target="alice",
                data={},
                result=401,
                remote_address="203.0.113.10",
                logged_time=200.0,
            ),
            AuditEntry(
                id="new-entry",
                action="login",
                username="alice",
                target="alice",
                data={},
                result=0,
                remote_address="203.0.113.10",
                logged_time=300.0,
            ),
        ]
    )
""",
    )


def _read_audit_ids(src_dir: Path) -> list[str]:
    result = _run_python(
        src_dir,
        """
import json

from maintenance.runtime import load_database_models

load_database_models()

from include.database.models.operations import AuditEntry
from include.database.session import Session

with Session() as session:
    print(json.dumps([entry.id for entry in session.query(AuditEntry).order_by(AuditEntry.logged_time, AuditEntry.id)]))
""",
    )
    return json.loads(result.stdout)


def _read_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
