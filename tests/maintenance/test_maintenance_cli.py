import datetime as dt
import json
import re
import shutil
import subprocess
import zipfile
from pathlib import Path

import pytest
import tomlkit
import typer

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_SRC_PATH = _PROJECT_ROOT / "src"
_ANSI_ESCAPE_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
_BOX_DRAWING_RE = re.compile(r"[\u2500-\u257F]")


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


_AUDIT_CUTOFF = dt.datetime.fromtimestamp(200, dt.UTC).isoformat()


def test_run_prints_error_after_status_exits(monkeypatch):
    from maintenance import cli
    from maintenance.operations.exceptions import MaintenanceOperationError

    active = {"status": False}
    events: list[str] = []

    class FakeStatus:
        def __enter__(self):
            active["status"] = True
            events.append("enter")
            return self

        def __exit__(self, exc_type, exc, traceback):
            events.append("exit")
            active["status"] = False
            return False

    def fake_status(message: str, *, spinner: str):
        assert message == "Working..."
        assert spinner == "dots"
        return FakeStatus()

    def fake_print_error(message: str) -> None:
        assert active["status"] is False
        events.append(f"error:{message}")

    def fail() -> None:
        raise MaintenanceOperationError("boom")

    monkeypatch.setattr(cli.console, "status", fake_status)
    monkeypatch.setattr(cli, "_print_error", fake_print_error)

    with pytest.raises(typer.Exit) as exc_info:
        cli._run(fail, status="Working...")

    assert exc_info.value.exit_code == 1
    assert events == ["enter", "exit", "error:boom"]


def test_backup_progress_shares_verbose_log_console():
    from maintenance import cli

    progress = cli._build_backup_progress()
    description_column = progress.columns[1].get_table_column()

    assert progress.console is cli.error_console
    assert description_column.no_wrap is True
    assert description_column.overflow == "ellipsis"


def test_command_finds_server_root_from_deployment_root(tmp_path):
    src_dir = _make_src_dir(tmp_path)

    result = _run_maintain(tmp_path, ["config", "fill-pepper"])
    config = tomlkit.parse((src_dir / "config.toml").read_text(encoding="utf-8"))

    assert result.returncode == 0
    assert len(config["security"]["pepper"]) == 64


def test_command_supports_flat_bundle_and_nested_workdir(tmp_path):
    server_root = _make_src_dir(tmp_path, "release-bundle")
    nested_workdir = server_root / "content" / "operations"
    nested_workdir.mkdir()

    result = _run_maintain(nested_workdir, ["config", "fill-pepper"])
    config = tomlkit.parse((server_root / "config.toml").read_text(encoding="utf-8"))

    assert result.returncode == 0
    assert len(config["security"]["pepper"]) == 64


def test_command_rejects_unrelated_workdir(tmp_path):
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()

    result = _run_maintain(unrelated, ["config", "fill-pepper"], check=False)

    assert result.returncode == 1
    assert "Unable to locate a CFMS server root" in result.stdout + result.stderr


def test_backup_import_requires_exactly_one_key_source(tmp_path):
    result = _run_maintain(
        tmp_path,
        ["backup", "import", "backup.confbak", "--yes"],
        check=False,
    )

    assert result.returncode != 0
    assert "Choose exactly one decryption key source" in _normalize_cli_output(
        result.stdout + result.stderr
    )


def test_fill_pepper_updates_config_and_is_idempotent(tmp_path):
    src_dir = _make_src_dir(tmp_path)

    result = _run_maintain(src_dir, ["config", "fill-pepper"])
    config = tomlkit.parse((src_dir / "config.toml").read_text("utf-8"))

    assert result.returncode == 0
    assert len(config["security"]["pepper"]) == 64

    result = _run_maintain(src_dir, ["config", "fill-pepper"])

    assert "already set" in result.stdout


def test_explicit_template_path_is_relative_to_invocation_directory(tmp_path):
    _make_src_dir(tmp_path)
    template_path = tmp_path / "operator-template.toml"
    template_path.write_text(
        (_SRC_PATH / "config.toml.sample").read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    result = _run_maintain(
        tmp_path,
        [
            "config",
            "sync-template",
            "--template",
            template_path.name,
            "--check",
        ],
    )

    assert result.returncode == 0


def test_default_template_path_comes_from_server_root(tmp_path):
    _make_src_dir(tmp_path)
    (tmp_path / "config.toml.sample").write_text("invalid = true\n", encoding="utf-8")

    result = _run_maintain(
        tmp_path,
        ["config", "sync-template", "--check"],
    )

    assert result.returncode == 0


def test_sync_template_check_then_apply_preserves_unknown_settings(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    config_path = src_dir / "config.toml"
    config = tomlkit.parse(config_path.read_text(encoding="utf-8"))
    del config["server"]["trusted_proxy_networks"]
    config["server"]["local_setting"] = "keep"
    config["server"]["secret_key"] = "must-not-be-printed"
    config_path.write_text(tomlkit.dumps(config), encoding="utf-8")
    original_source = config_path.read_text(encoding="utf-8")

    check_result = _run_maintain(
        src_dir,
        ["config", "sync-template", "--check"],
        check=False,
    )

    assert check_result.returncode == 1
    assert config_path.read_text(encoding="utf-8") == original_source
    assert list(src_dir.glob("config.toml.backup-*")) == []
    assert "must-not-be-printed" not in check_result.stdout + check_result.stderr

    apply_result = _run_maintain(
        src_dir,
        ["config", "sync-template", "--yes"],
    )
    synchronized = tomlkit.parse(config_path.read_text(encoding="utf-8"))

    assert synchronized["server"]["trusted_proxy_networks"] == [
        "127.0.0.1/32",
        "::1/128",
    ]
    assert synchronized["server"]["local_setting"] == "keep"
    assert "must-not-be-printed" not in apply_result.stdout + apply_result.stderr
    assert len(list(src_dir.glob("config.toml.backup-*"))) == 1

    synchronized_check = _run_maintain(
        src_dir,
        ["config", "sync-template", "--check"],
    )

    assert "is synchronized" in synchronized_check.stdout


def test_sync_template_interactively_removes_unknown_setting(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    config_path = src_dir / "config.toml"
    config = tomlkit.parse(config_path.read_text(encoding="utf-8"))
    config["server"]["old_setting"] = 1
    config_path.write_text(tomlkit.dumps(config), encoding="utf-8")

    result = _run_maintain(
        src_dir,
        ["config", "sync-template"],
        input_text="y\ny\n",
    )
    synchronized = tomlkit.parse(config_path.read_text(encoding="utf-8"))

    assert "old_setting" not in synchronized["server"]
    assert "server.old_setting" in result.stdout


def test_sync_template_rejects_conflicting_options(tmp_path):
    src_dir = _make_src_dir(tmp_path)

    result = _run_maintain(
        src_dir,
        [
            "config",
            "sync-template",
            "--prune",
            "--remove",
            "server.old_setting",
        ],
        check=False,
    )

    assert result.returncode != 0
    assert "cannot be combined" in result.stdout + result.stderr


def test_reset_password_updates_hash_and_can_generate_password(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_users(src_dir)

    result = _run_maintain(
        src_dir,
        ["user", "reset-password", "alice", "--password", "NewPass123!"],
    )
    state = _read_user_state(src_dir, "NewPass123!")

    assert "updated" in result.stdout
    assert state["alice"]["password_ok"] is True
    assert state["alice"]["passwd_last_modified"] == 0

    result = _run_maintain(src_dir, ["user", "reset-password", "bob"])

    assert "Generated Password" in result.stdout
    assert "Store this password safely" in result.stdout


def test_clear_totp_for_single_user_and_all_users(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_users(src_dir)

    _run_maintain(src_dir, ["user", "clear-totp", "alice"])
    state = _read_user_state(src_dir, "OldPass123!")

    assert state["alice"]["totp_enabled"] is False
    assert state["alice"]["totp_secret"] is None
    assert state["alice"]["totp_backup_codes"] is None
    assert state["bob"]["totp_enabled"] is True

    _run_maintain(src_dir, ["user", "clear-totp", "--all", "--yes"])
    state = _read_user_state(src_dir, "OldPass123!")

    assert state["alice"]["totp_enabled"] is False
    assert state["bob"]["totp_enabled"] is False


def test_clear_totp_all_abort_uses_typer_abort_and_keeps_users(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_users(src_dir)

    result = _run_maintain(
        src_dir,
        ["user", "clear-totp", "--all"],
        check=False,
        input_text="n\n",
    )
    state = _read_user_state(src_dir, "OldPass123!")

    assert result.returncode == 1
    assert "Aborted." in result.stderr
    assert state["alice"]["totp_enabled"] is True
    assert state["bob"]["totp_enabled"] is True


def test_permission_purge_dry_run_confirmation_and_idempotency(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_permission_entries(src_dir)

    dry_run = _run_maintain(
        src_dir,
        ["permission", "purge-expired", "--dry-run"],
    )
    dry_run_output = _normalize_cli_output(dry_run.stdout)

    assert "User permission entries 1" in dry_run_output
    assert "Group permission entries 1" in dry_run_output
    assert _read_permission_entries(src_dir) == {
        "user": ["old_user", "recent_user", "permanent_user_revocation"],
        "group": ["old_group", "recent_group", "permanent_group_revocation"],
    }

    aborted = _run_maintain(
        src_dir,
        ["permission", "purge-expired"],
        check=False,
        input_text="n\n",
    )

    assert aborted.returncode == 1
    assert "Aborted." in aborted.stderr
    assert len(_read_permission_entries(src_dir)["user"]) == 3
    assert len(_read_permission_entries(src_dir)["group"]) == 3

    purged = _run_maintain(
        src_dir,
        ["permission", "purge-expired", "--yes"],
    )

    assert "Purged Permission Entries" in purged.stdout
    assert _read_permission_entries(src_dir) == {
        "user": ["recent_user", "permanent_user_revocation"],
        "group": ["recent_group", "permanent_group_revocation"],
    }

    repeated = _run_maintain(
        src_dir,
        ["permission", "purge-expired", "--yes"],
    )

    assert "No expired permission entries are eligible" in repeated.stdout


def test_audit_export_filters_orders_and_refuses_overwrite(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_audit_entries(src_dir)
    output_path = tmp_path / "important.jsonl"

    result = _run_maintain(
        tmp_path,
        [
            "audit",
            "export",
            output_path.name,
            "--before",
            _AUDIT_CUTOFF,
            "--action",
            "update_document",
            "--action",
            "login",
            "--result",
            "401",
            "--username",
            "alice",
            "--target",
            "alice",
            "--remote-address",
            "203.0.113.10",
        ],
    )
    rows = _read_jsonl(output_path)

    assert "Records" in result.stdout
    assert [row["id"] for row in rows] == ["old-login"]
    assert rows[0] == {
        "action": "login",
        "data": {"detail": {"message": "重要记录"}},
        "id": "old-login",
        "logged_time": 100.0,
        "remote_address": "203.0.113.10",
        "result": 401,
        "target": "alice",
        "username": "alice",
    }

    repeated = _run_maintain(
        tmp_path,
        ["audit", "export", output_path.name, "--before", _AUDIT_CUTOFF],
        check=False,
    )

    assert repeated.returncode == 1
    assert "already exists" in repeated.stdout + repeated.stderr
    assert _read_jsonl(output_path) == rows


def test_audit_purge_dry_run_abort_archive_and_idempotency(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_audit_entries(src_dir, batch_size=1)
    archive_path = src_dir / "expired.jsonl"

    dry_run = _run_maintain(
        src_dir,
        ["audit", "purge", "--dry-run", "--before", _AUDIT_CUTOFF],
    )
    dry_run_output = _normalize_cli_output(dry_run.stdout)

    assert "Total 2" in dry_run_output
    assert "login 1" in dry_run_output
    assert "update_document 1" in dry_run_output
    assert "401 1" in dry_run_output
    assert not archive_path.exists()
    assert _read_audit_ids(src_dir) == [
        "old-login",
        "old-update",
        "cutoff",
        "new-entry",
    ]

    aborted = _run_maintain(
        src_dir,
        [
            "audit",
            "purge",
            "--archive",
            str(archive_path),
            "--before",
            _AUDIT_CUTOFF,
        ],
        check=False,
        input_text="n\n",
    )

    assert aborted.returncode == 1
    assert "Aborted." in aborted.stderr
    assert not archive_path.exists()

    archive_path.write_text("existing archive", encoding="utf-8")
    blocked = _run_maintain(
        src_dir,
        [
            "audit",
            "purge",
            "--archive",
            str(archive_path),
            "--before",
            _AUDIT_CUTOFF,
            "--yes",
        ],
        check=False,
    )

    assert blocked.returncode == 1
    assert "already exists" in blocked.stdout + blocked.stderr
    assert archive_path.read_text(encoding="utf-8") == "existing archive"
    assert _read_audit_ids(src_dir) == [
        "old-login",
        "old-update",
        "cutoff",
        "new-entry",
    ]
    archive_path.unlink()

    purged = _run_maintain(
        src_dir,
        [
            "audit",
            "purge",
            "--archive",
            str(archive_path),
            "--before",
            _AUDIT_CUTOFF,
            "--yes",
        ],
    )

    archived_rows = _read_jsonl(archive_path)
    assert [row["id"] for row in archived_rows] == [
        "old-login",
        "old-update",
    ]
    assert archived_rows[1]["username"] is None
    assert archived_rows[1]["data"] is None
    assert archived_rows[1]["remote_address"] is None
    assert "Archived" in purged.stdout
    assert "Deleted" in purged.stdout
    assert _read_audit_ids(src_dir) == ["cutoff", "new-entry"]

    repeated_archive = src_dir / "repeated.jsonl"
    repeated = _run_maintain(
        src_dir,
        [
            "audit",
            "purge",
            "--archive",
            str(repeated_archive),
            "--before",
            _AUDIT_CUTOFF,
            "--yes",
        ],
    )

    assert "No audit entries are eligible" in repeated.stdout
    assert not repeated_archive.exists()


def test_audit_purge_requires_archive_and_timezone(tmp_path):
    src_dir = _make_src_dir(tmp_path)

    missing_archive = _run_maintain(
        src_dir,
        ["audit", "purge", "--before", _AUDIT_CUTOFF, "--yes"],
        check=False,
    )
    naive_time = _run_maintain(
        src_dir,
        ["audit", "purge", "--dry-run", "--before", "2026-01-01T00:00:00"],
        check=False,
    )
    invalid_time = _run_maintain(
        src_dir,
        ["audit", "purge", "--dry-run", "--before", "not-a-time"],
        check=False,
    )
    missing_archive_error = _normalize_cli_output(missing_archive.stderr)
    naive_time_error = _normalize_cli_output(naive_time.stderr)
    invalid_time_error = _normalize_cli_output(invalid_time.stderr)

    assert missing_archive.returncode == 2
    assert "--archive is required" in missing_archive_error
    assert naive_time.returncode == 2
    assert "must include a timezone" in naive_time_error
    assert invalid_time.returncode == 2
    assert "must be an ISO 8601 timestamp" in invalid_time_error


def test_audit_purge_partial_failure_keeps_complete_archive(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_audit_entries(src_dir, batch_size=1)
    archive_path = src_dir / "partial.jsonl"
    _run_python(
        src_dir,
        '''
from maintenance.runtime import load_database_models

load_database_models()

from include.database.session import engine

with engine.begin() as connection:
    connection.exec_driver_sql(
        """CREATE TRIGGER reject_old_update
        BEFORE DELETE ON audit_entries
        WHEN OLD.id = 'old-update'
        BEGIN
            SELECT RAISE(ABORT, 'simulated audit deletion failure');
        END"""
    )
''',
    )

    result = _run_maintain(
        src_dir,
        [
            "audit",
            "purge",
            "--archive",
            str(archive_path),
            "--before",
            _AUDIT_CUTOFF,
            "--yes",
        ],
        check=False,
    )

    assert result.returncode == 1
    assert "after deleting 1 of 2 archived entries" in result.stdout + result.stderr
    assert [row["id"] for row in _read_jsonl(archive_path)] == [
        "old-login",
        "old-update",
    ]
    assert _read_audit_ids(src_dir) == ["old-update", "cutoff", "new-entry"]


def test_audit_purge_rejects_changed_candidate_count_before_deletion(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_audit_entries(src_dir)
    archive_path = src_dir / "changed.jsonl"
    result = _run_python(
        src_dir,
        f"""
import datetime as dt

from maintenance.operations import (
    MaintenanceOperationError,
    create_audit_selection,
    purge_audit_entries,
)

selection = create_audit_selection(
    before=dt.datetime.fromisoformat({_AUDIT_CUTOFF!r})
)
try:
    purge_audit_entries({str(archive_path)!r}, selection, expected_count=1)
except MaintenanceOperationError as exc:
    print(exc)
else:
    raise AssertionError("candidate-count change was not rejected")
""",
    )

    assert "Expected 1, archived 2" in result.stdout
    assert [row["id"] for row in _read_jsonl(archive_path)] == [
        "old-login",
        "old-update",
    ]
    assert _read_audit_ids(src_dir) == [
        "old-login",
        "old-update",
        "cutoff",
        "new-entry",
    ]


def test_backup_import_abort_uses_typer_abort_before_operation(tmp_path):
    src_dir = _make_src_dir(tmp_path)

    result = _run_maintain(
        src_dir,
        ["backup", "import", "missing.confbak", "--key", "abc"],
        check=False,
        input_text="n\n",
    )

    assert result.returncode == 1
    assert "Aborted." in result.stderr
    assert not (src_dir / "init").exists()


def test_extension_cli_lists_installs_and_enables(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    shutil.copytree(
        _SRC_PATH / "include" / "extensions",
        src_dir / "include" / "extensions",
    )
    package = tmp_path / "cli_extension.zip"
    with zipfile.ZipFile(package, "w") as archive:
        archive.writestr(
            "manifest.toml",
            """manifest_version = 2

[extension]
identifier = "cli_extension"
name = "CLI Extension"
version = "1.0.0"
authors = ["Test Author"]
license = "Apache-2.0"
""",
        )
        archive.writestr("_extension.py", "raise RuntimeError('must not import')\n")

    listed = _run_maintain(tmp_path, ["extension", "list"])
    aborted = _run_maintain(
        tmp_path,
        ["extension", "install", package.name],
        check=False,
        input_text="n\n",
    )
    assert aborted.returncode == 1
    assert "Aborted" in aborted.stderr
    assert not (src_dir / "include" / "extensions" / "cli_extension").exists()

    installed = _run_maintain(
        tmp_path,
        ["extension", "install", package.name, "--yes"],
    )
    enabled = _run_maintain(
        tmp_path,
        ["extension", "enable", "cli_extension", "--yes"],
    )
    info = _run_maintain(tmp_path, ["extension", "info", "cli_extension"])

    assert "builtin" in listed.stdout
    assert "remains disabled" in _normalize_cli_output(installed.stdout)
    assert "Restart any running server" in _normalize_cli_output(enabled.stdout)
    assert "CLI Extension" in _normalize_cli_output(info.stdout)
    config = tomlkit.parse((src_dir / "config.toml").read_text(encoding="utf-8"))
    assert config["extensions"]["enabled"] == ["cli_extension"]


def test_backup_export_interactive_rejects_other_arguments(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    cases = [
        ["backup", "export", "-i", "backup.confbak"],
        ["backup", "export", "-i", "--key-out", "backup.key"],
        ["backup", "export", "-i", "--verbose"],
    ]

    for args in cases:
        result = _run_maintain(src_dir, args, check=False)
        output = _normalize_cli_output(result.stdout + result.stderr)

        assert result.returncode != 0
        assert "Interactive export must be invoked" in output


def test_backup_export_interactive_wizard_and_import(tmp_path):
    source_src = _make_src_dir(tmp_path, "interactive-source")
    target_src = _make_src_dir(tmp_path, "interactive-target")
    _create_empty_database(source_src)

    input_text = "\n\n\n\n\ninteractive.confbak\nfile\ninteractive.key\ny\n"
    export_result = _run_maintain(
        source_src,
        ["backup", "export", "-i"],
        input_text=input_text,
    )

    assert "Backup Wizard" in export_result.stdout
    assert "Backup Export Summary" in export_result.stdout
    assert (source_src / "interactive.confbak").is_file()
    assert (source_src / "interactive.key").is_file()
    key_text = (source_src / "interactive.key").read_text(encoding="utf-8").strip()
    key_data = key_text.replace("-", "")
    assert len(key_data) == 52
    assert not set(key_data) & set("01OILl")

    import_result = _run_maintain(
        target_src,
        [
            "backup",
            "import",
            str(source_src / "interactive.confbak"),
            "--key-file",
            str(source_src / "interactive.key"),
            "--yes",
        ],
    )

    assert "Backup Import" in import_result.stdout
    assert (target_src / "init").is_file()


def test_backup_export_info_and_import(tmp_path):
    source_src = _make_src_dir(tmp_path, "source-src")
    target_src = _make_src_dir(tmp_path, "target-src")
    source_workdir = source_src / "operator"
    target_workdir = target_src / "operator"
    source_workdir.mkdir()
    target_workdir.mkdir()
    _create_empty_database(source_src)

    export_result = _run_maintain(
        source_workdir,
        [
            "backup",
            "export",
            "backup.confbak",
            "--key-out",
            "backup.key",
            "--verbose",
        ],
    )

    assert "Backup Export" in export_result.stdout
    assert "Backup export completed" in export_result.stderr
    assert "Starting backup export" in export_result.stderr
    assert "Adding archive member" in export_result.stderr
    assert (source_workdir / "backup.confbak").is_file()
    assert (source_workdir / "backup.key").is_file()
    assert not (source_src / "backup.confbak").exists()

    info_result = _run_maintain(
        source_workdir,
        ["backup", "info", "backup.confbak", "--verbose"],
    )

    assert "CFMS Backup" in info_result.stdout
    assert "AES-256-GCM" in info_result.stdout
    assert "Reading backup info" in info_result.stderr

    import_result = _run_maintain(
        target_workdir,
        [
            "backup",
            "import",
            str(Path("..", "..", "source-src", "operator", "backup.confbak")),
            "--key-file",
            str(Path("..", "..", "source-src", "operator", "backup.key")),
            "--yes",
            "--verbose",
        ],
    )

    assert "Backup Import" in import_result.stdout
    assert "Backup import completed" in import_result.stderr
    assert "Starting backup import" in import_result.stderr
    assert (target_src / "init").is_file()
