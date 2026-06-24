import json
import subprocess
from pathlib import Path

import pytest
import tomlkit
import typer

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
_SRC_PATH = _PROJECT_ROOT / "src"


def _run_maintain(cwd: Path, args: list[str], *, check: bool = True):
    result = subprocess.run(
        ["uv", "run", "--project", str(_PROJECT_ROOT), "maintain", *args],
        cwd=cwd,
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
    return src_dir


def _create_empty_database(src_dir: Path) -> None:
    _run_python(
        src_dir,
        """
from maintenance.runtime import load_database_models

load_database_models()

from include.database.handler import Base, engine

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

from include.database.handler import Base, Session, engine
from include.database.models.classic import User

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

from include.database.handler import Session
from include.database.models.classic import User

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


def test_command_rejects_non_src_workdir(tmp_path):
    result = _run_maintain(tmp_path, ["config", "fill-pepper"], check=False)

    assert result.returncode == 1
    assert "CFMS src directory" in result.stdout + result.stderr


def test_incomplete_commands_show_contextual_hints(tmp_path):
    cases = [
        (
            ["user"],
            ["Maintain users.", "reset-password", "clear-totp"],
        ),
        (
            ["config"],
            ["Maintain configuration.", "fill-pepper"],
        ),
        (
            ["backup"],
            ["Maintain backups.", "export", "import"],
        ),
        (
            ["user", "reset-password"],
            [
                "Choose the account whose password should be reset.",
                "maintain user reset-password alice",
            ],
        ),
        (
            ["user", "reset-password", "alice", "--password"],
            ["Provide the new password after --password"],
        ),
        (
            ["user", "clear-totp"],
            [
                "Choose exactly one TOTP target",
                "maintain user clear-totp --all --yes",
            ],
        ),
        (
            ["backup", "export"],
            ["Choose where the encrypted backup should be written."],
        ),
        (
            ["backup", "export", "backup.confbak", "--key-out"],
            ["Provide a file path after --key-out"],
        ),
        (
            ["backup", "info"],
            ["Provide the backup file to inspect."],
        ),
        (
            ["backup", "import"],
            [
                "Provide the encrypted backup file to import",
                "--key-file backup.key --yes",
            ],
        ),
        (
            ["backup", "import", "backup.confbak", "--yes"],
            ["Choose exactly one decryption key source"],
        ),
        (
            ["backup", "import", "backup.confbak", "--key"],
            ["Provide the base64url decryption key after --key"],
        ),
        (
            ["backup", "import", "backup.confbak", "--key-file"],
            ["Provide the path to a file containing the decryption key"],
        ),
    ]

    for args, expected_parts in cases:
        result = _run_maintain(tmp_path, args, check=False)
        output = result.stdout + result.stderr
        normalized_output = " ".join(output.replace("│", " ").split())

        assert result.returncode != 0
        for expected_part in expected_parts:
            assert " ".join(expected_part.split()) in normalized_output


def test_fill_pepper_updates_config_and_is_idempotent(tmp_path):
    src_dir = _make_src_dir(tmp_path)

    result = _run_maintain(src_dir, ["config", "fill-pepper"])
    config = tomlkit.parse((src_dir / "config.toml").read_text("utf-8"))

    assert result.returncode == 0
    assert len(config["security"]["pepper"]) == 64

    result = _run_maintain(src_dir, ["config", "fill-pepper"])

    assert "already set" in result.stdout


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


def test_backup_export_info_and_import(tmp_path):
    source_src = _make_src_dir(tmp_path, "source-src")
    target_src = _make_src_dir(tmp_path, "target-src")
    _create_empty_database(source_src)

    export_result = _run_maintain(
        source_src,
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
    assert "Backup progress" in export_result.stdout
    assert "Backup export completed" in export_result.stdout
    assert "Starting backup export" in export_result.stderr
    assert (source_src / "backup.confbak").is_file()
    assert (source_src / "backup.key").is_file()

    info_result = _run_maintain(
        source_src,
        ["backup", "info", "backup.confbak", "--verbose"],
    )

    assert "CFMS Backup" in info_result.stdout
    assert "AES-256-GCM" in info_result.stdout
    assert "Reading backup info" in info_result.stderr

    import_result = _run_maintain(
        target_src,
        [
            "backup",
            "import",
            str(source_src / "backup.confbak"),
            "--key-file",
            str(source_src / "backup.key"),
            "--yes",
            "--verbose",
        ],
    )

    assert "Backup Import" in import_result.stdout
    assert "Backup progress" in import_result.stdout
    assert "Backup import completed" in import_result.stdout
    assert "Starting backup import" in import_result.stderr
    assert (target_src / "init").is_file()
