import json
import re
import subprocess
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
            ["Maintain configuration.", "fill-pepper", "sync-template"],
        ),
        (
            ["backup"],
            ["Maintain backups.", "export", "import"],
        ),
        (
            ["user", "reset-password"],
            [
                "Account whose password should be reset.",
                "maintain user reset-password alice",
            ],
        ),
        (
            ["user", "reset-password", "alice", "--password"],
            ["Option '--password' requires an argument."],
        ),
        (
            ["user", "clear-totp"],
            [
                "Clear TOTP state for one user or all users.",
                "maintain user clear-totp --all --yes",
            ],
        ),
        (
            ["backup", "export"],
            ["Where the encrypted backup should be written."],
        ),
        (
            ["backup", "export", "backup.confbak", "--key-out"],
            ["Option '--key-out' requires an argument."],
        ),
        (
            ["backup", "info"],
            ["Backup file to inspect."],
        ),
        (
            ["backup", "import"],
            [
                "Backup file to import",
                "--key-file backup.key --yes",
            ],
        ),
        (
            ["backup", "import", "backup.confbak", "--yes"],
            ["Choose exactly one decryption key source"],
        ),
        (
            ["backup", "import", "backup.confbak", "--key"],
            ["Option '--key' requires an argument."],
        ),
        (
            ["backup", "import", "backup.confbak", "--key-file"],
            ["Option '--key-file' requires an argument."],
        ),
    ]

    for args, expected_parts in cases:
        result = _run_maintain(tmp_path, args, check=False)
        output = result.stdout + result.stderr
        normalized_output = _normalize_cli_output(output)

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
    assert "Backup export completed" in export_result.stderr
    assert "Starting backup export" in export_result.stderr
    assert "Adding archive member" in export_result.stderr
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
    assert "Backup import completed" in import_result.stderr
    assert "Starting backup import" in import_result.stderr
    assert (target_src / "init").is_file()
