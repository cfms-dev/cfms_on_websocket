import re

import pytest
import tomlkit

from .support import (
    _SRC_PATH,
    _make_src_dir,
    _normalize_cli_output,
    _read_user_state,
    _run_maintain,
    _seed_users,
)

pytestmark = pytest.mark.integration


def test_fill_pepper_initializes_empty_pepper(tmp_path):
    src_dir = _make_src_dir(tmp_path)

    result = _run_maintain(src_dir, ["config", "fill-pepper"])
    config = tomlkit.parse((src_dir / "config.toml").read_text("utf-8"))

    assert result.returncode == 0
    assert len(config["security"]["pepper"]) == 64


def test_fill_pepper_preserves_existing_pepper_and_config(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    config_path = src_dir / "config.toml"
    config = tomlkit.parse(config_path.read_text(encoding="utf-8"))
    config["security"]["pepper"] = "existing-pepper"
    config_path.write_text(tomlkit.dumps(config), encoding="utf-8")
    original_source = config_path.read_bytes()

    result = _run_maintain(src_dir, ["config", "fill-pepper"])

    assert "already set" in result.stdout
    assert config_path.read_bytes() == original_source


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


def test_sync_template_check_reports_missing_settings_without_writing_or_disclosing_secrets(
    tmp_path,
):
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


def test_sync_template_applies_missing_settings_and_preserves_unknown_values(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    config_path = src_dir / "config.toml"
    config = tomlkit.parse(config_path.read_text(encoding="utf-8"))
    del config["server"]["trusted_proxy_networks"]
    config["server"]["local_setting"] = "keep"
    config["server"]["secret_key"] = "must-not-be-printed"
    config_path.write_text(tomlkit.dumps(config), encoding="utf-8")
    original_source = config_path.read_bytes()

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
    backups = list(src_dir.glob("config.toml.backup-*"))
    assert len(backups) == 1
    assert backups[0].read_bytes() == original_source


def test_sync_template_check_accepts_already_synchronized_config(tmp_path):
    src_dir = _make_src_dir(tmp_path)

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

    assert result.returncode == 2
    assert "cannot be combined" in result.stdout + result.stderr


def test_reset_password_persists_explicit_password_and_requires_login_update(tmp_path):
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


def test_reset_password_persists_the_generated_password_shown_to_operator(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_users(src_dir)

    result = _run_maintain(src_dir, ["user", "reset-password", "bob"])

    assert "Generated Password" in result.stdout
    assert "Store this password safely" in result.stdout
    password_row = re.search(r"\bbob\s+(\S+)", _normalize_cli_output(result.stdout))
    assert password_row is not None, result.stdout
    generated_password = password_row.group(1)
    state = _read_user_state(src_dir, generated_password)
    assert state["bob"]["password_ok"] is True
    assert state["bob"]["passwd_last_modified"] == 0


def test_clear_totp_for_single_user_preserves_other_users(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_users(src_dir)

    _run_maintain(src_dir, ["user", "clear-totp", "alice"])
    state = _read_user_state(src_dir, "OldPass123!")

    assert state["alice"]["totp_enabled"] is False
    assert state["alice"]["totp_secret"] is None
    assert state["alice"]["totp_backup_codes"] is None
    assert state["bob"]["totp_enabled"] is True


def test_clear_totp_for_all_users_removes_secrets_and_backup_codes(tmp_path):
    src_dir = _make_src_dir(tmp_path)
    _seed_users(src_dir)

    _run_maintain(src_dir, ["user", "clear-totp", "--all", "--yes"])
    state = _read_user_state(src_dir, "OldPass123!")

    for username in ("alice", "bob"):
        assert state[username]["totp_enabled"] is False
        assert state[username]["totp_secret"] is None
        assert state[username]["totp_backup_codes"] is None


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
