import pytest
import tomlkit
import typer

from .support import _make_src_dir, _normalize_cli_output, _run_maintain


def test_run_prints_error_after_status_exits(monkeypatch):
    from maintenance.cli import common as cli
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
    from maintenance.cli import common as cli

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


def test_deployment_commands_remove_redundant_confirmation_options(tmp_path):
    upgrade_help = _run_maintain(tmp_path, ["deployment", "upgrade", "--help"])
    downgrade_help = _run_maintain(tmp_path, ["deployment", "downgrade", "--help"])
    prune_help = _run_maintain(tmp_path, ["deployment", "prune", "--help"])
    resume_help = _run_maintain(tmp_path, ["deployment", "resume", "--help"])
    upgrade_output = _normalize_cli_output(upgrade_help.stdout + upgrade_help.stderr)
    downgrade_output = _normalize_cli_output(
        downgrade_help.stdout + downgrade_help.stderr
    )
    prune_output = _normalize_cli_output(prune_help.stdout + prune_help.stderr)
    resume_output = _normalize_cli_output(resume_help.stdout + resume_help.stderr)

    assert "--backup-confirmed" not in upgrade_output
    assert "--backup-confirmed" not in downgrade_output
    assert "--database-restored" not in resume_output
    assert "--yes" in upgrade_output
    assert "--yes" in downgrade_output
    assert "--sha256" in upgrade_output
    assert "--checksums" in upgrade_output
    assert "--dry-run" in prune_output
    assert "--yes" in prune_output


def test_deployment_upgrade_warns_only_without_external_digest(tmp_path):
    without_digest = _run_maintain(
        tmp_path,
        [
            "deployment",
            "upgrade",
            "release.zip",
            "--deployment-root",
            str(tmp_path),
            "--yes",
        ],
        check=False,
    )
    with_digest = _run_maintain(
        tmp_path,
        [
            "deployment",
            "upgrade",
            "release.zip",
            "--deployment-root",
            str(tmp_path),
            "--sha256",
            "a" * 64,
            "--yes",
        ],
        check=False,
    )

    warning = "external release package SHA-256 verification is disabled"
    assert warning in _normalize_cli_output(
        without_digest.stdout + without_digest.stderr
    )
    assert warning not in _normalize_cli_output(with_digest.stdout + with_digest.stderr)


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
