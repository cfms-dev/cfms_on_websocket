from io import StringIO

import pytest
import tomlkit
import typer
from rich.console import Console

from .support import _make_src_dir, _normalize_cli_output, _run_maintain


@pytest.mark.unit
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


@pytest.mark.unit
@pytest.mark.parametrize("width", [80, 120], ids=["narrow-console", "wide-console"])
def test_backup_progress_renders_long_description_without_wrapping_on_error_console(
    monkeypatch, width
):
    from maintenance.cli import common as cli

    output = StringIO()
    console = Console(file=output, width=width, force_terminal=False, color_system=None)
    monkeypatch.setattr(cli, "error_console", console)
    progress = cli._build_backup_progress()
    progress.add_task(
        "Restoring database rows " + "large table " * 20,
        start=False,
        total=10,
        completed=3,
    )

    progress.console.print(progress.get_renderable())

    lines = output.getvalue().splitlines()
    assert len(lines) == 1
    assert lines[0].startswith("Restoring database rows")
    assert lines[0].rstrip().endswith("…")
    assert len(lines[0]) <= width


@pytest.mark.integration
def test_command_finds_server_root_from_deployment_root(tmp_path):
    src_dir = _make_src_dir(tmp_path)

    result = _run_maintain(tmp_path, ["config", "fill-pepper"])
    config = tomlkit.parse((src_dir / "config.toml").read_text(encoding="utf-8"))

    assert result.returncode == 0
    assert len(config["security"]["pepper"]) == 64


@pytest.mark.integration
def test_command_supports_flat_bundle_and_nested_workdir(tmp_path):
    server_root = _make_src_dir(tmp_path, "release-bundle")
    nested_workdir = server_root / "content" / "operations"
    nested_workdir.mkdir()

    result = _run_maintain(nested_workdir, ["config", "fill-pepper"])
    config = tomlkit.parse((server_root / "config.toml").read_text(encoding="utf-8"))

    assert result.returncode == 0
    assert len(config["security"]["pepper"]) == 64


@pytest.mark.integration
def test_command_rejects_unrelated_workdir(tmp_path):
    unrelated = tmp_path / "unrelated"
    unrelated.mkdir()

    result = _run_maintain(unrelated, ["config", "fill-pepper"], check=False)

    assert result.returncode == 1
    assert "Unable to locate a CFMS server root" in result.stdout + result.stderr


@pytest.mark.integration
@pytest.mark.parametrize(
    ("command", "present_options", "absent_options"),
    [
        pytest.param(
            "upgrade",
            ("--yes", "--sha256", "--checksums"),
            ("--backup-confirmed",),
            id="upgrade",
        ),
        pytest.param("downgrade", ("--yes",), ("--backup-confirmed",), id="downgrade"),
        pytest.param("prune", ("--dry-run", "--yes"), (), id="prune"),
        pytest.param("resume", (), ("--database-restored",), id="resume"),
    ],
)
def test_deployment_command_help_exposes_current_confirmation_options(
    tmp_path, command, present_options, absent_options
):
    result = _run_maintain(tmp_path, ["deployment", command, "--help"])
    output = _normalize_cli_output(result.stdout + result.stderr)

    for option in present_options:
        assert option in output
    for option in absent_options:
        assert option not in output


@pytest.mark.integration
@pytest.mark.parametrize(
    ("digest_args", "warns"),
    [
        pytest.param([], True, id="without-digest"),
        pytest.param(["--sha256", "a" * 64], False, id="with-digest"),
    ],
)
def test_deployment_upgrade_warns_only_without_external_digest(
    tmp_path, digest_args, warns
):
    result = _run_maintain(
        tmp_path,
        [
            "deployment",
            "upgrade",
            "release.zip",
            "--deployment-root",
            str(tmp_path),
            *digest_args,
            "--yes",
        ],
        check=False,
    )

    warning = "external release package SHA-256 verification is disabled"
    output = _normalize_cli_output(result.stdout + result.stderr)
    assert (warning in output) is warns


@pytest.mark.integration
def test_backup_import_requires_exactly_one_key_source(tmp_path):
    result = _run_maintain(
        tmp_path,
        ["backup", "import", "backup.confbak", "--yes"],
        check=False,
    )

    assert result.returncode == 2
    assert "Choose exactly one decryption key source" in _normalize_cli_output(
        result.stdout + result.stderr
    )
