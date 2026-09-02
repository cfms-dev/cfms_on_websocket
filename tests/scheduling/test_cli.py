from typer.testing import CliRunner

from include.scheduling.cli import app


def test_jobs_cli_exposes_scheduler_and_worker_commands():
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "scheduler" in result.stdout
    assert "worker" in result.stdout
