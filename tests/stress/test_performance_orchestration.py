from pathlib import Path

import pytest

from tools.run_performance_comparison import build_load_command, parse_args


def test_orchestrator_accepts_only_local_disposable_target(tmp_path):
    args = parse_args(
        [
            "--baseline-ref",
            "baseline",
            "--candidate-ref",
            "candidate",
            "--output-dir",
            str(tmp_path),
        ]
    )

    assert args.target == "managed-disposable"
    assert args.environment == "local-disposable"
    assert args.repetitions == 3

    with pytest.raises(SystemExit):
        parse_args(
            [
                "--baseline-ref",
                "baseline",
                "--candidate-ref",
                "candidate",
                "--target",
                "remote",
                "--output-dir",
                str(tmp_path),
            ]
        )


def test_orchestrator_builds_secret_free_managed_command(tmp_path):
    command = build_load_command(
        Path("worktree"),
        profile="smoke",
        seed=42,
        output_path=tmp_path / "result.json",
        harness_commit="harness-commit",
        server_commit="server-commit",
        load_args=["--duration", "1s"],
    )

    assert command == [
        "uv",
        "run",
        "--locked",
        "python",
        "-m",
        "tests.stress.ws_load",
        "--profile",
        "smoke",
        "--seed",
        "42",
        "--managed-reset",
        "--harness-commit",
        "harness-commit",
        "--server-commit",
        "server-commit",
        "--output",
        str(tmp_path / "result.json"),
        "--duration",
        "1s",
    ]
    serialized = " ".join(command).lower()
    assert "password" not in serialized
    assert "token" not in serialized


def test_orchestrator_rejects_credential_load_arguments(tmp_path):
    with pytest.raises(SystemExit):
        parse_args(
            [
                "--baseline-ref",
                "baseline",
                "--candidate-ref",
                "candidate",
                "--output-dir",
                str(tmp_path),
                "--load-arg=--password-env",
            ]
        )
