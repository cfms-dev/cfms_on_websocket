import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path

HARNESS_PATHS = (
    "tests/__init__.py",
    "tests/stress",
    "tests/support/__init__.py",
    "tests/support/client.py",
    "tests/support/config.py",
    "tests/support/server.py",
)


def _positive_int(value: str) -> int:
    number = int(value)
    if number <= 0:
        raise argparse.ArgumentTypeError("value must be positive")
    return number


def _fraction(value: str) -> float:
    number = float(value)
    if not 0 <= number < 1:
        raise argparse.ArgumentTypeError("value must be between 0 and 1")
    return number


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run reproducible baseline and candidate CFMS performance tests"
    )
    parser.add_argument(
        "--baseline-ref", default=os.environ.get("CFMS_PERF_BASELINE_REF")
    )
    parser.add_argument(
        "--candidate-ref", default=os.environ.get("CFMS_PERF_CANDIDATE_REF")
    )
    parser.add_argument(
        "--harness-ref",
        help="Harness revision; defaults to candidate-ref",
    )
    parser.add_argument(
        "--profile", default=os.environ.get("CFMS_PERF_PROFILE", "smoke")
    )
    parser.add_argument(
        "--target",
        default=os.environ.get("CFMS_PERF_TARGET", "managed-disposable"),
    )
    parser.add_argument(
        "--environment",
        default=os.environ.get("CFMS_PERF_ENVIRONMENT", "local-disposable"),
    )
    parser.add_argument(
        "--repetitions",
        type=_positive_int,
        default=os.environ.get("CFMS_PERF_REPETITIONS", "3"),
    )
    parser.add_argument(
        "--max-regression",
        type=_fraction,
        default=os.environ.get("CFMS_PERF_MAX_REGRESSION", "0.10"),
    )
    parser.add_argument("--seed", type=int, default=20260908)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument(
        "--load-arg",
        action="append",
        default=[],
        help="Additional non-secret ws_load argument; repeat for each token",
    )
    parser.add_argument("--keep-worktrees", action="store_true")
    args = parser.parse_args(argv)
    if not args.baseline_ref or not args.candidate_ref:
        parser.error("baseline and candidate refs are required")
    if args.target != "managed-disposable":
        parser.error(
            "only target managed-disposable is implemented; remote deployment "
            "details require project-owner configuration"
        )
    if args.environment != "local-disposable":
        parser.error("managed-disposable requires environment local-disposable")
    forbidden = {"--password-env", "--username", "--accounts-file"}
    if forbidden.intersection(args.load_arg):
        parser.error("credentials cannot be passed through --load-arg")
    return args


def _run_git(repo_root: Path, *arguments: str) -> str:
    completed = subprocess.run(
        ["git", *arguments],
        cwd=repo_root,
        check=True,
        capture_output=True,
        text=True,
    )
    return completed.stdout.strip()


def resolve_commit(repo_root: Path, revision: str) -> str:
    return _run_git(repo_root, "rev-parse", "--verify", f"{revision}^{{commit}}")


def _harness_files(repo_root: Path, harness_commit: str) -> list[str]:
    output = _run_git(
        repo_root,
        "ls-tree",
        "-r",
        "--name-only",
        harness_commit,
        "--",
        *HARNESS_PATHS,
    )
    files = [line for line in output.splitlines() if line]
    required = {
        "tests/stress/ws_load.py",
        "tests/stress/load_config.py",
        "tests/stress/load_metrics.py",
        "tests/stress/profiles.toml",
        "tests/support/client.py",
    }
    missing = required - set(files)
    if missing:
        raise RuntimeError(
            f"harness revision is missing required files: {sorted(missing)}"
        )
    return files


def materialize_harness(
    repo_root: Path,
    worktree: Path,
    harness_commit: str,
    harness_files: list[str],
) -> None:
    for relative_path in harness_files:
        completed = subprocess.run(
            ["git", "show", f"{harness_commit}:{relative_path}"],
            cwd=repo_root,
            check=True,
            capture_output=True,
        )
        destination = worktree / relative_path
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(completed.stdout)


def build_load_command(
    worktree: Path,
    *,
    profile: str,
    seed: int,
    output_path: Path,
    harness_commit: str,
    server_commit: str,
    load_args: list[str],
) -> list[str]:
    return [
        "uv",
        "run",
        "--locked",
        "python",
        "-m",
        "tests.stress.ws_load",
        "--profile",
        profile,
        "--seed",
        str(seed),
        "--managed-reset",
        "--harness-commit",
        harness_commit,
        "--server-commit",
        server_commit,
        "--output",
        str(output_path),
        *load_args,
    ]


def _copy_server_logs(worktree: Path, destination: Path) -> None:
    for relative_path in (Path("test_logs"), Path("src/content/logs")):
        source = worktree / relative_path
        if source.exists():
            shutil.copytree(
                source,
                destination / relative_path,
                dirs_exist_ok=True,
            )


def _remove_disposable_worktree(
    repo_root: Path, worktree: Path, temporary_root: Path
) -> None:
    resolved_worktree = worktree.resolve()
    resolved_root = temporary_root.resolve()
    if not resolved_worktree.is_relative_to(resolved_root):
        raise RuntimeError(f"refusing to remove worktree outside {resolved_root}")
    subprocess.run(
        ["git", "worktree", "remove", "--force", str(resolved_worktree)],
        cwd=repo_root,
        check=True,
    )


def _write_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    temporary.replace(path)


def run_comparison(args: argparse.Namespace) -> int:
    repo_root = Path(__file__).resolve().parents[1]
    baseline_commit = resolve_commit(repo_root, args.baseline_ref)
    candidate_commit = resolve_commit(repo_root, args.candidate_ref)
    harness_commit = resolve_commit(repo_root, args.harness_ref or args.candidate_ref)
    harness_files = _harness_files(repo_root, harness_commit)
    output_dir = args.output_dir.resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "schema_version": 1,
        "started_at": datetime.now(UTC).isoformat(),
        "baseline_ref": args.baseline_ref,
        "baseline_commit": baseline_commit,
        "candidate_ref": args.candidate_ref,
        "candidate_commit": candidate_commit,
        "harness_commit": harness_commit,
        "profile": args.profile,
        "target": args.target,
        "environment": args.environment,
        "repetitions": args.repetitions,
        "random_seeds": [args.seed + index for index in range(args.repetitions)],
        "max_regression": args.max_regression,
    }
    _write_json(output_dir / "manifest.json", manifest)

    temporary_root = Path(tempfile.mkdtemp(prefix="cfms-performance-worktrees-"))
    worktrees: list[Path] = []
    try:
        revisions = (
            ("baseline", baseline_commit),
            ("candidate", candidate_commit),
        )
        for label, server_commit in revisions:
            worktree = temporary_root / label
            subprocess.run(
                ["git", "worktree", "add", "--detach", str(worktree), server_commit],
                cwd=repo_root,
                check=True,
            )
            worktrees.append(worktree)
            materialize_harness(
                repo_root,
                worktree,
                harness_commit,
                harness_files,
            )
            install = subprocess.run(
                ["uv", "sync", "--locked", "--dev"],
                cwd=worktree,
                capture_output=True,
                text=True,
            )
            label_output = output_dir / label
            label_output.mkdir(parents=True, exist_ok=True)
            (label_output / "environment.log").write_text(
                install.stdout + install.stderr, encoding="utf-8"
            )
            if install.returncode:
                raise RuntimeError(f"{label} environment setup failed")

            for run_index in range(args.repetitions):
                result_path = label_output / f"run-{run_index + 1}.json"
                command = build_load_command(
                    worktree,
                    profile=args.profile,
                    seed=args.seed + run_index,
                    output_path=result_path,
                    harness_commit=harness_commit,
                    server_commit=server_commit,
                    load_args=args.load_arg,
                )
                completed = subprocess.run(
                    command,
                    cwd=worktree,
                    capture_output=True,
                    text=True,
                )
                (label_output / f"run-{run_index + 1}.log").write_text(
                    completed.stdout + completed.stderr,
                    encoding="utf-8",
                )
                _copy_server_logs(
                    worktree,
                    label_output / "server-logs" / f"run-{run_index + 1}",
                )
                if completed.returncode:
                    raise RuntimeError(
                        f"{label} performance run {run_index + 1} failed"
                    )

        report_path = output_dir / "comparison.json"
        comparison = subprocess.run(
            [
                sys.executable,
                str(repo_root / "tools/compare_upload_benchmarks.py"),
                str(output_dir / "baseline"),
                str(output_dir / "candidate"),
                "--max-regression",
                str(args.max_regression),
                "--output",
                str(report_path),
            ],
            cwd=repo_root,
            capture_output=True,
            text=True,
        )
        (output_dir / "comparison.log").write_text(
            comparison.stdout + comparison.stderr,
            encoding="utf-8",
        )
        manifest["finished_at"] = datetime.now(UTC).isoformat()
        manifest["comparison_exit_code"] = comparison.returncode
        _write_json(output_dir / "manifest.json", manifest)
        return comparison.returncode
    finally:
        if args.keep_worktrees:
            manifest["retained_worktree_root"] = str(temporary_root)
            _write_json(output_dir / "manifest.json", manifest)
        else:
            for worktree in reversed(worktrees):
                if worktree.exists():
                    _remove_disposable_worktree(
                        repo_root,
                        worktree,
                        temporary_root,
                    )
            temporary_root.rmdir()


def main(argv: list[str] | None = None) -> int:
    return run_comparison(parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
