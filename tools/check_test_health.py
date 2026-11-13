"""Run pytest with reproducible ordering, whole-process timing and JUnit checks."""

import argparse
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import time
from pathlib import Path
from xml.etree import ElementTree as ET

PROJECT_ROOT = Path(__file__).resolve().parents[1]
REFERENCE_FILE = PROJECT_ROOT / "tests" / "first-baseline-ref.txt"
MYSQL_PATHS = (
    "tests/scheduling/test_engine_shared_database.py",
    "tests/scheduling/test_engine.py::test_runtime_state_initialization_is_atomic_on_shared_database",
    "tests/domains/documents/test_upload_cleanup_mysql.py",
    "tests/domains/documents/test_rate_limits_mysql.py",
    "tests/maintenance/database/test_mysql.py",
    "tests/database/test_system_states_mysql.py",
    "tests/domains/operations/test_lockdown_mysql.py",
)
PROFILES = {
    **{
        layer: ["tests/", "-m", f"{layer} and not stress"]
        for layer in ("unit", "component", "integration")
    },
    "all": ["tests/", "-m", "not stress"],
    "redis": ["tests/providers/test_redis_lua_integration.py"],
    "mysql-8.4": [*MYSQL_PATHS, "-k", "mysql"],
    "mysql-9.7": [*MYSQL_PATHS, "-k", "mysql"],
    "postgresql": [
        "tests/scheduling/test_engine_shared_database.py",
        "tests/scheduling/test_engine.py::test_runtime_state_initialization_is_atomic_on_shared_database",
        "-k",
        "postgresql",
    ],
    "s3": ["tests/providers/test_s3_compatibility_integration.py"],
}
BACKEND_ENVIRONMENT = {
    "redis": ("CFMS_TEST_REDIS_URL",),
    "mysql-8.4": ("CFMS_TEST_MYSQL_URL",),
    "mysql-9.7": ("CFMS_TEST_MYSQL_URL",),
    "postgresql": ("CFMS_TEST_POSTGRESQL_URL",),
    "s3": ("CFMS_TEST_S3_WRITE", "CFMS_TEST_S3_BUCKET", "CFMS_TEST_S3_ENDPOINT_URL"),
}
ISOLATED_NODES = (
    *[
        f"tests/domains/access/test_access.py::TestAccessManagement::{name}"
        for name in (
            "test_grant_and_revoke_access",
            "test_grant_multiple_access_types",
            "test_grant_access_to_group",
            "test_grant_access_to_directory",
        )
    ],
    "tests/domains/documents/test_search.py::TestSearch::test_search_directories",
    "tests/domains/documents/test_search.py::TestSearch::test_search_both",
    "tests/domains/security/test_totp.py::TestTotpCredentials::test_confirm_totp_setup_with_valid_token",
    "tests/domains/security/test_totp.py::TestMfaLogin::test_totp_mfa_login_with_valid_token",
)


def environment_fingerprint() -> str:
    environment = {
        "python": platform.python_version(),
        "platform": sys.platform,
        "machine": platform.machine(),
        "runner_image": os.environ.get("ImageOS", "local"),
        "runner_version": os.environ.get("ImageVersion", "local"),
        "lock": hashlib.sha256((PROJECT_ROOT / "uv.lock").read_bytes()).hexdigest(),
    }
    return hashlib.sha256(json.dumps(environment, sort_keys=True).encode()).hexdigest()


def validate_junit(path: Path, *, require_no_skips: bool) -> dict[str, int]:
    root = ET.parse(path).getroot()
    cases = root.findall(".//testcase")
    if not cases:
        raise ValueError("JUnit report contains no executed tests")
    counts = {
        tag: sum(case.find(tag) is not None for case in cases)
        for tag in ("skipped", "failure", "error")
    }
    if counts["failure"] or counts["error"]:
        raise ValueError(f"JUnit report contains failures or errors: {counts}")
    if require_no_skips and counts["skipped"]:
        raise ValueError("Backend JUnit report contains skipped tests")
    executed = len(cases) - counts["skipped"]
    if executed == 0:
        raise ValueError("JUnit report contains only skipped tests")
    return {"executed": executed, **counts}


def time_budget(
    baseline: dict, profile: str, fingerprint: str, reference: str
) -> float:
    if (
        baseline["profile"] != profile
        or baseline["environment"] != fingerprint
        or baseline["reference"] != reference
    ):
        raise ValueError("Baseline profile, environment or reference does not match")
    samples = baseline["samples_seconds"]
    if len(samples) != 3 or any(
        not isinstance(sample, (int, float)) or not math.isfinite(sample) or sample <= 0
        for sample in samples
    ):
        raise ValueError("Baseline requires three positive finite samples")
    median = statistics.median(samples)
    allowance = {"unit": 5.0, "component": 15.0}.get(profile, 30.0)
    return max(1.5 * median, median + allowance)


def run_pytest(
    root: Path, arguments: list[str], report: Path, seed: int | None
) -> tuple[int, float]:
    report.parent.mkdir(parents=True, exist_ok=True)
    report.unlink(missing_ok=True)
    environment = os.environ.copy()
    environment["PYTHONPATH"] = os.pathsep.join((str(root / "src"), str(root)))
    command = [
        sys.executable,
        "-m",
        "pytest",
        *arguments,
        "-q",
        f"--junitxml={report}",
        "--durations=25",
    ]
    if seed is not None:
        environment["PYTHONHASHSEED"] = str(seed)
        command.extend(("-p", "randomly", f"--randomly-seed={seed}"))
    else:
        command.extend(("-p", "no:randomly"))
    started = time.perf_counter()
    result = subprocess.run(command, cwd=root, env=environment, check=False)
    return result.returncode, time.perf_counter() - started


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("run", "calibrate", "isolate", "fingerprint"))
    parser.add_argument("--profile", choices=PROFILES, default="all")
    parser.add_argument("--root", type=Path, default=PROJECT_ROOT)
    parser.add_argument(
        "--report", type=Path, default=PROJECT_ROOT / "test-results" / "health.xml"
    )
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--seed", type=int)
    options = parser.parse_args(argv)
    fingerprint = environment_fingerprint()
    if options.mode == "fingerprint":
        print(fingerprint)
        return 0
    if options.seed is not None and not 0 <= options.seed <= 0xFFFFFFFF:
        parser.error("seed must be a 32-bit unsigned integer")
    if options.mode == "calibrate" and (
        options.baseline is None or options.seed is not None
    ):
        parser.error("calibrate requires --baseline and ordinary test order")
    root, report = options.root.resolve(), options.report.resolve()
    reference = REFERENCE_FILE.read_text(encoding="utf-8").strip()
    try:
        for name in BACKEND_ENVIRONMENT.get(options.profile, ()):
            if not os.environ.get(name):
                raise ValueError(f"{name} is required for {options.profile}")
        if options.profile == "s3" and os.environ["CFMS_TEST_S3_WRITE"] != "1":
            raise ValueError("CFMS_TEST_S3_WRITE must be 1")
        budget = None
        if options.mode == "run" and options.baseline is not None:
            budget = time_budget(
                json.loads(options.baseline.read_text(encoding="utf-8")),
                options.profile,
                fingerprint,
                reference,
            )
        if options.mode == "calibrate":
            actual_reference = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
            ).stdout.strip()
            if actual_reference != reference:
                raise ValueError(
                    "Calibration checkout must match the pinned reference commit"
                )
        arguments = [PROFILES[options.profile]] * (
            3 if options.mode == "calibrate" else 1
        )
        if options.mode == "isolate":
            arguments = [[node] for node in ISOLATED_NODES]
        samples = []
        for index, selection in enumerate(arguments):
            case_report = (
                report
                if len(arguments) == 1
                else report.with_stem(f"{report.stem}-{index + 1}")
            )
            code, elapsed = run_pytest(root, selection, case_report, options.seed)
            summary = {
                "profile": options.profile,
                "seed": options.seed,
                "elapsed_seconds": elapsed,
                "returncode": code,
                "environment": fingerprint,
            }
            if code == 0:
                summary.update(
                    validate_junit(
                        case_report,
                        require_no_skips=options.profile in BACKEND_ENVIRONMENT,
                    )
                )
            case_report.with_suffix(".json").write_text(
                json.dumps(summary, indent=2) + "\n", encoding="utf-8"
            )
            print(json.dumps(summary), flush=True)
            if code != 0:
                return code
            samples.append(elapsed)
            if budget is not None and elapsed > budget:
                raise ValueError(
                    f"{options.profile} exceeded time budget: {elapsed:.2f}s > {budget:.2f}s"
                )
        if options.mode == "calibrate":
            baseline = {
                "profile": options.profile,
                "environment": fingerprint,
                "reference": reference,
                "samples_seconds": samples,
            }
            options.baseline.parent.mkdir(parents=True, exist_ok=True)
            options.baseline.write_text(
                json.dumps(baseline, indent=2) + "\n", encoding="utf-8"
            )
    except (
        OSError,
        ValueError,
        KeyError,
        TypeError,
        ET.ParseError,
        subprocess.CalledProcessError,
    ) as exc:
        print(f"Test health check failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
