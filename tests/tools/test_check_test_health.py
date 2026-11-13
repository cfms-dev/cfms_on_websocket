import json
from types import SimpleNamespace

import pytest

from tools import check_test_health as health

pytestmark = pytest.mark.component


@pytest.mark.parametrize(
    ("contents", "no_skips", "valid"),
    [
        ("<testcase/>", True, True),
        ("<testcase/><testcase><skipped/></testcase>", False, True),
        ("", False, False),
        ("<testcase><skipped/></testcase>", False, False),
        ("<testcase/><testcase><skipped/></testcase>", True, False),
        ("<testcase><failure/></testcase>", False, False),
        ("<testcase><error/></testcase>", False, False),
    ],
)
def test_junit_requires_executed_successes_and_checks_backend_skips(
    tmp_path, contents, no_skips, valid
):
    report = tmp_path / "result.xml"
    report.write_text(
        f"<testsuites><testsuite>{contents}</testsuite></testsuites>", encoding="utf-8"
    )
    if valid:
        counts = health.validate_junit(report, require_no_skips=no_skips)
        assert counts["executed"] == 1
        assert counts["failure"] == counts["error"] == 0
    else:
        with pytest.raises(ValueError, match="JUnit"):
            health.validate_junit(report, require_no_skips=no_skips)


@pytest.mark.parametrize(
    ("profile", "samples", "expected"),
    [
        ("unit", [5, 6, 7], 11),
        ("component", [40, 50, 60], 75),
        ("integration", [10, 20, 30], 50),
        ("redis", [2, 3, 4], 33),
    ],
)
def test_time_budget_uses_median_and_layer_allowance(profile, samples, expected):
    baseline = {
        "profile": profile,
        "environment": "environment",
        "reference": "reference",
        "samples_seconds": samples,
    }
    assert health.time_budget(baseline, profile, "environment", "reference") == expected


@pytest.mark.parametrize(
    ("key", "value"),
    [
        ("profile", "integration"),
        ("environment", "other"),
        ("reference", "other"),
        ("samples_seconds", [1, 2]),
        ("samples_seconds", [1, 2, float("nan")]),
        ("samples_seconds", [0, 1, 2]),
    ],
)
def test_time_budget_rejects_incomparable_or_invalid_baselines(key, value):
    baseline = {
        "profile": "unit",
        "environment": "environment",
        "reference": "reference",
        "samples_seconds": [1, 2, 3],
    }
    baseline[key] = value
    with pytest.raises(ValueError, match="Baseline"):
        health.time_budget(baseline, "unit", "environment", "reference")


@pytest.mark.parametrize("code", [0, 2, 5])
def test_run_preserves_pytest_exit_status_and_records_elapsed_time(
    tmp_path, monkeypatch, code
):
    report = tmp_path / "result.xml"
    report.write_text("stale report", encoding="utf-8")

    def run(command, *, cwd, env, check):
        assert not report.exists()
        assert cwd == tmp_path
        assert env["PYTHONHASHSEED"] == "17"
        assert env["PYTHONPATH"].split(health.os.pathsep) == [
            str(tmp_path / "src"),
            str(tmp_path),
        ]
        assert "--randomly-seed=17" in command
        assert check is False
        report.write_text(
            "<testsuites><testsuite><testcase/></testsuite></testsuites>",
            encoding="utf-8",
        )
        return SimpleNamespace(returncode=code)

    ticks = iter([10.0, 12.5])
    monkeypatch.setattr(health.subprocess, "run", run)
    monkeypatch.setattr(health.time, "perf_counter", lambda: next(ticks))
    assert health.run_pytest(tmp_path, ["tests/"], report, 17) == (code, 2.5)


@pytest.mark.parametrize(("elapsed", "exit_code"), [(10, 0), (40, 1)])
def test_main_blocks_excessive_time_without_updating_the_baseline(
    tmp_path, monkeypatch, elapsed, exit_code
):
    baseline = tmp_path / "baseline.json"
    original = json.dumps(
        {
            "profile": "unit",
            "environment": health.environment_fingerprint(),
            "reference": health.REFERENCE_FILE.read_text().strip(),
            "samples_seconds": [10, 11, 12],
        }
    )
    baseline.write_text(original, encoding="utf-8")
    report = tmp_path / "result.xml"

    def run(_root, _arguments, path, _seed):
        path.write_text(
            "<testsuites><testsuite><testcase/></testsuite></testsuites>",
            encoding="utf-8",
        )
        return 0, elapsed

    monkeypatch.setattr(health, "run_pytest", run)
    assert (
        health.main(
            [
                "run",
                "--profile",
                "unit",
                "--report",
                str(report),
                "--baseline",
                str(baseline),
            ]
        )
        == exit_code
    )
    assert baseline.read_text(encoding="utf-8") == original
    assert (
        json.loads(report.with_suffix(".json").read_text())["elapsed_seconds"]
        == elapsed
    )


def test_calibration_runs_three_clean_sessions_at_the_pinned_reference(
    tmp_path, monkeypatch
):
    baseline = tmp_path / "baseline.json"
    elapsed = iter([3, 1, 2])
    reports = []

    def run(_root, _arguments, report, seed):
        assert seed is None
        reports.append(report)
        report.write_text(
            "<testsuites><testsuite><testcase/></testsuite></testsuites>",
            encoding="utf-8",
        )
        return 0, next(elapsed)

    monkeypatch.setattr(health, "run_pytest", run)
    monkeypatch.setattr(
        health.subprocess,
        "run",
        lambda *_args, **_kwargs: SimpleNamespace(
            stdout=health.REFERENCE_FILE.read_text()
        ),
    )
    assert (
        health.main(
            [
                "calibrate",
                "--profile",
                "unit",
                "--report",
                str(tmp_path / "baseline.xml"),
                "--baseline",
                str(baseline),
            ]
        )
        == 0
    )
    assert len(set(reports)) == 3
    assert json.loads(baseline.read_text())["samples_seconds"] == [3, 1, 2]


def test_configured_backend_requires_environment_before_running(tmp_path, monkeypatch):
    monkeypatch.delenv("CFMS_TEST_REDIS_URL", raising=False)
    assert (
        health.main(
            ["run", "--profile", "redis", "--report", str(tmp_path / "result.xml")]
        )
        == 1
    )
    assert not (tmp_path / "result.xml").exists()
